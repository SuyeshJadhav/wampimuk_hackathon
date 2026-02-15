# risk_engine/rookie_score.py
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
import concurrent.futures

import tldextract
import whois  # python-whois

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
WHOIS_CACHE_PATH = os.path.join(DATA_DIR, "whois_cache.json")

# Hackathon defaults
ROOKIE_AGE_THRESHOLD_DAYS = 30          # "new domain" threshold
WHOIS_TIMEOUT_SECONDS = 1.5             # keep proxy responsive
WHOIS_CACHE_TTL_SECONDS = 7 * 24 * 3600 # 7 days

ALLOWLIST = {"ncsu.edu", "github.com", "linkedin.com", "httpbin.org"}
DENYLIST = {"pastebin.com", "transfer.sh", "0x0.st"}
RISKY_TLDS = {"zip", "xyz", "top", "click", "mov", "ru", "tk"}


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, obj):
    _ensure_data_dir()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def registrable_domain(host: str) -> str:
    """
    Returns registrable domain like 'example.com' from 'sub.a.example.com'.
    """
    host = (host or "").strip().lower()
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def _to_dt_utc(val) -> Optional[datetime]:
    """
    Normalize python-whois date field into a UTC datetime.
    whois can return datetime OR list of datetimes OR str.
    """
    if val is None:
        return None

    # sometimes it's a list
    if isinstance(val, list):
        # pick earliest plausible creation date
        dts = [v for v in val if isinstance(v, datetime)]
        if dts:
            return min(dts).astimezone(timezone.utc) if dts[0].tzinfo else min(dts).replace(tzinfo=timezone.utc)
        # if list of strings etc, give up
        return None

    if isinstance(val, datetime):
        return val.astimezone(timezone.utc) if val.tzinfo else val.replace(tzinfo=timezone.utc)

    # occasionally strings appear; parsing reliably across TLDs is messy
    # keep MVP safe: don't attempt fragile parsing
    return None


def _whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Raw whois lookup (can be slow/hang without timeout control).
    """
    w = whois.whois(domain)
    return w if isinstance(w, dict) else w.__dict__


def get_domain_age_days(domain: str) -> Tuple[Optional[int], List[str]]:
    """
    Best-effort domain age in days using WHOIS.
    Returns (age_days or None, reasons[])
    Uses cache + timeout.
    """
    domain = registrable_domain(domain)
    reasons: List[str] = []

    _ensure_data_dir()
    cache = _load_json(WHOIS_CACHE_PATH, default={"domains": {}})

    entry = cache["domains"].get(domain)
    now = int(time.time())

    # Cache hit (fresh)
    if entry and (now - entry.get("cached_at", 0) <= WHOIS_CACHE_TTL_SECONDS):
        age_days = entry.get("age_days")
        if age_days is None:
            reasons.append("WHOIS cached but creation date unknown")
        else:
            reasons.append("WHOIS cached")
        return age_days, reasons

    # Cache miss or stale -> do WHOIS with timeout
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_whois_lookup, domain)
            raw = fut.result(timeout=WHOIS_TIMEOUT_SECONDS)

        created = _to_dt_utc(raw.get("creation_date"))
        if created is None:
            # Some TLDs store in "created" or variants; try a couple common keys
            for k in ("created", "Creation Date", "registered"):
                if k in raw:
                    created = _to_dt_utc(raw.get(k))
                    if created:
                        break

        if created is None:
            reasons.append("WHOIS lookup succeeded but creation date unavailable (privacy/TLD differences)")
            cache["domains"][domain] = {"cached_at": now, "age_days": None}
            _save_json(WHOIS_CACHE_PATH, cache)
            return None, reasons

        age_days = (datetime.now(timezone.utc) - created).days
        reasons.append("WHOIS lookup ok")
        cache["domains"][domain] = {"cached_at": now, "age_days": age_days, "creation_date_utc": created.isoformat()}
        _save_json(WHOIS_CACHE_PATH, cache)
        return age_days, reasons

    except concurrent.futures.TimeoutError:
        reasons.append("WHOIS lookup timed out")
    except Exception as e:
        reasons.append(f"WHOIS lookup failed: {type(e).__name__}")

    # Fallback: cache failure for a short time so you don't retry constantly
    cache["domains"][domain] = {"cached_at": now, "age_days": None, "error": reasons[-1]}
    _save_json(WHOIS_CACHE_PATH, cache)
    return None, reasons


def compute_rookie_score(domain: str, method: str, headers: Dict[str, Any], files: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Returns a destination-risk score 0-100 using WHOIS age + heuristics.
    Higher = lower trust.
    """
    host = registrable_domain(domain)
    tld = host.split(".")[-1] if "." in host else ""

    score = 10
    reasons: List[str] = []
    signals: Dict[str, Any] = {"domain": host, "tld": tld}

    # 1) Allow/deny lists
    if host in ALLOWLIST:
        score -= 25
        reasons.append("Allowlisted destination")
        signals["allowlisted"] = True
    if host in DENYLIST:
        score += 60
        reasons.append("Denylisted destination")
        signals["denylisted"] = True

    # 2) WHOIS domain age
    age_days, age_reasons = get_domain_age_days(host)
    signals["age_days"] = age_days
    signals["whois_notes"] = age_reasons
    notes = " ".join(age_reasons).lower()
    signals["whois_failure"] = notes

    if "notfound" in notes or "domainnotfound" in notes:
        score += 20
        reasons.append("WHOIS indicates domain may not exist")

    if age_days is None:
    # unknown age -> HIGH risk by default (WHOIS failed / domain might be brand new / non-existent)
        score += 50
        reasons.append("Domain age unknown (WHOIS unavailable)")

        # If it's a data-leaving request, make it even riskier
        if (method or "").upper() in {"POST", "PUT", "PATCH"}:
            score += 25
            reasons.append("Unknown-age domain + state-changing method")
    else:
        if age_days < ROOKIE_AGE_THRESHOLD_DAYS:
            score += 35
            reasons.append(f"New domain (age {age_days} days)")
        elif age_days < 180:
            score += 15
            reasons.append(f"Relatively new domain (age {age_days} days)")
        else:
            score -= 5
            reasons.append(f"Established domain (age {age_days} days)")

    # 3) Risky TLD
    if tld in RISKY_TLDS:
        score += 20
        reasons.append(f"Risky TLD .{tld}")

    # 4) Context (how data-leaving-ish it is)
    if (method or "").upper() in {"POST", "PUT", "PATCH"}:
        score += 10
        reasons.append("State-changing method")

    # ctype = (headers or {}).get("content-type", "").lower()
    # if "multipart/form-data" in ctype or (files and len(files) > 0):
    #     score += 20
    #     reasons.append("Upload-like request (multipart/files)")

    # clamp
    score = max(0, min(100, score))

    trust = "HIGH" if score < 40 else ("MED" if score < 70 else "LOW")
    return {"rookie_score": score, "trust_tier": trust, "reasons": reasons, "signals": signals}
