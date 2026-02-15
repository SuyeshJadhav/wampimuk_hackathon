from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_plus

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .dlp_scanner import DLPScanner
from .rookie_score import compute_rookie_score

app = FastAPI()
dlp_scanner = DLPScanner()
EVENTS: deque = deque(maxlen=2000)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = PROJECT_ROOT / "ui_dashboard"
app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")

BACKGROUND_DOMAIN_HINTS = (
    "spotify",
    "discord",
    "microsoft",
    "office",
    "telemetry",
    "gstatic",
    "googleapis",
    "doubleclick",
    "googletagmanager",
    "google-analytics",
    "amplitude",
    "sentry",
)


class EvaluatePayload(BaseModel):
    domain: str
    url: str
    method: str
    headers: Dict[str, Any] = {}
    body: Optional[str] = None
    keywords_found: List[str] = []
    files: List[Dict[str, Any]] = []
    tnc_text: Optional[str] = None


class EventIngestPayload(BaseModel):
    timestamp: Optional[str] = None
    domain: str
    url: str
    method: str
    decision: str
    score: int
    rookie_score: int = 0
    trust_tier: str = "UNKNOWN"
    dlp_raw_score: int = 0
    dlp_types: List[str] = []
    dlp_findings_count: int = 0
    reasons: List[str] = []
    user_agent: str = ""
    is_background: Optional[bool] = None


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_background_traffic(headers: Dict[str, Any], domain: str, url: str) -> bool:
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    ua = h.get("user-agent", "").lower()
    accept = h.get("accept", "").lower()
    lowered = f"{domain} {url} {ua}".lower()
    if any(token in lowered for token in BACKGROUND_DOMAIN_HINTS):
        return True

    # Explicit user-driven requests (CLI/manual tests) should always appear.
    if "curl/" in ua or "postmanruntime/" in ua:
        return False

    # Browser navigation signals: treat these as foreground traffic.
    sec_fetch_dest = h.get("sec-fetch-dest", "").lower()
    sec_fetch_mode = h.get("sec-fetch-mode", "").lower()
    sec_fetch_site = h.get("sec-fetch-site", "").lower()
    is_nav = (
        sec_fetch_dest == "document"
        or sec_fetch_mode == "navigate"
        or ("text/html" in accept and sec_fetch_site in {"same-origin", "same-site", "none"})
    )
    if is_nav:
        return False

    # Everything else (API beacons, telemetry, asset chatter) defaults to background.
    return True


def _record_event(
    payload: EvaluatePayload,
    decision: str,
    score: int,
    rookie_details: Dict[str, Any],
    dlp_details: Dict[str, Any],
) -> None:
    findings = dlp_details.get("findings", []) or []
    user_agent = str((payload.headers or {}).get("user-agent", ""))
    EVENTS.append(
        {
            "timestamp": _ts(),
            "domain": payload.domain,
            "url": payload.url,
            "method": (payload.method or "").upper(),
            "decision": decision,
            "score": int(score),
            "rookie_score": int(rookie_details.get("rookie_score", 0)),
            "trust_tier": rookie_details.get("trust_tier", "UNKNOWN"),
            "dlp_raw_score": int(dlp_details.get("raw_score", 0)),
            "dlp_types": [f.get("type", "UNKNOWN") for f in findings],
            "dlp_findings_count": len(findings),
            "reasons": rookie_details.get("reasons", []),
            "user_agent": user_agent,
            "is_background": _is_background_traffic(payload.headers, payload.domain, payload.url),
        }
    )


@app.post("/evaluate")
def evaluate(p: EvaluatePayload):
    rs = compute_rookie_score(p.domain, p.method, p.headers, p.files)
    method = (p.method or "").upper()
    body = p.body or ""
    content_type = (p.headers or {}).get("content-type", "").lower()
    if "application/x-www-form-urlencoded" in content_type and body:
        body = unquote_plus(body)

    # Run DLP only for POST requests. Any sensitive match is an immediate block.
    if method == "POST":
        dlp = dlp_scanner.scan(body)
        findings = dlp.get("findings", [])
        print(f"[EVAL] method={method} body_bytes={len(body.encode('utf-8'))} dlp_findings={len(findings)}")
        if findings:
            response = {
                "decision": "BLOCK",
                "score": 100,
                "details": {
                    "rookie": rs,
                    "dlp": {
                        "raw_score": int(dlp.get("total_score", 0)),
                        "findings": findings,
                        "reason": "Sensitive data detected in POST body",
                    },
                },
            }
            _record_event(p, response["decision"], response["score"], rs, response["details"]["dlp"])
            return response
    else:
        dlp = {"total_score": 0, "findings": []}

    score = rs["rookie_score"]

    if score >= 60:
        decision = "BLOCK"
    elif score >= 40:
        decision = "WARN"
    else:
        decision = "ALLOW"

    response = {
        "decision": decision,
        "score": score,
        "details": {
            "rookie": rs,
            "dlp": {
                "raw_score": int(dlp.get("total_score", 0)),
                "findings": dlp.get("findings", []),
            },
        },
    }
    _record_event(p, decision, score, rs, response["details"]["dlp"])
    return response


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "timestamp": _ts(), "events_tracked": len(EVENTS)}


@app.get("/api/events")
def get_events(
    limit: int = Query(100, ge=1, le=500),
    decision: Optional[str] = Query(None),
    include_background: bool = Query(False),
    q: str = Query(""),
) -> List[Dict[str, Any]]:
    rows = list(reversed(EVENTS))
    if decision:
        rows = [r for r in rows if r["decision"] == decision.upper()]
    if not include_background:
        rows = [r for r in rows if not r.get("is_background", False)]
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in (r.get("domain", "").lower() + " " + r.get("url", "").lower())]
    return rows[:limit]


@app.get("/api/summary")
def get_summary(include_background: bool = Query(False), q: str = Query("")) -> Dict[str, Any]:
    rows = list(EVENTS)
    if not include_background:
        rows = [r for r in rows if not r.get("is_background", False)]
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in (r.get("domain", "").lower() + " " + r.get("url", "").lower())]

    decision_counts = Counter(r["decision"] for r in rows)
    dlp_type_counts = Counter()
    domain_counts = Counter()
    for r in rows:
        domain_counts[r["domain"]] += 1
        for t in r.get("dlp_types", []):
            dlp_type_counts[t] += 1

    return {
        "total": len(rows),
        "decisions": {
            "ALLOW": decision_counts.get("ALLOW", 0),
            "WARN": decision_counts.get("WARN", 0),
            "BLOCK": decision_counts.get("BLOCK", 0),
        },
        "top_domains": domain_counts.most_common(6),
        "dlp_types": dlp_type_counts.most_common(8),
    }


@app.post("/api/events/ingest")
def ingest_event(p: EventIngestPayload) -> Dict[str, Any]:
    EVENTS.append(
        {
            "timestamp": p.timestamp or _ts(),
            "domain": p.domain,
            "url": p.url,
            "method": (p.method or "").upper(),
            "decision": (p.decision or "ALLOW").upper(),
            "score": int(p.score),
            "rookie_score": int(p.rookie_score),
            "trust_tier": p.trust_tier,
            "dlp_raw_score": int(p.dlp_raw_score),
            "dlp_types": p.dlp_types,
            "dlp_findings_count": int(p.dlp_findings_count),
            "reasons": p.reasons,
            "user_agent": p.user_agent,
            "is_background": bool(p.is_background) if p.is_background is not None else True,
        }
    )
    return {"ok": True, "events_tracked": len(EVENTS)}


@app.post("/api/events/clear")
def clear_events() -> Dict[str, Any]:
    EVENTS.clear()
    return {"ok": True, "events_tracked": 0}
