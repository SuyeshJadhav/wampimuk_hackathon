# mitmproxy_addon/utils.py

import re
from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    """
    Extracts domain from a given URL.
    Example: https://sub.example.com/path -> example.com
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])  # example.com
    return hostname

def normalize_url(url: str) -> str:
    """
    Normalize URL by stripping scheme and trailing slashes
    """
    parsed = urlparse(url)
    return f"{parsed.netloc}{parsed.path}".rstrip("/")

def parse_multipart_form(body: bytes, content_type: str) -> dict:
    """
    Placeholder for multipart/form-data parsing
    Returns:
        {
            "fields": {...},
            "files": [
                {"filename": "...", "content_type": "...", "size": ...},
                ...
            ]
        }
    """
    # TODO: implement actual multipart parser or use existing library
    return {"fields": {}, "files": []}

def detect_sensitive_keywords(text: str, keywords: list) -> list:
    """
    Simple detection of sensitive keywords in text
    """
    found = []
    for kw in keywords:
        if re.search(kw, text, re.IGNORECASE):
            found.append(kw)
    return found


# ─────────────────────────────────────────────────────────────────────────────
#  T&C / Privacy Page Detection (Content-Based)
# ─────────────────────────────────────────────────────────────────────────────

# URL path segments that HINT at a T&C / privacy page (secondary signal)
TNC_URL_HINTS = {
    "terms", "tos", "privacy", "legal", "policy", "eula",
    "cookie", "cookies", "data-policy", "data_policy",
    "terms-of-service", "terms-of-use", "terms_of_service",
    "privacy-policy", "privacy_policy", "user-agreement",
    "acceptable-use", "disclaimer", "gdpr", "ccpa",
}

# Phrases that strongly indicate the page IS a T&C / privacy document.
# We look for these in the visible text of the page.
# A page must contain at least TNC_CONTENT_THRESHOLD matches to qualify.
TNC_CONTENT_PHRASES = [
    r"terms\s+(of\s+)?(service|use|conditions)",
    r"privacy\s+(policy|notice|statement)",
    r"cookie\s+(policy|notice|consent)",
    r"user\s+agreement",
    r"end\s+user\s+license\s+agreement",
    r"data\s+(protection|processing)\s+(policy|agreement|notice)",
    r"acceptable\s+use\s+policy",
    r"by\s+(using|accessing|continuing).*(you\s+agree|you\s+accept|you\s+consent)",
    r"we\s+(collect|gather|process|store)\s+(your\s+)?(personal\s+)?(data|information)",
    r"third.party.*(share|disclose|transfer|sell)",
    r"(opt.out|withdraw\s+consent|right\s+to\s+erasure|right\s+to\s+be\s+forgotten)",
    r"(gdpr|ccpa|coppa|hipaa|ferpa)",
]

# Compiled once for performance
_TNC_CONTENT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in TNC_CONTENT_PHRASES]

# Minimum number of distinct content phrase matches to consider a page T&C-like
TNC_CONTENT_THRESHOLD = 2


def strip_html_to_text(html: str) -> str:
    """
    Strip HTML tags and decode entities to get readable plain text.
    Lightweight — no external library needed.
    """
    # Remove script and style blocks entirely
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)

    # Replace block-level tags with newlines for readability
    text = re.sub(r"<(br|p|div|h[1-6]|li|tr)[^>]*>", "\n", text, flags=re.IGNORECASE)

    # Strip all remaining tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Decode common HTML entities
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")

    # Collapse whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)

    return text.strip()


def is_tnc_page(url: str, body_text: str) -> bool:
    """
    Detect whether a page is a Terms & Conditions / Privacy Policy page.

    Uses TWO signals:
      1. URL path hints  (weak signal — lowers the content threshold)
      2. Content phrases  (strong signal — works regardless of URL)

    Returns True if the page is likely a T&C / privacy document.
    """
    # Check URL hints
    path = urlparse(url).path.lower().strip("/")
    path_segments = set(re.split(r"[/._-]", path))
    url_match = bool(path_segments & TNC_URL_HINTS)

    # Count content phrase matches
    lower_text = body_text.lower()
    hit_count = sum(1 for p in _TNC_CONTENT_PATTERNS if p.search(lower_text))

    # If URL hints match, lower the bar (1 content match is enough)
    # Otherwise, require the full threshold
    threshold = 1 if url_match else TNC_CONTENT_THRESHOLD

    return hit_count >= threshold
