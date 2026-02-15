from mitmproxy import http
import re

# SSN with dashes
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Stricter JWT:
# - header typically starts with "eyJ"
# - 3 segments
# - each segment has a minimum length to reduce false positives
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

def block(flow: http.HTTPFlow, reason: str):
    flow.response = http.Response.make(
        403,
        f"Sensitive data detected ({reason}). Request blocked.".encode("utf-8"),
        {"Content-Type": "text/plain"}
    )

def request(flow: http.HTTPFlow):
    if flow.request.method != "POST":
        return

    # Only inspect text-like bodies
    ctype = (flow.request.headers.get("content-type") or "").lower()
    if not any(t in ctype for t in ["application/x-www-form-urlencoded", "application/json", "text/", "multipart/form-data"]):
        return

    try:
        body = flow.request.get_text(strict=False) or ""
    except Exception:
        return

    # 1) SSN FIRST
    m_ssn = SSN_RE.search(body)
    if m_ssn:
        print(f"🚨 SSN DETECTED: {m_ssn.group(0)}  -> blocking {flow.request.host}{flow.request.path}")
        return block(flow, "SSN")

    # 2) JWT SECOND (stricter)
    m_jwt = JWT_RE.search(body)
    if m_jwt:
        print(f"🚨 JWT DETECTED: {m_jwt.group(0)[:20]}…  -> blocking {flow.request.host}{flow.request.path}")
        return block(flow, "JWT")
