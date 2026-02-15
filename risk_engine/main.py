from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_plus
from .rookie_score import compute_rookie_score
from .dlp_scanner import DLPScanner

app = FastAPI()
dlp_scanner = DLPScanner()

class EvaluatePayload(BaseModel):
    domain: str
    url: str
    method: str
    headers: Dict[str, Any] = {}
    body: Optional[str] = None
    keywords_found: List[str] = []
    files: List[Dict[str, Any]] = []
    tnc_text: Optional[str] = None

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
            return {
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
    else:
        dlp = {"total_score": 0, "findings": []}

    score = rs["rookie_score"]

    if score >= 60:
        decision = "BLOCK"
    elif score >= 40:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
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
