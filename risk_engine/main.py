from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from .rookie_score import compute_rookie_score

app = FastAPI()

class EvaluatePayload(BaseModel):
    domain: str
    url: str
    method: str
    headers: Dict[str, Any] = {}
    body: Optional[str] = None
    keywords_found: List[str] = []
    files: List[Dict[str, Any]] = []

@app.post("/evaluate")
def evaluate(p: EvaluatePayload):
    rs = compute_rookie_score(p.domain, p.method, p.headers, p.files)

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
        "details": rs
    }
