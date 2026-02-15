"""
Agency Guard Risk Engine - Main Controller

Responsibilities:

- Receive ALL requests from mitmproxy
- Decide which requests need analysis
- Call helper modules:
    - DLP Scanner
    - Rookie Score
    - Future modules
- Aggregate scores
- Return decision

This file is the central orchestrator.
"""

import json
import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List

from .dlp_scanner import DLPScanner
from .rookie_score import compute_rookie_score
from .tnc_analysis import TnCAnalyzer

# Optional module imports
try:
    from .rookie_score import RookieScore
except ImportError:
    RookieScore = None


# -----------------------------------
# FastAPI Init
# -----------------------------------

app = FastAPI(title="Agency Guard Risk Engine")

# Enable CORS so the Electron renderer (file://) can call us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTERCEPT_LOG_PATH = PROJECT_ROOT / "mitmproxy_addon" / "intercept_log.json"



# -----------------------------------
# Initialize modules ONCE
# -----------------------------------

dlp_scanner = DLPScanner()
tnc_analyzer = TnCAnalyzer()

rookie_score = RookieScore() if RookieScore else None



# -----------------------------------
# Request Model (matches mitm payload exactly)
# -----------------------------------

class EvaluateRequest(BaseModel):

    domain: str
    url: str
    method: str
    headers: Dict[str, Any]
    body: str = ""
    keywords_found: List[str] = []
    files: List[Dict] = []
    tnc_text: str = ""



# -----------------------------------
# Response Model
# -----------------------------------

class ModuleResult(BaseModel):

    module: str
    score: int
    details: Any = None



class EvaluateResponse(BaseModel):

    decision: str
    score: int
    details: List[ModuleResult]



# -----------------------------------
# Decision thresholds
# -----------------------------------

BLOCK_THRESHOLD = 2
WARN_THRESHOLD = 0



# -----------------------------------
# Should analyze logic
# -----------------------------------

def should_analyze(request: EvaluateRequest) -> bool:
    """
    Decide whether to run risk analysis

    We analyze only when:

    - POST request
    - AND contains body
    - AND is likely form submission
    """

    if request.method != "POST":
        return False

    if not request.body:
        return False

    content_type = request.headers.get("content-type", "").lower()

    if (

        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
        or "application/json" in content_type

    ):
        return True

    return False



# -----------------------------------
# Aggregate scores
# -----------------------------------

def aggregate(module_results: List[ModuleResult]):

    total_score = sum(m.score for m in module_results)

    if total_score >= BLOCK_THRESHOLD:

        decision = "BLOCK"

    elif total_score >= WARN_THRESHOLD:

        decision = "WARN"

    else:

        decision = "ALLOW"

    print(f"Total Score: {total_score} | Decision: {decision}")
    return decision, total_score



# -----------------------------------
# MAIN ENDPOINT
# -----------------------------------

@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(request: EvaluateRequest):

    module_results: List[ModuleResult] = []


    # -----------------------------------
    # Decide if analysis needed
    # -----------------------------------

    if should_analyze(request):


        # -------------------
        # DLP Scanner
        # -------------------

        dlp_result = dlp_scanner.scan(request.body)

        module_results.append(

            ModuleResult(

                module="DLP",
                score=dlp_result["total_score"],
                details=dlp_result["findings"]

            )

        )




        # Future modules go here

    # -------------------
    # TnC Analysis
    # -------------------

    if request.tnc_text:
        try:
            tnc_result = tnc_analyzer.analyze_text(request.tnc_text)
            module_results.append(
                ModuleResult(
                    module="TNC_ANALYSIS",
                    score=tnc_result["tnc_score"],
                    details={
                        "status": tnc_result["status"],
                        "findings": tnc_result["findings"]
                    }
                )
            )
        except Exception as e:
            module_results.append(
                ModuleResult(
                    module="TNC_ANALYSIS",
                    score=0,
                    details={"error": str(e)}
                )
            )
    # -------------------
    # Rookie Score
    # -------------------

    try:
        rookie_result = compute_rookie_score(
            domain=request.domain,
            method=request.method,
            headers=request.headers,
            files=request.files
        )
        module_results.append(
            ModuleResult(
                module="ROOKIE_SCORE",
                score=rookie_result["rookie_score"],
                details={
                    "trust_tier": rookie_result["trust_tier"],
                    "reasons": rookie_result["reasons"],
                    "signals": rookie_result["signals"]
                }
            )
        )

    except Exception as e:
        module_results.append(
            ModuleResult(
                module="ROOKIE_SCORE",
                score=0,
                details={"error": str(e)}
            )
        )


    # -----------------------------------
    # Aggregate results
    # -----------------------------------

    decision, total_score = aggregate(module_results)



    # -----------------------------------
    # Return response
    # -----------------------------------

    return {

        "decision": decision,
        "score": total_score,
        "details": module_results

    }



# ===================================
# DASHBOARD ENDPOINTS
# ===================================
# These replace the Flask backend (ui_dashboard/backend/api.py).
# The Electron renderer calls these directly on port 8000.


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.get("/api/traffic")
def get_traffic():
    """
    Returns the last 50 intercepted requests from the mitmproxy
    addon's log file, newest first.
    """
    try:
        if INTERCEPT_LOG_PATH.exists():
            with open(INTERCEPT_LOG_PATH, "r") as f:
                logs = json.load(f)
            return logs[-50:][::-1]
        return []
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/scan-pdf")
async def scan_pdf(file: UploadFile = File(...)):
    """
    Accepts a PDF upload, extracts text, and auto-detects sensitive
    data using DLP regex patterns from dlp_rules.py.
    """
    import sys
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from file_analysis import extract_text_from_pdf
    from file_analysis.redaction import scan_text

    try:
        pdf_bytes = await file.read()

        # 1. Extract text
        result = extract_text_from_pdf(pdf_bytes)
        if result.get("error"):
            return {"error": result["error"]}

        text = result["text"]

        # 2. Auto-detect findings using DLP regex (dynamic!)
        raw_findings = scan_text(text)

        # Deduplicate by value for the UI
        seen = set()
        findings = []
        for f in raw_findings:
            if f["match"] not in seen:
                seen.add(f["match"])
                findings.append({"type": f["type"], "value": f["match"]})

        return {
            "text_preview": text[:500] + "..." if len(text) > 500 else text,
            "page_count": result["page_count"],
            "findings": findings,
            "metadata": result.get("metadata", {}),
        }

    except Exception as e:
        return {"error": str(e)}


# -----------------------------------
# TnC ANALYSIS ENDPOINT (dedicated)
# -----------------------------------
# Called by the mitmproxy response() hook when a T&C / Privacy page
# is detected, OR directly by the frontend for manual analysis.

class TnCRequest(BaseModel):
    url: str = ""
    domain: str = ""
    tnc_text: str

class TnCResponse(BaseModel):
    url: str
    domain: str
    tnc_score: int
    status: str
    findings: List[Dict[str, Any]]

@app.post("/analyze-tnc", response_model=TnCResponse)
def analyze_tnc(request: TnCRequest):
    """
    Standalone T&C / Privacy Policy analysis.

    Accepts raw text from a T&C page and returns risk findings.
    This is separate from /evaluate because:
      - It runs on RESPONSE bodies (not request bodies)
      - It doesn't need DLP or Rookie Score
      - The frontend can call it directly for user-uploaded TnC text
    """
    if not request.tnc_text or not request.tnc_text.strip():
        return {
            "url": request.url,
            "domain": request.domain,
            "tnc_score": 0,
            "status": "SAFE",
            "findings": []
        }

    try:
        result = tnc_analyzer.analyze_text(request.tnc_text)

        print(f"[TNC] {request.domain} | Score: {result['tnc_score']} | Status: {result['status']}")

        return {
            "url": request.url,
            "domain": request.domain,
            "tnc_score": result["tnc_score"],
            "status": result["status"],
            "findings": result["findings"]
        }

    except Exception as e:
        print(f"[TNC ERROR] {request.domain} | {e}")
        return {
            "url": request.url,
            "domain": request.domain,
            "tnc_score": 0,
            "status": "ERROR",
            "findings": [{"category": "error", "risk_level": 0, "count": 0, "snippet": str(e)}]
        }
