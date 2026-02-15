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

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, List

from .dlp_scanner import DLPScanner

# Optional module imports
try:
    from .rookie_score import RookieScore
except ImportError:
    RookieScore = None


# -----------------------------------
# FastAPI Init
# -----------------------------------

app = FastAPI(title="Agency Guard Risk Engine")



# -----------------------------------
# Initialize modules ONCE
# -----------------------------------

dlp_scanner = DLPScanner()

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


        # -------------------
        # Rookie Score
        # -------------------

        if rookie_score:

            rookie_result = rookie_score.calculate(request.domain)

            module_results.append(

                ModuleResult(

                    module="ROOKIE_SCORE",
                    score=rookie_result["score"],
                    details=rookie_result.get("details")

                )

            )


        # Future modules go here


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
