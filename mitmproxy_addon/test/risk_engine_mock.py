# risk_engine_mock.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict
import uvicorn

app = FastAPI()

class FileInfo(BaseModel):
    filename: str
    content_type: str
    size: int

class RequestData(BaseModel):
    domain: str
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    keywords_found: List[str] = []
    files: List[FileInfo] = []

@app.post("/evaluate")
def evaluate(request: RequestData):
    """
    Mock evaluation:
    - Block if keywords found
    - Warn if domain contains 'test'
    - Allow otherwise
    """
    print("Received request:", request.dict())

    if request.keywords_found:
        decision = "BLOCK"
    elif "test" in request.domain.lower():
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "score": len(request.keywords_found) * 10,
        "decision": decision,
        "details": {"mock": "This is a mock response"}
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
