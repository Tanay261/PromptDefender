from fastapi import FastAPI
from pydantic import BaseModel
from promptdefender.detector import Detector
from promptdefender.policy import decide
from promptdefender.sanitizer import sanitize

app = FastAPI(title="PromptDefender", version="0.1.0")
detector = Detector()

class DetectIn(BaseModel):
    prompt: str

class DetectOut(BaseModel):
    risk_score: float
    labels: list[str]
    decision: str
    explanations: list[dict]
    sanitized_prompt: str | None = None

@app.post("/detect", response_model=DetectOut)
def detect(inp: DetectIn):
    res = detector.analyze(inp.prompt)
    out = {
        "risk_score": res.risk_score,
        "labels": res.labels,
        "decision": decide(res),
        "explanations": [e.__dict__ for e in res.explanations],
        "sanitized_prompt": None
    }
    if out["decision"] == "SANITIZE":
        sanitized, _ = sanitize(inp.prompt)
        out["sanitized_prompt"] = sanitized
    return out

@app.get("/healthz")
def health():
    return {"ok": True}
