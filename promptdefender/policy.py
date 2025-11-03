from __future__ import annotations
from typing import Dict, Any
from promptdefender.detector import DetectionResult

# Map labels/risk to gate decisions you can enforce in your app/tool layer.
def decide(result: DetectionResult) -> str:
    # already computed in DetectionResult, but example hook for richer policies
    return result.decision

def allowed_tools(result: DetectionResult) -> Dict[str, Any]:
    # Example: disallow file or shell tools when risk labels are dangerous
    denied = {"file_read": False, "shell_exec": False, "code_run": True}
    if "tool-abuse" in result.labels or result.risk_score >= 60:
        denied["code_run"] = False
    return denied
