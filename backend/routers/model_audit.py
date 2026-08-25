from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.model_audit_service import analyze_model_audit, generate_markdown_report
from services.owasp_llm_reference import OWASP_LLM_TOP10, OWASP_LLM_DISCLAIMER
from services import db

router = APIRouter(prefix="/api/model-audit", tags=["model-audit"])

APP_NAME = "model_audit"


class AnalyzeRequest(BaseModel):
    content: str
    input_type: str = "system_prompt"  # "system_prompt" | "config" | "tools"


@router.get("/reference")
async def get_reference():
    return {"owasp_llm_top10": OWASP_LLM_TOP10, "disclaimer": OWASP_LLM_DISCLAIMER}


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")

    result = analyze_model_audit(request.content, request.input_type)
    entry = {
        "input_type": request.input_type,
        "preview": request.content[:100].replace("\n", " "),
        **result,
    }
    entry["id"] = db.add_entry(APP_NAME, entry)
    return entry


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int):
    entry = db.get_entry(APP_NAME, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return generate_markdown_report(entry)
