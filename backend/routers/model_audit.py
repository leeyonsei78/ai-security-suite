from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.model_audit_service import analyze_model_audit, generate_markdown_report
from services.owasp_llm_reference import OWASP_LLM_TOP10, OWASP_LLM_DISCLAIMER

router = APIRouter(prefix="/api/model-audit", tags=["model-audit"])

history: list[dict] = []


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
        "id": len(history) + 1,
        "input_type": request.input_type,
        "preview": request.content[:100].replace("\n", " "),
        **result,
    }
    history.append(entry)
    return entry


@router.get("/history")
async def get_history():
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    history.clear()
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int):
    entry = next((h for h in history if h["id"] == entry_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return generate_markdown_report(entry)
