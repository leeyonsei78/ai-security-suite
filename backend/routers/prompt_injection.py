from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.prompt_injection_service import analyze_injection

router = APIRouter(prefix="/api/injection", tags=["prompt-injection"])

history: list[dict] = []


class AnalyzeRequest(BaseModel):
    content: str
    input_type: str = "prompt"  # "prompt" | "document" | "conversation"


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")

    result = analyze_injection(request.content, request.input_type)
    entry = {
        "id": len(history) + 1,
        "input_type": request.input_type,
        "preview": request.content[:120].replace("\n", " "),
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
