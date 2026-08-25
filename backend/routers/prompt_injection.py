from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.prompt_injection_service import analyze_injection
from services import db

router = APIRouter(prefix="/api/injection", tags=["prompt-injection"])

APP_NAME = "injection"


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
        "input_type": request.input_type,
        "preview": request.content[:120].replace("\n", " "),
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
