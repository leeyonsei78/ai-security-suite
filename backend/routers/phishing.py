from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.phishing_service import analyze_phishing

router = APIRouter(prefix="/api/phishing", tags=["phishing"])

history: list[dict] = []


class AnalyzeRequest(BaseModel):
    content: str
    input_type: str = "text"  # "email" | "url" | "text"


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")

    result = analyze_phishing(request.content)
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
