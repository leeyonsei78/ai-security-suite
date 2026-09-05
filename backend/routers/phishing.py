from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.phishing_service import analyze_phishing
from services import db, notify

router = APIRouter(prefix="/api/phishing", tags=["phishing"])

APP_NAME = "phishing"


class AnalyzeRequest(BaseModel):
    content: str
    input_type: str = "text"  # "email" | "url" | "text"


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")

    result = await analyze_phishing(request.content)
    entry = {
        "input_type": request.input_type,
        "preview": request.content[:120].replace("\n", " "),
        **result,
    }
    entry["id"] = db.add_entry(APP_NAME, entry)
    await notify.alert_if_critical(
        APP_NAME, entry.get("verdict") == "MALICIOUS", "MALICIOUS", entry.get("summary", ""), entry["id"]
    )
    return entry


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
