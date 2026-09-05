from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.ioc_service import analyze_ioc
from services import db, notify

router = APIRouter(prefix="/api/ioc", tags=["ioc"])

APP_NAME = "ioc"


class AnalyzeRequest(BaseModel):
    content: str


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 10000:
        raise HTTPException(status_code=400, detail="Too many IoCs")

    results = await analyze_ioc(request.content)
    if not results:
        raise HTTPException(status_code=400, detail="No valid IoCs found")

    entry = {"results": results, "total": len(results)}
    entry["id"] = db.add_entry(APP_NAME, entry)
    malicious = [r for r in results if r.get("verdict") == "MALICIOUS"]
    if malicious:
        summary = f"{len(malicious)}개의 악성 IoC 탐지: " + ", ".join(f"{r.get('ioc')}({r.get('category', '')})" for r in malicious[:5])
        await notify.alert_if_critical(APP_NAME, True, "MALICIOUS", summary, entry["id"])
    return entry


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
