from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from services.claude_service import analyze_logs
from services.file_extract import extract_text, ExtractError
from services import db, notify

router = APIRouter(prefix="/api", tags=["analyze"])

APP_NAME = "dashboard"


class TextAnalysisRequest(BaseModel):
    content: str


@router.post("/analyze/upload")
async def analyze_log_file(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        log_text = extract_text(file.filename or "", raw)["text"]
    except ExtractError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await analyze_logs(log_text)
    result["filename"] = file.filename
    result["id"] = db.add_entry(APP_NAME, result)
    await notify.alert_if_critical(
        APP_NAME, result.get("threat_level") == "CRITICAL", "CRITICAL", result.get("summary", ""), result["id"]
    )
    return result


@router.post("/analyze/text")
async def analyze_log_text(request: TextAnalysisRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")

    result = await analyze_logs(request.content)
    result["filename"] = "manual_input"
    result["id"] = db.add_entry(APP_NAME, result)
    await notify.alert_if_critical(
        APP_NAME, result.get("threat_level") == "CRITICAL", "CRITICAL", result.get("summary", ""), result["id"]
    )
    return result


@router.get("/threats")
async def get_threats():
    analyses = db.get_history(APP_NAME)
    return {"analyses": analyses, "total": len(analyses)}


@router.delete("/threats")
async def clear_threats():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
