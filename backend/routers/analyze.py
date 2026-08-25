from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from services.claude_service import analyze_logs
from services import db

router = APIRouter(prefix="/api", tags=["analyze"])

APP_NAME = "dashboard"


class TextAnalysisRequest(BaseModel):
    content: str


@router.post("/analyze/upload")
async def analyze_log_file(file: UploadFile = File(...)):
    if not file.filename.endswith((".log", ".txt", ".csv", ".json")):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    content = await file.read()
    log_text = content.decode("utf-8", errors="replace")

    if len(log_text) > 50000:
        log_text = log_text[:50000]

    result = analyze_logs(log_text)
    result["filename"] = file.filename
    result["id"] = db.add_entry(APP_NAME, result)
    return result


@router.post("/analyze/text")
async def analyze_log_text(request: TextAnalysisRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")

    result = analyze_logs(request.content)
    result["filename"] = "manual_input"
    result["id"] = db.add_entry(APP_NAME, result)
    return result


@router.get("/threats")
async def get_threats():
    analyses = db.get_history(APP_NAME)
    return {"analyses": analyses, "total": len(analyses)}


@router.delete("/threats")
async def clear_threats():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
