from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from services.claude_service import analyze_logs

router = APIRouter(prefix="/api", tags=["analyze"])

# In-memory store for demo purposes
analysis_store: list[dict] = []


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
    result["id"] = len(analysis_store) + 1
    analysis_store.append(result)
    return result


@router.post("/analyze/text")
async def analyze_log_text(request: TextAnalysisRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")

    result = analyze_logs(request.content)
    result["filename"] = "manual_input"
    result["id"] = len(analysis_store) + 1
    analysis_store.append(result)
    return result


@router.get("/threats")
async def get_threats():
    return {"analyses": analysis_store, "total": len(analysis_store)}


@router.delete("/threats")
async def clear_threats():
    analysis_store.clear()
    return {"message": "Cleared"}
