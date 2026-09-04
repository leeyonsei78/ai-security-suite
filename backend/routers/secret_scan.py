from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.secret_scanner_service import (
    scan_text, generate_markdown_report, PATTERN_REFERENCE, DISCLAIMER, MAX_CONTENT_CHARS,
)
from services import db, notify

router = APIRouter(prefix="/api/secret-scan", tags=["secret-scan"])

APP_NAME = "secret_scan"


class ScanRequest(BaseModel):
    content: str
    filename: str = ""


@router.get("/guide")
async def get_guide():
    return {"patterns": PATTERN_REFERENCE, "disclaimer": DISCLAIMER}


@router.post("/scan")
async def scan(request: ScanRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > MAX_CONTENT_CHARS:
        raise HTTPException(status_code=400, detail=f"Content too long (max {MAX_CONTENT_CHARS:,} chars)")

    result = scan_text(request.content, request.filename)
    # ⚠️ 원본 content는 절대 저장하지 않는다 — 길이/줄 수 같은 비민감 메타데이터만 기록
    entry = {
        "filename": request.filename,
        "char_count": len(request.content),
        "line_count": request.content.count("\n") + 1,
        **result,
    }
    entry["id"] = db.add_entry(APP_NAME, entry)

    if entry.get("overall_risk") == "CRITICAL":
        top = next((f for f in entry.get("findings", []) if f.get("severity") == "CRITICAL"), None)
        summary = f"{top['pattern_label']} 발견 (line {top['line']})" if top else entry.get("summary", "")
        await notify.alert_if_critical(APP_NAME, True, "CRITICAL", summary, entry["id"])

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
