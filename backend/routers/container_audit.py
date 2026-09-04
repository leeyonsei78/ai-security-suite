from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.container_audit_service import analyze_container, generate_markdown_report, SOURCE_LABELS
from services.container_audit_guide import SOURCE_TYPES, DISCLAIMER
from services import db, notify

router = APIRouter(prefix="/api/container-audit", tags=["container-audit"])

APP_NAME = "container_audit"

VALID_SOURCE_TYPES = set(SOURCE_LABELS.keys())


class AnalyzeRequest(BaseModel):
    source_type: str = "dockerfile"
    content: str
    context: str = ""


@router.get("/guide")
async def get_guide():
    return {"source_types": SOURCE_TYPES, "disclaimer": DISCLAIMER}


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")
    if request.source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source_type, must be one of {sorted(VALID_SOURCE_TYPES)}")

    result = analyze_container(request.source_type, request.content, request.context)
    entry = {
        "source_type": request.source_type,
        "preview": request.content.strip()[:100].replace("\n", " "),
        **result,
    }
    entry["id"] = db.add_entry(APP_NAME, entry)

    if entry.get("overall_risk") == "CRITICAL":
        top = next((f for f in entry.get("findings", []) if f.get("severity") == "CRITICAL"), None)
        summary = top["description"] if top else entry.get("summary", "")
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
