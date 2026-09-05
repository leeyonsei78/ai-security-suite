from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.fsi_csp_audit_service import analyze, generate_markdown_report
from services.fsi_csp_audit_guide import ASSESSMENT_TYPES, DISCLAIMER, REFERENCE_LINKS
from services import db, notify

router = APIRouter(prefix="/api/fsi-csp-audit", tags=["fsi-csp-audit"])

APP_NAME = "fsi_csp_audit"

VALID_ASSESSMENT_TYPES = set(ASSESSMENT_TYPES.keys())


class AnalyzeRequest(BaseModel):
    assessment_type: str = "cloud_env_management"
    content: str
    context: str = ""


@router.get("/guide")
async def get_guide():
    return {"assessment_types": ASSESSMENT_TYPES, "disclaimer": DISCLAIMER, "reference_links": REFERENCE_LINKS}


@router.post("/analyze")
async def analyze_endpoint(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")
    if request.assessment_type not in VALID_ASSESSMENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid assessment_type, must be one of {sorted(VALID_ASSESSMENT_TYPES)}")

    result = analyze(request.assessment_type, request.content, request.context)
    entry = {
        "assessment_type": request.assessment_type,
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
