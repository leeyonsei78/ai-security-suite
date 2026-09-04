from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.dns_security_service import check_domain, generate_markdown_report, DISCLAIMER
from services import db, notify

router = APIRouter(prefix="/api/dns-security", tags=["dns-security"])

APP_NAME = "dns_security"


class CheckRequest(BaseModel):
    domain: str


@router.get("/guide")
async def get_guide():
    return {"disclaimer": DISCLAIMER}


@router.post("/check")
async def check(request: CheckRequest):
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Empty domain")

    result = await check_domain(domain)
    if result.get("error"):
        code = 400 if result["error"] == "invalid_format" else 404
        raise HTTPException(status_code=code, detail=result["message"])

    entry = dict(result)
    entry["id"] = db.add_entry(APP_NAME, entry)

    if entry.get("overall_risk") == "CRITICAL":
        top = next((c for c in entry.get("checks", []) if c.get("severity") == "CRITICAL"), None)
        summary = f"{top['check']}: {top['description']}" if top else entry.get("summary", "")
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
