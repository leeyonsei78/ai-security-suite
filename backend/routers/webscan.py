from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.webscan_service import scan_url, IS_MOCK
from services import db, notify

router = APIRouter(prefix="/api/webscan", tags=["webscan"])

APP_NAME = "webscan"


class ScanRequest(BaseModel):
    url: str
    authorized: bool = False


@router.post("/scan")
async def scan(request: ScanRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")
    if not request.authorized:
        raise HTTPException(status_code=400, detail="authorized=true로 이 사이트에 대한 소유권/테스트 권한을 확인해야 스캔이 실행됩니다.")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    if len(url) > 500:
        raise HTTPException(status_code=400, detail="URL too long")

    result = await scan_url(url)
    if "error" in result and not result.get("findings"):
        raise HTTPException(status_code=400, detail=result["error"])

    entry = dict(result)
    entry["id"] = db.add_entry(APP_NAME, entry)
    has_critical = any(f.get("severity") == "CRITICAL" for f in entry.get("findings", []))
    await notify.alert_if_critical(APP_NAME, has_critical, "CRITICAL", entry.get("summary", ""), entry["id"])
    return entry


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}


@router.get("/mode")
async def get_mode():
    return {"mock": IS_MOCK}
