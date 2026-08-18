from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.webscan_service import scan_url, IS_MOCK

router = APIRouter(prefix="/api/webscan", tags=["webscan"])

history: list[dict] = []


class ScanRequest(BaseModel):
    url: str


@router.post("/scan")
async def scan(request: ScanRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL required")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    if len(url) > 500:
        raise HTTPException(status_code=400, detail="URL too long")

    result = await scan_url(url)
    if "error" in result and not result.get("findings"):
        raise HTTPException(status_code=400, detail=result["error"])

    entry = {"id": len(history) + 1, **result}
    history.append(entry)
    return entry


@router.get("/history")
async def get_history():
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    history.clear()
    return {"message": "Cleared"}


@router.get("/mode")
async def get_mode():
    return {"mock": IS_MOCK}
