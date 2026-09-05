from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from services.cve_lookup_service import lookup_cve, search_cves, get_network_mode, HAS_API_KEY
from services import db, cve_offline_store, mode_manager

router = APIRouter(prefix="/api/cve", tags=["cve-lookup"])

APP_NAME = "cve_lookup"

_ERROR_STATUS = {
    "invalid_format": 400,
    "invalid_query": 400,
    "not_found": 404,
    "offline_not_cached": 503,
    "rate_limited": 429,
    "timeout": 504,
    "network": 502,
    "upstream_error": 502,
}


class ModeOverrideRequest(BaseModel):
    mode: str | None = None  # "online" | "offline" | null(자동 감지로 복귀)


@router.get("/status")
async def status():
    network_mode = await get_network_mode()
    return {
        "has_api_key": HAS_API_KEY,
        "source": "NVD (services.nvd.nist.gov)",
        "network_mode": network_mode,
        "override": mode_manager.get_override("cve"),
        "offline_cache": cve_offline_store.stats(),
    }


@router.post("/mode")
async def set_mode(request: ModeOverrideRequest):
    try:
        mode_manager.set_external_api_override("cve", request.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await status()


@router.post("/import-feed")
async def import_feed(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > 200 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="파일이 너무 큽니다 (최대 200MB)")
    try:
        result = cve_offline_store.import_feed(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.get("/search")
async def search(keyword: str, results_per_page: int = 10):
    result = await search_cves(keyword, results_per_page)
    if "error" in result:
        raise HTTPException(status_code=_ERROR_STATUS.get(result["error"], 500), detail=result["message"])
    return result


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}


@router.get("/{cve_id}")
async def get_cve(cve_id: str):
    result = await lookup_cve(cve_id)
    if "error" in result:
        raise HTTPException(status_code=_ERROR_STATUS.get(result["error"], 500), detail=result["message"])
    db.add_entry(APP_NAME, result)
    return result
