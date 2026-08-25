from fastapi import APIRouter, HTTPException
from services.cve_lookup_service import lookup_cve, search_cves, HAS_API_KEY
from services import db

router = APIRouter(prefix="/api/cve", tags=["cve-lookup"])

APP_NAME = "cve_lookup"

_ERROR_STATUS = {
    "invalid_format": 400,
    "invalid_query": 400,
    "not_found": 404,
    "rate_limited": 429,
    "timeout": 504,
    "network": 502,
    "upstream_error": 502,
}


@router.get("/status")
async def status():
    return {"has_api_key": HAS_API_KEY, "source": "NVD (services.nvd.nist.gov)"}


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
