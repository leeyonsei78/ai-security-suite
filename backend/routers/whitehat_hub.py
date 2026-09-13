from fastapi import APIRouter
from services import whitehat_hub_service

router = APIRouter(prefix="/api/whitehat-hub", tags=["whitehat-hub"])


@router.get("/catalog")
async def get_catalog():
    return whitehat_hub_service.get_catalog()
