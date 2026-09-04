from fastapi import APIRouter
from services.dashboard_service import get_overview

router = APIRouter(prefix="/api/dashboard", tags=["dashboard-overview"])


@router.get("/overview")
async def overview():
    return get_overview()
