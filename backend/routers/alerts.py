from fastapi import APIRouter
from services import notify

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def get_alerts():
    return {
        "alerts": notify.get_alerts(),
        "is_mock": notify.IS_MOCK,
        "configured": {"slack": notify.IS_SLACK_CONFIGURED, "email": notify.IS_EMAIL_CONFIGURED},
    }


@router.delete("")
async def clear_alerts():
    notify.clear_alerts()
    return {"message": "Cleared"}
