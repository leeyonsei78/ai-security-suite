from fastapi import APIRouter, HTTPException
from services import notify
from services.dashboard_service import get_overview, get_alert_entry, get_alerts_for_app

router = APIRouter(prefix="/api/dashboard", tags=["dashboard-overview"])


@router.get("/overview")
async def overview():
    return get_overview()


@router.get("/alerts")
async def alerts_for_app(app: str):
    """"앱별 현황" 행을 펼쳤을 때 그 앱의 CRITICAL 알림 전체 목록을 최신순으로 반환한다
    ("최근 알림"의 15건 캡과 달리 개수 제한 없음)."""
    return {"alerts": get_alerts_for_app(app)}


@router.get("/alert-entry")
async def alert_entry(app: str, entry_id: int):
    """알림 카드를 펼쳤을 때 "대상/방법/확인"을 보여주기 위해 원본 분석 결과를 그대로
    반환한다 — 앱마다 스키마가 달라 여기서는 해석하지 않고 프론트가 best-effort로 찾는다."""
    entry = get_alert_entry(app, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="원본 분석 결과를 찾을 수 없습니다 (삭제되었거나 초기화됨)")
    return entry


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int):
    updated = notify.set_alert_resolved(alert_id, True)
    if updated is None:
        raise HTTPException(status_code=404, detail="알림을 찾을 수 없습니다")
    return updated


@router.post("/alerts/{alert_id}/reopen")
async def reopen_alert(alert_id: int):
    updated = notify.set_alert_resolved(alert_id, False)
    if updated is None:
        raise HTTPException(status_code=404, detail="알림을 찾을 수 없습니다")
    return updated
