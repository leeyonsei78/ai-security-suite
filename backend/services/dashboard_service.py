"""통합 리스크 대시보드 — 탐지형 앱(notify.APP_LABELS 기준, 앱이 추가될 때마다 자동으로
늘어남)의 실행 건수·CRITICAL 알림 건수를 한 곳에
집계한다. 앱마다 저장하는 결과 스키마가 제각각이라(App 1의 이벤트 목록, App 16의
findings, App 17의 매칭된 CVE 등) 개별 스키마를 파싱하지 않고, 모든 앱이 이미
공통으로 거치는 두 지점만 재사용한다 — history.db의 앱별 건수(db.get_history 길이)와
notify.py가 이미 정규화해 쌓아둔 alerts 테이블(app/app_label/severity/created_at).
새 분석 로직이 없어 Claude API를 쓰지 않고, 이 서버 안의 기존 데이터만 집계한다.
"""

from services import db, notify


def get_alert_entry(app: str, entry_id: int) -> dict | None:
    """알림 하나가 어느 원본 분석 결과(entry_id)에서 나왔는지 그대로 돌려준다 — 이 함수는
    스키마를 해석하지 않고 저장된 그대로 반환만 한다(해석은 프론트에서 대상/조치 후보
    필드를 찾아보는 best-effort 방식으로 처리, 앱마다 스키마가 달라 여기서 단정하지 않음)."""
    return db.get_entry(app, entry_id)


def get_alerts_for_app(app: str) -> list[dict]:
    """"앱별 현황"에서 한 앱을 펼쳤을 때 그 앱의 CRITICAL 알림 전체(최근 15건 제한 없이)를
    최신순으로 돌려준다 — "누적 CRITICAL 101건" 같은 숫자만 보고 정작 어디서 무엇을 봐야
    하는지 알 수 없다는 문제에 대한 직접적인 답."""
    alerts = db.get_history(notify.ALERTS_APP)
    return list(reversed([a for a in alerts if a.get("app") == app]))


def get_overview() -> dict:
    alerts = db.get_history(notify.ALERTS_APP)

    apps = []
    for app_name, label in notify.APP_LABELS.items():
        total_runs = len(db.get_history(app_name))
        app_alerts = [a for a in alerts if a.get("app") == app_name]
        unresolved = [a for a in app_alerts if not a.get("resolved")]
        apps.append({
            "app": app_name,
            "app_label": label,
            "total_runs": total_runs,
            "critical_alerts": len(app_alerts),
            "unresolved_critical_alerts": len(unresolved),
            "last_alert_at": app_alerts[-1]["created_at"] if app_alerts else None,
        })

    # 처리 여부를 추적하기 전에는 "누적 건수"로만 정렬했으나, 실제로 지금 봐야 할 앱은
    # "아직 안 끝난 게 많은 앱"이므로 미해결 건수를 최우선 기준으로 정렬한다.
    apps.sort(key=lambda a: (a["unresolved_critical_alerts"], a["critical_alerts"], a["total_runs"]), reverse=True)

    return {
        "apps": apps,
        "total_runs": sum(a["total_runs"] for a in apps),
        "total_critical_alerts": len(alerts),
        "total_unresolved_critical_alerts": sum(1 for a in alerts if not a.get("resolved")),
        "recent_alerts": list(reversed(alerts))[:15],
    }
