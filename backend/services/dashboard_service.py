"""통합 리스크 대시보드 — 탐지형 앱 14개의 실행 건수·CRITICAL 알림 건수를 한 곳에
집계한다. 앱마다 저장하는 결과 스키마가 제각각이라(App 1의 이벤트 목록, App 16의
findings, App 17의 매칭된 CVE 등) 개별 스키마를 파싱하지 않고, 모든 앱이 이미
공통으로 거치는 두 지점만 재사용한다 — history.db의 앱별 건수(db.get_history 길이)와
notify.py가 이미 정규화해 쌓아둔 alerts 테이블(app/app_label/severity/created_at).
새 분석 로직이 없어 Claude API를 쓰지 않고, 이 서버 안의 기존 데이터만 집계한다.
"""

from services import db, notify


def get_overview() -> dict:
    alerts = db.get_history(notify.ALERTS_APP)

    apps = []
    for app_name, label in notify.APP_LABELS.items():
        total_runs = len(db.get_history(app_name))
        app_alerts = [a for a in alerts if a.get("app") == app_name]
        apps.append({
            "app": app_name,
            "app_label": label,
            "total_runs": total_runs,
            "critical_alerts": len(app_alerts),
            "last_alert_at": app_alerts[-1]["created_at"] if app_alerts else None,
        })

    apps.sort(key=lambda a: (a["critical_alerts"], a["total_runs"]), reverse=True)

    return {
        "apps": apps,
        "total_runs": sum(a["total_runs"] for a in apps),
        "total_critical_alerts": len(alerts),
        "recent_alerts": list(reversed(alerts))[:15],
    }
