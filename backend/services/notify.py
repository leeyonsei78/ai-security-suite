"""Critical 탐지 시 이메일/슬랙 알림 (Roadmap "알림 시스템"). App 1(대시보드·실시간
모니터링)/2(피싱)/3(취약점)/4(IoC)/6(웹스캐너)/8(인젝션탐지)/12(모델감사)처럼 단일
판정 결과를 내는 탐지형 앱에서, 그 결과가 최고 심각도(각 앱 기준 CRITICAL/MALICIOUS/
INJECTION)일 때만 호출된다. 상담형 앱(인시던트 대응·위협 분석 랩)과 생성형 앱(보안
정책 생성기)은 "위협을 판정"하는 게 아니라 대상이 아니다.

SLACK_WEBHOOK_URL 또는 SMTP_* 환경변수가 없으면 Mock 모드로 동작 — 실제로 전송하지
않고 앱 내 알림 로그에만 기록한다 (다른 앱들의 Mock/Live 모드와 동일한 패턴).
"""

import asyncio
import json
import os
import smtplib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText

from dotenv import load_dotenv

from services import db

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "").strip()
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "").strip() or SMTP_USER

IS_SLACK_CONFIGURED = bool(SLACK_WEBHOOK_URL)
IS_EMAIL_CONFIGURED = bool(SMTP_HOST and ALERT_EMAIL_TO)
IS_MOCK = not (IS_SLACK_CONFIGURED or IS_EMAIL_CONFIGURED)

APP_LABELS = {
    "dashboard": "AI 보안 분석 대시보드",
    "phishing": "피싱/악성 콘텐츠 탐지기",
    "vuln": "취약점 스캐너",
    "ioc": "IoC 분석기",
    "webscan": "웹 취약점 스캐너",
    "injection": "프롬프트 인젝션 탐지기",
    "model_audit": "AI 모델 감사",
    "firewall_audit": "방화벽 정책 감사기",
    "infra_scan_dependency": "인프라 취약점 스캐너 (의존성)",
    "infra_scan_network": "인프라 취약점 스캐너 (네트워크)",
}

ALERTS_APP = "alerts"


def _send_slack(title: str, message: str) -> dict:
    payload = json.dumps({"text": f"*{title}*\n{message}"}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"ok": resp.status == 200, "status": resp.status}
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e)}


def _send_email(title: str, message: str) -> dict:
    msg = MIMEText(message)
    msg["Subject"] = title
    msg["From"] = ALERT_EMAIL_FROM
    msg["To"] = ALERT_EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _dispatch(title: str, message: str) -> dict:
    result = {}
    if IS_SLACK_CONFIGURED:
        result["slack"] = _send_slack(title, message)
    if IS_EMAIL_CONFIGURED:
        result["email"] = _send_email(title, message)
    return result


def send_alert(app: str, severity_label: str, summary: str, entry_id: int | None) -> dict:
    label = APP_LABELS.get(app, app)
    title = f"[{severity_label}] {label}에서 위협 탐지"
    message = f"{summary}\n\n분석 ID: {entry_id if entry_id is not None else 'N/A'}"

    if IS_MOCK:
        dispatch_result = {
            "mock": True,
            "note": "SLACK_WEBHOOK_URL 또는 SMTP_* 환경변수가 설정되지 않아 Mock 모드로 동작합니다. 실제 전송은 되지 않았습니다.",
        }
    else:
        dispatch_result = _dispatch(title, message)

    alert = {
        "app": app,
        "app_label": label,
        "severity": severity_label,
        "summary": summary,
        "entry_id": entry_id,
        "dispatch": dispatch_result,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    alert_id = db.add_entry(ALERTS_APP, alert)
    alert["id"] = alert_id
    return alert


async def alert_if_critical(
    app: str, is_critical: bool, severity_label: str, summary: str, entry_id: int | None
) -> dict | None:
    """호출부가 이미 판정한 "이게 이 앱 기준 최고 심각도인가"만 받아 알림 발송을 담당한다.
    실제 전송(urllib/smtplib)은 블로킹 호출이라, 이를 async 라우트 안에서 그대로 기다리면
    이벤트 루프를 막는다 — 실시간 모니터링 WebSocket에서 이미 겪은 것과 같은 함정이라
    run_in_executor로 스레드에 위임한다."""
    if not is_critical:
        return None
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, send_alert, app, severity_label, summary, entry_id)


def get_alerts(limit: int = 50) -> list[dict]:
    alerts = db.get_history(ALERTS_APP)
    return list(reversed(alerts))[:limit]


def clear_alerts() -> None:
    db.clear_history(ALERTS_APP)
