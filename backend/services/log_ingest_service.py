"""Syslog(rsyslog/syslog-ng) 등 임의의 로그 포워더가 HTTPS로 직접 로그를 보낼 수
있게 하는 범용 수집 엔드포인트(App 18). App 17(CloudTrail)이 AWS 전용 웹훅이라면
이건 "HTTPS POST만 할 수 있으면 어떤 로그 소스든" 붙일 수 있는 범용 버전이다.

이 서버가 UDP 514 같은 syslog 포트를 직접 열어 인터넷에 노출하지 않는다 — 고객사
쪽 rsyslog/syslog-ng가 이미 파싱한 로그를 JSON으로 변환해 이 엔드포인트에 HTTPS로
포워딩하는 구조(docs/log-ingest-integration.md 참고). 소스별로 발급되는
`ingest_key`로 인증하며, 이 값이 새 로 나가면 삭제 후 재발급하는 방식으로 회전한다
(우리 내부 API_KEY와는 별개 — 여러 고객사 소스를 서로 격리하기 위해 소스 단위로 발급).
"""

import asyncio
import secrets
from datetime import datetime, timezone

from services import db, notify
from services.claude_service import analyze_logs

APP_NAME = "log_sources"
MAX_LINES_PER_BATCH = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_source(label: str) -> dict:
    if not label.strip():
        raise ValueError("label은 필수입니다")
    source = {
        "label": label.strip(),
        "ingest_key": secrets.token_urlsafe(24),
        "created_at": _now(),
        "last_event_at": None,
        "last_error": None,
        "events_ingested": 0,
        "enabled": True,
    }
    source["id"] = db.add_entry(APP_NAME, source)
    return source


def list_sources() -> list[dict]:
    return db.get_history(APP_NAME)


def get_source(source_id: int) -> dict | None:
    return db.get_entry(APP_NAME, source_id)


def get_source_by_key(ingest_key: str) -> dict | None:
    if not ingest_key:
        return None
    for s in list_sources():
        if s.get("enabled", True) and secrets.compare_digest(s.get("ingest_key", ""), ingest_key):
            return s
    return None


def delete_source(source_id: int) -> None:
    db.delete_entry(APP_NAME, source_id)


def line_from_entry(entry) -> str:
    """rsyslog(omhttp)/syslog-ng(format-json) 쪽에서 흔히 쓰는 필드명을 그대로 지원."""
    if isinstance(entry, dict):
        ts = entry.get("timestamp") or entry.get("date") or ""
        host = entry.get("host") or entry.get("HOST") or ""
        sev = entry.get("severity") or entry.get("PRIORITY") or ""
        msg = entry.get("message") or entry.get("MESSAGE") or entry.get("msg") or ""
        return f"{ts} host={host} severity={sev} {msg}".strip()
    return str(entry)


async def ingest(source: dict, lines: list[str]) -> None:
    if not lines:
        return
    lines = lines[:MAX_LINES_PER_BATCH]
    log_content = "\n".join(lines)

    loop = asyncio.get_event_loop()
    # analyze_logs()는 Live 모드에서 Anthropic SDK를 동기 호출한다 — App 1/17과 동일한
    # 이유로 스레드 오프로드(run_in_executor) 필요
    result = await loop.run_in_executor(None, analyze_logs, log_content)
    result["filename"] = f"syslog:{source['label']}"
    result["raw_log"] = log_content
    result["id"] = db.add_entry("dashboard", result)

    await notify.alert_if_critical(
        "dashboard", result.get("threat_level") == "CRITICAL", "CRITICAL",
        f"[{source['label']}] {result.get('summary', '')}", result["id"],
    )

    db.update_entry(APP_NAME, source["id"], {
        **source, "last_event_at": _now(), "last_error": None,
        "events_ingested": source.get("events_ingested", 0) + len(lines),
    })
