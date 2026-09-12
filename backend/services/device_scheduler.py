"""등록된 장비(방화벽/스위치/서버/클라우드 계정)를 각자 설정된 주기로 자동 수집·분석하는
백그라운드 루프 — 이번에 신설한 "장비 관리 자동 점검" 기능의 핵심.

SIEM 장비들이 방화벽·스위치 등에 API/SSH로 직접 접속해 정보를 주기적으로 가져와
분석하는 것과 같은 동작을, 이 프로젝트에 이미 있는 부품들을 조합해 구현한다:
- 수집: `device_collector.collect()` (SSH/클라우드 CLI/PowerShell — App 23/25 재사용)
- 분석: `firewall_audit_service.analyze_firewall()` / `iam_audit_service.analyze_iam()` /
  `claude_service.analyze_logs()` — 기존 감사/로그분석 엔진을 그대로 재사용(새 AI 프롬프트를
  만들지 않음)
- 저장·알림: `db.add_entry("device_monitor", ...)` + `notify.alert_if_critical(...)` — 다른
  탐지형 앱과 동일한 패턴이라 App 22(통합 리스크 대시보드)에도 자동으로 집계된다.

수동 트리거([지금 수집] 버튼, `routers/devices.py`)와 주기 스케줄러가 `run_device_scan()`
하나를 공유한다 — 수동/자동 경로를 따로 구현하지 않는다.

수집(SSH/서브프로세스/PowerShell)은 전부 블로킹 호출이라, 이 프로젝트 전체에서 반복된
패턴대로 `run_in_executor()`로 스레드에 위임해 이벤트 루프(다른 API 요청, WebSocket 등)를
막지 않게 한다.
"""

import asyncio
import logging
from datetime import datetime, timezone

from services import db, device_collector, device_store, firewall_audit_service, iam_audit_service, notify
from services import claude_service

logger = logging.getLogger("device_scheduler")

APP_NAME = "device_monitor"
POLL_INTERVAL_SECONDS = 20

# 이미 수집 중인 장비를 다음 tick에서 또 집지 않기 위한 in-memory 가드 — DB 컬럼 대신
# 프로세스 메모리로 충분하다(재시작되면 어차피 진행 중이던 수집도 함께 끊기므로).
_running_ids: set[int] = set()

_ANALYZERS = {
    "firewall_audit": firewall_audit_service.analyze_firewall,
    "iam_audit": iam_audit_service.analyze_iam,
}


def _severity_and_summary(analyzer: str, result: dict) -> tuple[str, str]:
    if analyzer == "log_analysis":
        severity = result.get("threat_level", "INFO")
        events = result.get("events") or []
        top = next((e for e in events if e.get("severity") == severity), events[0] if events else None)
        summary = top["description"] if top else result.get("summary", "")
        return severity, summary

    severity = result.get("overall_risk", "INFO")
    findings = result.get("findings") or []
    top = next((f for f in findings if f.get("severity") == severity), findings[0] if findings else None)
    summary = top["description"] if top else result.get("summary", "")
    return severity, summary


async def run_device_scan(device_id: int) -> dict:
    """장비 하나를 지금 즉시 수집·분석한다. 수동([지금 수집] 버튼)·자동(스케줄러) 양쪽에서 호출."""
    device = device_store.get_device_internal(device_id)
    if device is None:
        raise ValueError(f"Device not found: {device_id}")

    loop = asyncio.get_event_loop()
    collected = await loop.run_in_executor(None, device_collector.collect, device)

    if not collected.get("ok"):
        device_store.record_result(
            device_id, status="error", error=collected.get("error"), severity=None,
            summary=None, entry_id=None, interval_minutes=device["interval_minutes"],
        )
        return {"ok": False, "error": collected.get("error"), "device_id": device_id}

    analyzer = device["analyzer"]
    content = collected["content"]
    if not content.strip():
        content = "(수집된 내용이 비어 있습니다 — 규칙/로그가 없거나 조회 결과가 없습니다.)"

    if analyzer == "log_analysis":
        result = await claude_service.analyze_logs(content)
    else:
        fn = _ANALYZERS[analyzer]
        result = await fn(collected["source_type"], content, device.get("context", ""))

    severity, summary = _severity_and_summary(analyzer, result)

    entry = {
        "device_id": device_id,
        "device_name": device["name"],
        "device_type": device["device_type"],
        "analyzer": analyzer,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        # notify.py의 알림 스냅샷(App22 대시보드용)이 mode를 entry 최상위에서 찾으므로
        # (다른 앱들은 result를 entry에 그대로 펼쳐 담아 자연히 최상위에 있음) 여기서도 복사해둔다.
        "mode": result.get("mode"),
        "result": result,
    }
    entry_id = db.add_entry(APP_NAME, entry)
    entry["id"] = entry_id

    is_critical = severity == "CRITICAL"
    await notify.alert_if_critical(
        APP_NAME, is_critical, "CRITICAL", f"[{device['name']}] {summary}", entry_id, entry
    )

    device_store.record_result(
        device_id, status="ok", error=None, severity=severity, summary=summary,
        entry_id=entry_id, interval_minutes=device["interval_minutes"],
    )
    return {"ok": True, "entry": entry, "device_id": device_id}


async def _tick() -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    for device_id in device_store.list_due(now_iso):
        if device_id in _running_ids:
            continue
        _running_ids.add(device_id)
        asyncio.create_task(_run_and_release(device_id))


async def _run_and_release(device_id: int) -> None:
    try:
        await run_device_scan(device_id)
    except Exception:
        logger.exception("device scan failed for device_id=%s", device_id)
    finally:
        _running_ids.discard(device_id)


async def _loop() -> None:
    while True:
        try:
            await _tick()
        except Exception:
            logger.exception("device scheduler tick failed")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


def start_background_loop() -> None:
    asyncio.get_event_loop().create_task(_loop())
