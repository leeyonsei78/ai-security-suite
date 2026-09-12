"""장비(방화벽/스위치/서버/클라우드 계정) 등록 정보 저장소.

`db.py`의 범용 히스토리 테이블(JSON 블롭)과 달리, 이 테이블은 스케줄러가 "지금
수집할 시각이 된 장비가 무엇인지"를 SQL로 직접 걸러야 해서 `enabled`/`next_run_at`을
전용 컬럼으로 둔다. 접속 정보(호스트/사용자명/암호화된 비밀번호 등)처럼 장비
유형마다 모양이 다른 필드는 기존 프로젝트 관행대로 JSON 블롭(`data`)에 담는다.

비밀번호는 절대 평문으로 저장하지 않는다 — `crypto_util.encrypt()`로 암호화한
값만 `data.secret_enc`에 넣고, 조회 API(`to_public`)는 이 필드 자체를 아예
빼버려 화면에도 API 응답에도 다시 나타나지 않는다. 스케줄러/수집기처럼 실제
접속이 필요한 내부 코드만 `get_device_internal()`로 복호화된 값을 받는다.
"""

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from services import crypto_util

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "history.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
_conn.execute(
    """
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        device_type TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        interval_minutes INTEGER NOT NULL DEFAULT 60,
        next_run_at TEXT,
        last_run_at TEXT,
        last_status TEXT,
        last_severity TEXT,
        last_summary TEXT,
        last_entry_id INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        data TEXT NOT NULL
    )
    """
)
_conn.commit()
_lock = threading.Lock()

# 장비 유형별로 고를 수 있는 분석기 — 프론트/라우터 양쪽에서 검증에 재사용한다.
ANALYZERS_BY_DEVICE_TYPE = {
    "network_device": ["firewall_audit"],
    "linux_host": ["firewall_audit", "log_analysis"],
    "windows_host": ["firewall_audit", "log_analysis"],
    "aws_account": ["firewall_audit", "iam_audit"],
    "azure_subscription": ["firewall_audit", "iam_audit"],
    "gcp_project": ["firewall_audit", "iam_audit"],
}

NETWORK_VENDORS = ["cisco_ios", "fortinet", "palo_alto", "juniper"]

_SECRET_FIELDS = {"password"}


def _iso_utc(sqlite_dt: str) -> str:
    return sqlite_dt.replace(" ", "T") + "Z"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row) -> dict:
    (row_id, name, device_type, enabled, interval_minutes, next_run_at, last_run_at,
     last_status, last_severity, last_summary, last_entry_id, created_at, data_json) = row
    data = json.loads(data_json)
    return {
        "id": row_id,
        "name": name,
        "device_type": device_type,
        "enabled": bool(enabled),
        "interval_minutes": interval_minutes,
        "next_run_at": next_run_at,
        "last_run_at": last_run_at,
        "last_status": last_status,
        "last_severity": last_severity,
        "last_summary": last_summary,
        "last_entry_id": last_entry_id,
        "created_at": _iso_utc(created_at) if "T" not in created_at else created_at,
        **data,
    }


def to_public(device: dict) -> dict:
    """API 응답/화면용 — 비밀번호(평문은 물론 암호문도)를 아예 제거하고, 등록
    여부만 `has_secret`으로 알려준다."""
    public = {k: v for k, v in device.items() if k not in ("secret_enc",)}
    public["has_secret"] = bool(device.get("secret_enc"))
    return public


def _extract_secret_and_data(payload: dict) -> tuple[str | None, dict]:
    """payload에서 저장 대상 필드만 골라 data 블롭으로 만들고, 비밀번호/개인키는 암호화한다.
    auth_method가 "private_key"면 password 필드에 담겨 온 PEM 텍스트를 그대로 암호화해
    secret_enc에 저장한다 — 저장 형태는 비밀번호와 동일(암호화된 문자열 하나)하고,
    device_collector가 auth_method를 보고 이 문자열을 비밀번호로 쓸지 개인키로 파싱할지
    결정한다(AWS EC2처럼 비밀번호 인증이 꺼져 있고 키 페어만 허용하는 대상을 지원하기 위함)."""
    data = {
        "vendor": payload.get("vendor") or None,
        "analyzer": payload.get("analyzer"),
        "host": (payload.get("host") or "").strip(),
        "port": payload.get("port"),
        "username": (payload.get("username") or "").strip(),
        "context": payload.get("context") or "",
        "auth_method": payload.get("auth_method") or "password",
    }
    password = payload.get("password")
    if password:
        data["secret_enc"] = crypto_util.encrypt(password)
    return password, data


def create_device(payload: dict) -> dict:
    _, data = _extract_secret_and_data(payload)
    interval_minutes = int(payload.get("interval_minutes") or 60)
    enabled = bool(payload.get("enabled", True))
    next_run = _now().isoformat() if enabled else None  # 등록 즉시 한 번은 곧 수집되도록 예약
    with _lock:
        cur = _conn.execute(
            "INSERT INTO devices (name, device_type, enabled, interval_minutes, next_run_at, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                payload["name"].strip(), payload["device_type"], int(enabled), interval_minutes,
                next_run, json.dumps(data, ensure_ascii=False),
            ),
        )
        _conn.commit()
        row_id = cur.lastrowid
    return get_device(row_id)


def list_devices() -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT id, name, device_type, enabled, interval_minutes, next_run_at, last_run_at, "
            "last_status, last_severity, last_summary, last_entry_id, created_at, data "
            "FROM devices ORDER BY id DESC"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_device(device_id: int) -> dict | None:
    with _lock:
        row = _conn.execute(
            "SELECT id, name, device_type, enabled, interval_minutes, next_run_at, last_run_at, "
            "last_status, last_severity, last_summary, last_entry_id, created_at, data "
            "FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_device_internal(device_id: int) -> dict | None:
    """수집기 전용 — 비밀번호를 복호화한 `password` 필드를 포함해 반환한다."""
    device = get_device(device_id)
    if device is None:
        return None
    secret_enc = device.get("secret_enc")
    device["password"] = crypto_util.decrypt(secret_enc) if secret_enc else ""
    return device


def update_device(device_id: int, payload: dict) -> dict | None:
    existing = get_device(device_id)
    if existing is None:
        return None
    merged = {**existing, **payload}
    # 비밀번호를 새로 보내지 않았으면(칸을 비워둔 채 저장) 기존 암호문을 유지한다.
    if not payload.get("password") and existing.get("secret_enc"):
        _, data = _extract_secret_and_data(merged)
        data["secret_enc"] = existing["secret_enc"]
    else:
        _, data = _extract_secret_and_data(merged)

    interval_minutes = int(merged.get("interval_minutes") or 60)
    enabled = bool(merged.get("enabled", True))
    next_run_at = existing.get("next_run_at")
    if enabled and not existing.get("enabled"):
        next_run_at = _now().isoformat()  # 꺼져 있다가 다시 켜지면 곧 수집되도록 재예약
    if not enabled:
        next_run_at = None

    with _lock:
        _conn.execute(
            "UPDATE devices SET name=?, device_type=?, enabled=?, interval_minutes=?, next_run_at=?, data=? "
            "WHERE id=?",
            (
                merged["name"].strip(), merged["device_type"], int(enabled), interval_minutes,
                next_run_at, json.dumps(data, ensure_ascii=False), device_id,
            ),
        )
        _conn.commit()
    return get_device(device_id)


def delete_device(device_id: int) -> None:
    with _lock:
        _conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        _conn.commit()


def list_due(now_iso: str) -> list[dict]:
    """enabled=1이고 next_run_at이 지금 이전인 장비 전체를 반환한다(스케줄러 전용)."""
    with _lock:
        rows = _conn.execute(
            "SELECT id FROM devices WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?",
            (now_iso,),
        ).fetchall()
    return [r[0] for r in rows]


def record_result(
    device_id: int, *, status: str, error: str | None, severity: str | None,
    summary: str | None, entry_id: int | None, interval_minutes: int,
) -> None:
    now = _now()
    next_run = (now + timedelta(minutes=max(1, interval_minutes))).isoformat()
    with _lock:
        _conn.execute(
            "UPDATE devices SET last_run_at=?, last_status=?, last_severity=?, last_summary=?, "
            "last_entry_id=?, next_run_at=? WHERE id=?",
            (now.isoformat(), status, severity, (summary or "")[:300], entry_id, next_run, device_id),
        )
        _conn.commit()


