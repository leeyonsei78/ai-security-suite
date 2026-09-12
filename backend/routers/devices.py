"""장비 등록/자동 점검 관리 — 방화벽·스위치·서버·클라우드 계정을 등록해두면 설정한
주기마다 자동으로 접속해 정보를 수집·분석하고, 문제(CRITICAL)가 발견되면 기존
알림 시스템(Slack/이메일/n8n)으로 통보한다. SIEM 장비가 방화벽/스위치 API를 직접
호출해 수집하는 것과 같은 동작을 이 프로젝트의 기존 감사 엔진(App 16/18)·수집기
(App 23/25)로 구현했다.
"""

import asyncio

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, ValidationError

from services import db, device_bulk_import, device_collector, device_scheduler, device_store

router = APIRouter(prefix="/api/devices", tags=["devices"])

APP_NAME = device_scheduler.APP_NAME

INTERVAL_PRESETS = [
    {"minutes": 15, "label": "15분"},
    {"minutes": 60, "label": "1시간"},
    {"minutes": 360, "label": "6시간"},
    {"minutes": 1440, "label": "24시간"},
]

DEVICE_TYPE_LABELS = {
    "network_device": "네트워크 장비 (방화벽/라우터/스위치)",
    "linux_host": "Linux 서버",
    "windows_host": "Windows 서버/PC",
    "aws_account": "AWS 계정",
    "azure_subscription": "Azure 구독",
    "gcp_project": "GCP 프로젝트",
}
VENDOR_LABELS = {
    "cisco_ios": "Cisco IOS",
    "fortinet": "Fortinet FortiGate",
    "palo_alto": "Palo Alto Networks (PAN-OS)",
    "juniper": "Juniper (Junos)",
}
ANALYZER_LABELS = {
    "firewall_audit": "방화벽/네트워크 정책 감사",
    "iam_audit": "IAM 권한 감사",
    "log_analysis": "보안 로그/신호 분석",
}

_HOST_HINTS = {
    "network_device": "SSH로 접속할 장비 IP 또는 호스트명",
    "linux_host": "SSH로 접속할 서버 IP 또는 호스트명",
    "windows_host": "WinRM으로 접속할 서버 IP/호스트명 (비워두면 이 백엔드가 실행 중인 이 PC를 대상으로 함)",
    "aws_account": "AWS CLI 프로파일 이름 (선택, 비워두면 기본 프로파일)",
    "azure_subscription": "Azure 구독 ID/이름 (선택, 비워두면 현재 로그인된 기본 구독)",
    "gcp_project": "GCP 프로젝트 ID (필수)",
}


class DevicePayload(BaseModel):
    name: str
    device_type: str
    vendor: str | None = None
    analyzer: str
    host: str = ""
    port: int | None = None
    username: str = ""
    password: str | None = None  # 비워두면(수정 시) 기존 값 유지, 신규 등록 시 필요한 유형은 필수
    auth_method: str = "password"  # "password" | "private_key" — private_key면 password 필드에 PEM 텍스트를 담아 보낸다
    context: str = ""
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    enabled: bool = True


def _validation_error(payload: DevicePayload, *, is_update: bool, existing_has_secret: bool = False) -> str | None:
    """검증 실패 사유를 문자열로 돌려준다(문제 없으면 None) — 단건 등록/수정은 이를 그대로
    HTTPException으로 던지고, 일괄 업로드(bulk import)는 행별 오류 목록에 모아 담는다."""
    if not payload.name.strip():
        return "장비 이름을 입력하세요."
    if payload.device_type not in device_store.ANALYZERS_BY_DEVICE_TYPE:
        return f"알 수 없는 장비 유형입니다: {payload.device_type}"
    allowed_analyzers = device_store.ANALYZERS_BY_DEVICE_TYPE[payload.device_type]
    if payload.analyzer not in allowed_analyzers:
        return f"이 장비 유형에는 다음 분석기만 선택할 수 있습니다: {allowed_analyzers}"

    if payload.device_type in ("network_device", "linux_host") and payload.auth_method not in ("password", "private_key"):
        return "인증 방식은 password 또는 private_key여야 합니다."

    if payload.device_type == "network_device":
        if payload.vendor not in device_store.NETWORK_VENDORS:
            return f"네트워크 장비는 vendor가 다음 중 하나여야 합니다: {device_store.NETWORK_VENDORS}"
        if not payload.host.strip():
            return "접속할 호스트/IP를 입력하세요."
        if not payload.username.strip():
            return "SSH 사용자명을 입력하세요."
        if not payload.password and not (is_update and existing_has_secret):
            return "SSH 비밀번호(또는 개인키)를 입력하세요."

    elif payload.device_type == "linux_host":
        if not payload.host.strip():
            return "접속할 호스트/IP를 입력하세요."
        if not payload.username.strip():
            return "SSH 사용자명을 입력하세요."
        if not payload.password and not (is_update and existing_has_secret):
            return "SSH 비밀번호(또는 개인키)를 입력하세요."

    elif payload.device_type == "windows_host":
        host = payload.host.strip()
        is_remote = bool(host) and host not in ("localhost", "127.0.0.1")
        if is_remote:
            if not payload.username.strip():
                return "원격 Windows 접속에는 사용자명이 필요합니다."
            if not payload.password and not (is_update and existing_has_secret):
                return "원격 Windows 접속에는 비밀번호가 필요합니다."

    elif payload.device_type == "gcp_project" and not payload.host.strip():
        return "GCP는 프로젝트 ID를 host 필드에 입력해야 합니다."

    return None


def _validate(payload: DevicePayload, *, is_update: bool, existing_has_secret: bool = False) -> None:
    error = _validation_error(payload, is_update=is_update, existing_has_secret=existing_has_secret)
    if error:
        raise HTTPException(status_code=400, detail=error)


@router.get("/meta")
async def get_meta():
    """등록/수정 화면을 그리는 데 필요한 정적 메타데이터."""
    return {
        "device_types": [{"id": k, "label": v, "analyzers": device_store.ANALYZERS_BY_DEVICE_TYPE[k], "host_hint": _HOST_HINTS[k]} for k, v in DEVICE_TYPE_LABELS.items()],
        "vendors": [{"id": k, "label": v} for k, v in VENDOR_LABELS.items()],
        "analyzers": [{"id": k, "label": v} for k, v in ANALYZER_LABELS.items()],
        "interval_presets": INTERVAL_PRESETS,
    }


@router.get("")
async def list_devices():
    devices = [device_store.to_public(d) for d in device_store.list_devices()]
    return {"devices": devices, "total": len(devices)}


@router.post("")
async def create_device(payload: DevicePayload):
    _validate(payload, is_update=False)
    device = device_store.create_device(payload.model_dump())
    return device_store.to_public(device)


@router.post("/bulk-upload")
async def bulk_upload_devices(file: UploadFile = File(...)):
    """CSV/Excel 파일 한 개로 여러 장비를 한 번에 등록한다 — 개별 등록과 같은 검증을
    행 단위로 적용해, 일부 행이 잘못돼도 나머지 행은 계속 등록된다. 업로드한 파일
    내용(비밀번호 포함 가능)은 파싱에만 쓰이고 저장되지 않는다."""
    raw = await file.read()
    try:
        rows = device_bulk_import.parse_rows(file.filename or "", raw)
    except device_bulk_import.ParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not rows:
        raise HTTPException(status_code=400, detail="파일에서 등록할 행을 찾지 못했습니다 — 헤더 행과 데이터 행이 있는지 확인하세요.")
    if len(rows) > 200:
        raise HTTPException(status_code=400, detail=f"한 번에 최대 200개 행까지 업로드할 수 있습니다 (현재 {len(rows)}행).")

    created = []
    errors = []
    for i, raw_row in enumerate(rows, start=2):  # 1행은 헤더이므로 데이터는 2행부터
        row_name = raw_row.get("name") or f"{i}번째 행"
        try:
            normalized = device_bulk_import.normalize_row(raw_row)
            payload = DevicePayload(**normalized)
        except device_bulk_import.ParseError as e:
            errors.append({"row": i, "name": row_name, "message": str(e)})
            continue
        except ValidationError as e:
            errors.append({"row": i, "name": row_name, "message": e.errors()[0]["msg"]})
            continue

        error = _validation_error(payload, is_update=False)
        if error:
            errors.append({"row": i, "name": row_name, "message": error})
            continue

        device = device_store.create_device(payload.model_dump())
        created.append(device_store.to_public(device))

    return {"created": created, "created_count": len(created), "errors": errors, "error_count": len(errors), "total_rows": len(rows)}


@router.get("/{device_id}")
async def get_device(device_id: int):
    device = device_store.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device_store.to_public(device)


@router.put("/{device_id}")
async def update_device(device_id: int, payload: DevicePayload):
    existing = device_store.get_device(device_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Device not found")
    _validate(payload, is_update=True, existing_has_secret=bool(existing.get("secret_enc")))
    updated = device_store.update_device(device_id, payload.model_dump())
    return device_store.to_public(updated)


@router.delete("/{device_id}")
async def delete_device(device_id: int):
    if device_store.get_device(device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    device_store.delete_device(device_id)
    return {"message": "Deleted"}


@router.post("/test-connection")
async def test_connection_precheck(payload: DevicePayload):
    """저장 전 [연결 테스트] — 화면에 입력된 값 그대로(암호화하지 않은 상태) 접속만 확인한다."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, device_collector.check_connection, payload.model_dump())
    return result


@router.post("/{device_id}/test-connection")
async def test_connection_saved(device_id: int):
    device = device_store.get_device_internal(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, device_collector.check_connection, device)
    return result


@router.post("/{device_id}/collect-now")
async def collect_now(device_id: int):
    if device_store.get_device(device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    result = await device_scheduler.run_device_scan(device_id)
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error") or "수집에 실패했습니다.")
    return result["entry"]


@router.get("/{device_id}/history")
async def get_device_history(device_id: int):
    if device_store.get_device(device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    all_entries = db.get_history(APP_NAME)
    entries = [e for e in all_entries if e.get("device_id") == device_id]
    return {"history": list(reversed(entries)), "total": len(entries)}


@router.get("/{device_id}/history/{entry_id}")
async def get_device_history_entry(device_id: int, entry_id: int):
    entry = db.get_entry(APP_NAME, entry_id)
    if entry is None or entry.get("device_id") != device_id:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry
