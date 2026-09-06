import asyncio
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from services.forensics_lab import CHALLENGES, LAB_SETUP, FLAGS, get_challenge, get_artifact_bytes
from services.forensics_audit_service import analyze_artifact, generate_markdown_report, ARTIFACT_LABELS
from services.forensics_audit_guide import ARTIFACT_TYPES, DISCLAIMER, COMMAND_USAGE_NOTE
from services import forensics_collection_service as collection_svc
from services import db, notify

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

AUDIT_APP_NAME = "forensics_artifact_audit"
COLLECTION_APP_NAME = "forensics_collection"

VALID_ARTIFACT_TYPES = set(ARTIFACT_LABELS.keys())


# ── 실습 랩 ────────────────────────────────────────────────────────────

@router.get("/lab/challenges")
async def list_lab_challenges():
    return {"challenges": CHALLENGES, "lab_setup": LAB_SETUP}


@router.get("/lab/challenges/{challenge_id}/download")
async def download_lab_artifact(challenge_id: str):
    challenge = get_challenge(challenge_id)
    artifact = get_artifact_bytes(challenge_id)
    if not challenge or artifact is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return Response(
        content=artifact,
        media_type=challenge.get("media_type", "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{challenge["download_filename"]}"'},
    )


class LabVerifyRequest(BaseModel):
    challenge_id: str
    flag: str


@router.post("/lab/verify")
async def verify_lab_flag(request: LabVerifyRequest):
    expected = FLAGS.get(request.challenge_id)
    if expected is None:
        raise HTTPException(status_code=404, detail="Unknown challenge")
    return {"correct": request.flag.strip() == expected}


# ── 아티팩트 감사기 ─────────────────────────────────────────────────────

class AuditAnalyzeRequest(BaseModel):
    artifact_type: str = "event_log"
    content: str
    context: str = ""


@router.get("/audit/guide")
async def get_audit_guide():
    return {"artifact_types": ARTIFACT_TYPES, "disclaimer": DISCLAIMER, "command_usage_note": COMMAND_USAGE_NOTE}


@router.post("/audit/analyze")
async def analyze(request: AuditAnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 20000:
        raise HTTPException(status_code=400, detail="Content too long (max 20,000 chars)")
    if request.artifact_type not in VALID_ARTIFACT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid artifact_type, must be one of {sorted(VALID_ARTIFACT_TYPES)}")

    result = await analyze_artifact(request.artifact_type, request.content, request.context)
    entry = {
        "artifact_type": request.artifact_type,
        "preview": request.content.strip()[:100].replace("\n", " "),
        **result,
    }
    entry["id"] = db.add_entry(AUDIT_APP_NAME, entry)

    if entry.get("overall_severity") == "CRITICAL":
        top = next((f for f in entry.get("findings", []) if f.get("severity") == "CRITICAL"), None)
        summary = top["description"] if top else entry.get("summary", "")
        await notify.alert_if_critical(AUDIT_APP_NAME, True, "CRITICAL", summary, entry["id"])

    return entry


@router.get("/audit/history")
async def get_audit_history():
    history = db.get_history(AUDIT_APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/audit/history")
async def clear_audit_history():
    db.clear_history(AUDIT_APP_NAME)
    return {"message": "Cleared"}


@router.get("/audit/report/{entry_id}", response_class=PlainTextResponse)
async def get_audit_report(entry_id: int):
    entry = db.get_entry(AUDIT_APP_NAME, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return generate_markdown_report(entry)


# ── 증거 수집 도구 ──────────────────────────────────────────────────────

@router.get("/collection/items")
async def list_collection_items():
    # PowerShell 스크립트 원문은 내부 구현이라 목록 응답에는 표시용 command만 노출한다.
    return {
        "items": [
            {k: v for k, v in item.items() if k != "script"}
            for item in collection_svc.COLLECTIBLE_ITEMS
        ]
    }


class CollectRequest(BaseModel):
    item_id: str
    collected_by: str = ""


@router.post("/collection/collect")
async def collect(request: CollectRequest):
    if request.item_id not in {i["id"] for i in collection_svc.COLLECTIBLE_ITEMS}:
        raise HTTPException(status_code=404, detail="Unknown item_id")

    loop = asyncio.get_event_loop()
    try:
        record = await loop.run_in_executor(None, collection_svc.collect_item, request.item_id, request.collected_by)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    record["id"] = db.add_entry(COLLECTION_APP_NAME, record)
    return record


@router.get("/collection/history")
async def get_collection_history():
    history = db.get_history(COLLECTION_APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/collection/history")
async def clear_collection_history():
    db.clear_history(COLLECTION_APP_NAME)
    return {"message": "Cleared"}


@router.get("/collection/custody-report", response_class=PlainTextResponse)
async def get_custody_report():
    records = db.get_history(COLLECTION_APP_NAME)
    if not records:
        raise HTTPException(status_code=404, detail="No custody records yet")
    return collection_svc.generate_custody_report(records)


# ── 원격 SSH 수집 (Linux/macOS/네트워크 장비) ──────────────────────────────

@router.get("/collection/remote-options")
async def get_remote_options():
    return {
        "platforms": [
            {
                "platform": platform,
                "platform_label": d["platform_label"],
                "is_network_device": platform in collection_svc.NETWORK_DEVICE_PLATFORMS,
                "artifact_types": [{"artifact_type": a["artifact_type"], "label": a["label"], "commands": a["commands"]} for a in d["artifact_types"]],
            }
            for platform, d in collection_svc.SSH_COLLECTIBLE.items()
        ]
    }


class SshTargetRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str


@router.post("/collection/check-ssh")
async def check_ssh(request: SshTargetRequest):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, collection_svc.check_ssh_connection, request.host, request.port, request.username, request.password)


class CollectRemoteRequest(SshTargetRequest):
    platform: str
    artifact_type: str
    collected_by: str = ""


@router.post("/collection/collect-remote")
async def collect_remote(request: CollectRemoteRequest):
    loop = asyncio.get_event_loop()
    try:
        record = await loop.run_in_executor(
            None, collection_svc.collect_remote,
            request.platform, request.artifact_type, request.host, request.port, request.username, request.password, request.collected_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    record["id"] = db.add_entry(COLLECTION_APP_NAME, record)
    return record


# ── 클라우드 CLI 수집 (AWS/Azure/GCP) ──────────────────────────────────────

@router.get("/collection/cloud-options")
async def get_cloud_options():
    return {
        "providers": [
            {"provider": p, "platform_label": d["platform_label"]}
            for p, d in collection_svc.CLOUD_CLI_TARGETS.items()
        ]
    }


class CheckCloudRequest(BaseModel):
    provider: str


@router.post("/collection/check-cloud")
async def check_cloud(request: CheckCloudRequest):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, collection_svc.check_cloud_cli, request.provider)


class CollectCloudRequest(BaseModel):
    provider: str
    collected_by: str = ""


@router.post("/collection/collect-cloud")
async def collect_cloud(request: CollectCloudRequest):
    loop = asyncio.get_event_loop()
    try:
        record = await loop.run_in_executor(None, collection_svc.collect_cloud, request.provider, request.collected_by)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    record["id"] = db.add_entry(COLLECTION_APP_NAME, record)
    return record
