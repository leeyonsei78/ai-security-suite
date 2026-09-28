import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from services import log_ingest_service as ingest_service

# 소스 관리(발급/조회/삭제)는 우리 운영자용 API라 다른 앱들과 동일하게 main.py에서
# API_KEY 인증 dependency가 걸린다.
router = APIRouter(prefix="/api/log-sources", tags=["log-sources"])

# 실제 로그 수집 엔드포인트는 고객사 rsyslog/syslog-ng가 직접 호출하므로 API_KEY를
# 못 씀 — 대신 소스별로 발급된 X-Ingest-Key 헤더로 인증한다. main.py에서 이
# 라우터에는 _authed dependency를 걸지 않는다.
ingest_router = APIRouter(prefix="/api/logs", tags=["log-ingest"])


class CreateSourceRequest(BaseModel):
    label: str


@router.get("")
async def list_sources():
    return {"sources": ingest_service.list_sources()}


@router.post("")
async def create_source(request: CreateSourceRequest):
    try:
        return ingest_service.create_source(request.label)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{source_id}")
async def delete_source(source_id: int):
    if not ingest_service.get_source(source_id):
        raise HTTPException(status_code=404, detail="Source not found")
    ingest_service.delete_source(source_id)
    return {"message": "Deleted"}


@ingest_router.post("/ingest")
async def ingest(request: Request):
    source = ingest_service.get_source_by_key(request.headers.get("X-Ingest-Key", ""))
    if not source:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Ingest-Key")

    body = await request.body()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = None

    if isinstance(data, list):
        lines = [ingest_service.line_from_entry(e) for e in data]
    elif isinstance(data, dict):
        lines = [ingest_service.line_from_entry(data)]
    else:
        # JSON이 아니면 단순 텍스트 클라이언트(예: 셸 스크립트의 curl -d)도 지원하도록
        # 원문을 줄 단위 텍스트로 취급
        text = body.decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line.strip()]

    if not lines:
        raise HTTPException(status_code=400, detail="No log lines found in request body")

    await ingest_service.ingest(source, lines)
    return {"message": "Accepted", "lines": len(lines)}
