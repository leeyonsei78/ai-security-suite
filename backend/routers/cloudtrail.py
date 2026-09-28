import json
import logging

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

import httpx

from services import aws_cloudtrail_service as ct_service
from services import sns_verify

logger = logging.getLogger(__name__)

# 연결 관리(등록/조회/삭제)는 우리 백엔드 조작자가 쓰는 API라 다른 앱들과 동일하게
# main.py에서 API_KEY 인증 dependency가 걸린다.
router = APIRouter(prefix="/api/cloudtrail", tags=["cloudtrail"])

# 웹훅은 AWS SNS가 직접 호출하는 엔드포인트라 우리 API_KEY 헤더를 보낼 수 없다 —
# 대신 SNS 메시지 서명 검증(sns_verify.verify)으로 보호한다. main.py에서 이
# 라우터에는 _authed dependency를 걸지 않는다.
webhook_router = APIRouter(prefix="/api/cloudtrail", tags=["cloudtrail-webhook"])


class CreateConnectionRequest(BaseModel):
    role_arn: str
    external_id: str = ""
    region: str = "us-east-1"
    topic_arn: str


@router.get("/connections")
async def list_connections():
    return {"connections": ct_service.list_connections()}


@router.post("/connections")
async def create_connection(request: CreateConnectionRequest):
    try:
        conn = ct_service.create_connection(
            request.role_arn, request.external_id, request.region, request.topic_arn
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # AssumeRole 실패(잘못된 ARN, ExternalId 불일치, 신뢰 정책 미설정 등)
        raise HTTPException(status_code=400, detail=f"IAM Role을 확인할 수 없습니다: {e}")
    return conn


@router.delete("/connections/{conn_id}")
async def delete_connection(conn_id: int):
    if not ct_service.get_connection(conn_id):
        raise HTTPException(status_code=404, detail="Connection not found")
    ct_service.delete_connection(conn_id)
    return {"message": "Deleted"}


@webhook_router.post("/webhook")
async def webhook(request: Request):
    try:
        message = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not sns_verify.verify(message):
        logger.warning("CloudTrail webhook: invalid SNS signature, rejected")
        raise HTTPException(status_code=403, detail="Invalid SNS signature")

    msg_type = message.get("Type")

    if msg_type in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
        # AWS가 요구하는 핸드셰이크 — 서명이 유효한 확인 요청이면 SubscribeURL을
        # 한 번 GET해서 구독을 실제로 활성화한다.
        subscribe_url = message.get("SubscribeURL")
        if subscribe_url:
            async with httpx.AsyncClient(timeout=8.0) as client:
                await client.get(subscribe_url)
        return Response(status_code=200)

    if msg_type == "Notification":
        topic_arn = message.get("TopicArn", "")
        conn = ct_service.get_connection_by_topic_arn(topic_arn)
        if not conn:
            # 서명은 유효하지만 우리가 등록해두지 않은 토픽 — 다른 테넌트의 토픽으로
            # 서명된 메시지를 재전송하는 것을 막기 위해 여기서 조용히 거부한다.
            logger.warning("CloudTrail webhook: unknown TopicArn %s", topic_arn)
            return Response(status_code=200)

        parsed = ct_service.parse_notification_message(message.get("Message", ""))
        if parsed:
            bucket, keys = parsed
            for key in keys:
                await ct_service.ingest_log_file(conn, bucket, key)
        return Response(status_code=200)

    return Response(status_code=200)
