"""AWS CloudTrail 연동(App 17) — 고객사 AWS 계정의 CloudTrail 감사 로그를
S3+SNS 웹훅 방식으로 실시간에 가깝게 받아 App 1(대시보드) 분석 파이프라인에
흘려보낸다.

인증 모델은 AWS의 표준 "Cross-Account Role" 패턴을 그대로 쓴다 — 고객사가
자기 AWS 계정에 IAM Role을 만들어 우리 AWS 계정이 맡을(AssumeRole) 수 있게
신뢰 정책을 걸고, 우리는 그 Role로 딱 필요한 권한(S3 읽기)만 임시로 빌려 쓴다.
장기 액세스 키를 저장/전달하지 않는다 — Role ARN과 ExternalId만 우리 DB에
남는다. 우리 쪽 백엔드 자체는 boto3의 표준 자격증명 체인(환경변수 등)으로
"우리 회사 AWS 계정"으로 인증되어 있어야 sts:AssumeRole을 호출할 수 있다
(docs/cloudtrail-integration.md 참고).
"""

import asyncio
import gzip
import json
from datetime import datetime, timezone

import boto3

from services import db, notify
from services.claude_service import analyze_logs

APP_NAME = "cloudtrail_connections"
MAX_RECORDS_PER_FILE = 100  # 프롬프트 비용/크기를 보호하기 위한 상한


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_connection(role_arn: str, external_id: str, region: str, topic_arn: str) -> dict:
    if not role_arn.strip() or not topic_arn.strip():
        raise ValueError("role_arn과 topic_arn은 필수입니다")

    # 저장 전에 실제로 AssumeRole이 되는지 검증 — 잘못된 ARN/ExternalId를 나중에야
    # 웹훅이 실패하는 방식으로 알게 되는 것을 방지
    assume_role(role_arn, external_id, region)

    conn = {
        "role_arn": role_arn.strip(),
        "external_id": external_id.strip(),
        "region": region.strip() or "us-east-1",
        "topic_arn": topic_arn.strip(),
        "enabled": True,
        "created_at": _now(),
        "last_event_at": None,
        "last_error": None,
        "events_ingested": 0,
    }
    conn["id"] = db.add_entry(APP_NAME, conn)
    return conn


def list_connections() -> list[dict]:
    return db.get_history(APP_NAME)


def get_connection(conn_id: int) -> dict | None:
    return db.get_entry(APP_NAME, conn_id)


def get_connection_by_topic_arn(topic_arn: str) -> dict | None:
    for conn in list_connections():
        if conn.get("topic_arn") == topic_arn and conn.get("enabled", True):
            return conn
    return None


def delete_connection(conn_id: int) -> None:
    db.delete_entry(APP_NAME, conn_id)


def assume_role(role_arn: str, external_id: str, region: str):
    """boto3 STS로 고객사 Role을 잠깐 빌려쓸 임시 자격증명을 발급받는다.
    실패(잘못된 ARN, ExternalId 불일치, 신뢰 정책 미설정 등)하면 그대로 예외가 올라간다."""
    sts = boto3.client("sts", region_name=region or "us-east-1")
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "ai-security-suite-cloudtrail"}
    if external_id:
        kwargs["ExternalId"] = external_id
    resp = sts.assume_role(**kwargs)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or "us-east-1",
    )


def _cloudtrail_record_to_line(record: dict) -> str:
    identity = record.get("userIdentity", {}) or {}
    who = identity.get("arn") or identity.get("userName") or identity.get("type", "Unknown")
    err = f" ERROR={record.get('errorCode')}" if record.get("errorCode") else ""
    return (
        f"{record.get('eventTime')} region={record.get('awsRegion')} "
        f"{record.get('eventSource')} {record.get('eventName')} "
        f"by={who} sourceIP={record.get('sourceIPAddress')}{err}"
    )


def parse_notification_message(message_body: str) -> tuple[str, list[str]] | None:
    """CloudTrail이 SNS 알림을 켜면(`aws cloudtrail update-trail --sns-topic-name ...`)
    보내는 Message 본문 형식: {"s3Bucket": "...", "s3ObjectKey": ["key1", "key2", ...]}
    (파일 하나가 아니라 여러 개를 한 번에 묶어 알려줄 수 있음)."""
    try:
        data = json.loads(message_body)
        bucket = data.get("s3Bucket")
        keys = data.get("s3ObjectKey")
        if bucket and keys:
            return bucket, keys
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


def parse_cloudtrail_file(raw_bytes: bytes) -> list[dict]:
    """S3에서 받은 CloudTrail 로그 파일(.json.gz)을 압축 해제해 Records 목록을 반환."""
    try:
        raw = gzip.decompress(raw_bytes)
    except OSError:
        raw = raw_bytes  # 이미 압축 해제된 상태로 오는 경우 대비
    data = json.loads(raw)
    return data.get("Records", [])


async def ingest_log_file(conn: dict, bucket: str, key: str) -> None:
    """S3의 CloudTrail 로그 파일 하나를 가져와 분석 파이프라인에 넣고 히스토리/알림까지 처리."""
    try:
        session = assume_role(conn["role_arn"], conn.get("external_id", ""), conn.get("region", ""))
        s3 = session.client("s3")
        obj = s3.get_object(Bucket=bucket, Key=key)
        records = parse_cloudtrail_file(obj["Body"].read())
    except Exception as e:
        db.update_entry(APP_NAME, conn["id"], {**conn, "last_error": str(e)})
        return

    if not records:
        return

    lines = [_cloudtrail_record_to_line(r) for r in records[:MAX_RECORDS_PER_FILE]]
    log_content = "\n".join(lines)

    loop = asyncio.get_event_loop()
    # analyze_logs()는 Live 모드에서 Anthropic SDK를 동기 호출한다 — App 1 실시간
    # 모니터링에서 이미 겪은 함정과 같은 유형이라 스레드로 오프로드(run_in_executor)
    result = await loop.run_in_executor(None, analyze_logs, log_content)
    result["filename"] = f"cloudtrail:{bucket}/{key}"
    result["raw_log"] = log_content
    result["id"] = db.add_entry("dashboard", result)

    await notify.alert_if_critical(
        "dashboard", result.get("threat_level") == "CRITICAL", "CRITICAL",
        f"[CloudTrail] {result.get('summary', '')}", result["id"],
    )

    db.update_entry(APP_NAME, conn["id"], {
        **conn, "last_error": None, "last_event_at": _now(),
        "events_ingested": conn.get("events_ingested", 0) + len(records),
    })
