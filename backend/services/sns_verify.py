"""AWS SNS가 우리 웹훅(`/api/cloudtrail/webhook`)으로 보내는 메시지의 서명을 검증한다.

CloudTrail 연동(App 17)은 고객사 S3의 CloudTrail 로그가 새로 생길 때마다 SNS가
우리 엔드포인트를 HTTPS로 호출하는 구조다. 이 엔드포인트는 인터넷에 그대로
노출되므로(AWS가 호출하는 거라 우리 자체 `API_KEY` 헤더 인증을 못 씀), 대신
AWS가 각 메시지에 실어 보내는 전자서명을 검증해 "진짜 SNS가 보낸 메시지"인지
확인한다 — AWS가 공식적으로 권장하는 방식.
https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html

서명 검증만으로는 "어떤 SNS 토픽이든 서명이 유효하면 통과"하게 되므로, 호출부에서
메시지의 TopicArn이 우리가 등록해둔 연결의 TopicArn과 일치하는지 추가로 확인해야
한다(다른 사람이 자기 토픽으로 진짜 서명된 메시지를 만들어 우리에게 재전송하는
것을 막기 위함) — 이건 이 모듈이 아니라 라우터에서 처리.
"""

import base64
import re
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

# 진짜 AWS SNS가 발급하는 서명 인증서만 허용 (가짜 SigningCertURL로 검증을 우회하는 것 방지)
_CERT_URL_RE = re.compile(
    r"^https://sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?/SimpleNotificationService-[a-zA-Z0-9]+\.pem$"
)

# 인증서는 자주 안 바뀌니 프로세스 생명주기 동안만 캐싱(재요청마다 매번 받아오지 않음)
_cert_cache: dict[str, Any] = {}


def _string_to_sign(message: dict) -> bytes:
    msg_type = message.get("Type")
    if msg_type == "Notification":
        fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
    else:  # SubscriptionConfirmation / UnsubscribeConfirmation
        fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

    parts = []
    for field in fields:
        if field == "Subject" and "Subject" not in message:
            continue  # Subject는 있을 때만 서명에 포함됨
        parts.append(f"{field}\n{message[field]}\n")
    return "".join(parts).encode("utf-8")


def _get_public_key(cert_url: str):
    if cert_url in _cert_cache:
        return _cert_cache[cert_url]
    resp = httpx.get(cert_url, timeout=8.0)
    resp.raise_for_status()
    cert = load_pem_x509_certificate(resp.content)
    public_key = cert.public_key()
    _cert_cache[cert_url] = public_key
    return public_key


def verify(message: dict) -> bool:
    """메시지가 진짜 AWS SNS 서명이 유효하면 True. 인증서 URL이 AWS 도메인이
    아니거나, 서명이 안 맞거나, 필수 필드가 없으면 False (예외를 던지지 않고
    항상 bool로 반환 — 호출부는 이 결과만 보고 403을 내리면 됨)."""
    try:
        cert_url = message.get("SigningCertURL", "")
        if not _CERT_URL_RE.match(cert_url):
            return False

        signature = base64.b64decode(message["Signature"])
        to_sign = _string_to_sign(message)
        public_key = _get_public_key(cert_url)

        sig_version = message.get("SignatureVersion", "1")
        chosen_hash = hashes.SHA256() if sig_version == "2" else hashes.SHA1()

        public_key.verify(signature, to_sign, padding.PKCS1v15(), chosen_hash)
        return True
    except (InvalidSignature, KeyError, ValueError, httpx.HTTPError):
        return False
