"""IoC 분석기(App 4)의 오프라인(폐쇄망) 모드.

IoC 판정(악성/정상 여부)은 본질적으로 위협 인텔리전스 데이터베이스(VirusTotal, AbuseIPDB,
각종 피드) 대조가 필요한 작업이라, 네트워크 연결 없이는 "이 IP/해시가 실제로 악성인지"를
확정적으로 판정할 수 없다 — 이 한계를 감추지 않고 정직하게 UNKNOWN으로 보고하는 것이
핵심 설계 원칙이다(App 3/2 오프라인 엔진처럼 그럴듯한 가짜 판정을 지어내지 않음).

대신 로컬에서 구조적으로 판단 가능한 것만 실제로 분석한다:
  - IP: RFC1918 사설 대역/루프백/링크로컬 여부 (공인 IP는 판정 불가를 명시)
  - 도메인/이메일: 알려진 브랜드 타이포스쿼팅 패턴 + 남용이 흔한 무료 TLD
  - 해시: MD5/SHA1/SHA256 포맷 유효성만 확인 (평판은 온라인에서만 가능)
"""
import re

ENGINE_DISCLAIMER = (
    "IoC의 악성 여부 판정은 본질적으로 위협 인텔리전스 데이터베이스(VirusTotal, AbuseIPDB 등) "
    "대조가 필요한 작업이라, 오프라인(폐쇄망) 상태에서는 이 로컬 규칙 엔진이 구조적으로 확인 "
    "가능한 것(사설 IP 여부, 타이포스쿼팅 패턴, 해시 포맷 유효성)만 판정하고 나머지는 "
    "정직하게 UNKNOWN으로 표시합니다. 확정적 판정이 필요하면 인터넷이 되는 환경에서 AI 모드로 "
    "재조회하거나 전용 위협 인텔리전스 서비스를 이용하세요."
)

_PRIVATE_IP_RE = re.compile(
    r"^(10\.|127\.|192\.168\.|169\.254\.|0\.0\.0\.0$|172\.(1[6-9]|2\d|3[01])\.)"
)
_BRAND_TYPOSQUAT_RE = re.compile(
    r"(paypa1|payp4l|g00gle|micr0soft|amaz0n|netfl1x|app1e|coup4ng|k4kao|nid-naver|"
    r"nonghyub|kb-st4r|shinh4n|-secure-|-verify-|verify-now|secure-login)",
    re.I,
)
_ABUSE_PRONE_TLD_RE = re.compile(r"\.(tk|ml|ga|cf|gq|top|xyz|work|click)$", re.I)
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _analyze_ip(value: str) -> dict:
    if _PRIVATE_IP_RE.match(value):
        return {
            "verdict": "CLEAN", "confidence": 90, "category": "사설/예약 IP 대역",
            "description": "RFC1918 사설 대역, 루프백, 또는 링크로컬 대역에 속하는 IP입니다. "
                           "이런 주소는 인터넷상의 외부 위협 지표가 될 수 없습니다.",
            "tags": ["Private", "RFC1918"],
            "recommendation": "내부망 IP이므로 외부 위협 인텔리전스 조회 대상이 아닙니다. 내부 정책 위반 여부만 확인하세요.",
        }
    return {
        "verdict": "UNKNOWN", "confidence": 0, "category": "판정 불가 (공인 IP)",
        "description": "공인 IP 주소입니다. 실제 악성 여부는 위협 인텔리전스 데이터베이스 대조가 필요하며, "
                       "오프라인 상태에서는 로컬 규칙만으로 판정할 수 없습니다.",
        "tags": ["Public IP", "Offline-Unverifiable"],
        "recommendation": "인터넷이 되는 환경에서 AI 모드로 재조회하거나 AbuseIPDB/VirusTotal 등에서 직접 확인하세요.",
    }


def _analyze_domain(value: str) -> dict:
    reasons = []
    if _BRAND_TYPOSQUAT_RE.search(value):
        reasons.append("잘 알려진 브랜드를 사칭한 것으로 보이는 타이포스쿼팅 패턴")
    if _ABUSE_PRONE_TLD_RE.search(value):
        reasons.append("남용 사례가 흔한 무료/저비용 TLD")
    if reasons:
        return {
            "verdict": "SUSPICIOUS", "confidence": 55, "category": "타이포스쿼팅/고위험 TLD 의심",
            "description": f"{', '.join(reasons)}이(가) 감지되었습니다. 확정적 악성 판정은 아니지만 주의가 필요합니다.",
            "tags": ["Typosquatting-Pattern", "Offline-Heuristic"],
            "recommendation": "해당 도메인으로의 접속·통신을 모니터링하고, 가능하면 온라인 상태에서 재조회로 확정하세요.",
        }
    return {
        "verdict": "UNKNOWN", "confidence": 0, "category": "판정 불가",
        "description": "로컬 규칙(타이포스쿼팅 패턴, 고위험 TLD)에 해당하지 않습니다. 다만 이는 안전을 "
                       "의미하지 않으며, 신규 등록 여부·WHOIS·평판은 오프라인에서 확인할 수 없습니다.",
        "tags": ["Offline-Unverifiable"],
        "recommendation": "인터넷이 되는 환경에서 AI 모드로 재조회하거나 WHOIS/평판 조회 서비스를 이용하세요.",
    }


def _analyze_hash(value: str) -> dict:
    if _MD5_RE.match(value):
        fmt = "MD5(32자리)"
    elif _SHA1_RE.match(value):
        fmt = "SHA1(40자리)"
    elif _SHA256_RE.match(value):
        fmt = "SHA256(64자리)"
    else:
        return {
            "verdict": "UNKNOWN", "confidence": 0, "category": "형식 오류",
            "description": "알려진 해시 형식(MD5/SHA1/SHA256)과 일치하지 않습니다.",
            "tags": ["Invalid-Format"],
            "recommendation": "올바른 해시 값인지 다시 확인하세요.",
        }
    return {
        "verdict": "UNKNOWN", "confidence": 0, "category": f"{fmt} 형식 확인됨",
        "description": f"유효한 {fmt} 해시 형식입니다. 다만 파일 평판(악성코드 여부)은 "
                       "바이러스 백신 엔진/샌드박스 데이터베이스 대조가 필요해 오프라인에서는 판정할 수 없습니다.",
        "tags": ["Offline-Unverifiable", fmt.split("(")[0]],
        "recommendation": "인터넷이 되는 환경에서 AI 모드로 재조회하거나 VirusTotal 등에서 직접 조회하세요.",
    }


def _analyze_email(value: str) -> dict:
    domain = value.split("@")[-1] if "@" in value else ""
    domain_result = _analyze_domain(domain) if domain else None
    if domain_result and domain_result["verdict"] == "SUSPICIOUS":
        return {
            "verdict": "SUSPICIOUS", "confidence": 50, "category": "의심스러운 발신 도메인",
            "description": f"발신 도메인({domain})에서 {domain_result['category']}이(가) 감지되었습니다.",
            "tags": ["Suspicious-Sender-Domain"],
            "recommendation": "발신자를 별도 채널로 확인하고, 이 주소로부터의 요청은 신중히 처리하세요.",
        }
    return {
        "verdict": "UNKNOWN", "confidence": 0, "category": "판정 불가",
        "description": "발신 도메인에서 로컬 규칙에 해당하는 의심 패턴이 발견되지 않았습니다. "
                       "메일 발신자 평판은 오프라인에서 확정할 수 없습니다.",
        "tags": ["Offline-Unverifiable"],
        "recommendation": "인터넷이 되는 환경에서 AI 모드로 재조회하세요.",
    }


def analyze_offline_single(value: str, ioc_type: str) -> dict:
    if ioc_type == "ip":
        result = _analyze_ip(value)
    elif ioc_type == "domain":
        result = _analyze_domain(value)
    elif ioc_type == "hash":
        result = _analyze_hash(value)
    elif ioc_type == "email":
        result = _analyze_email(value)
    else:
        result = {
            "verdict": "UNKNOWN", "confidence": 0, "category": "분류 불가",
            "description": "IoC 유형을 자동으로 인식할 수 없습니다. IP 주소, 도메인, 파일 해시(MD5/SHA256), 이메일 형식으로 입력해 주세요.",
            "tags": [], "recommendation": "올바른 형식으로 다시 입력해 주세요.",
        }
    return {"ioc": value, "ioc_type": ioc_type, "engine_note": ENGINE_DISCLAIMER, **result}


def analyze_offline(lines: list[str], detect_type_fn) -> list[dict]:
    return [analyze_offline_single(line, detect_type_fn(line)) for line in lines]
