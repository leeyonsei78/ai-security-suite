import re

# IoC type detection patterns
_IP_RE     = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_HASH_RE   = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
_EMAIL_RE  = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
_URL_RE    = re.compile(r'^https?://')

_IP_SAMPLES = [
    {
        "verdict": "MALICIOUS",
        "confidence": 95,
        "category": "C2 서버",
        "description": "알려진 APT 그룹(Lazarus)의 Command & Control 서버로 보고된 IP입니다. 여러 위협 인텔리전스 피드에서 악성으로 분류됩니다.",
        "tags": ["APT", "C2", "Lazarus"],
        "recommendation": "즉시 방화벽에서 차단하고, 해당 IP와 통신한 내부 시스템을 격리하여 침해 여부를 조사하세요.",
    },
    {
        "verdict": "SUSPICIOUS",
        "confidence": 65,
        "category": "Proxy/VPN",
        "description": "Tor 출구 노드 또는 익명화 프록시로 사용되는 IP입니다. 악의적인 활동에 자주 사용됩니다.",
        "tags": ["Tor", "Proxy", "Anonymizer"],
        "recommendation": "해당 IP의 접근 로그를 검토하고 비정상적인 패턴이 있으면 차단을 고려하세요.",
    },
    {
        "verdict": "CLEAN",
        "confidence": 90,
        "category": "정상 IP",
        "description": "알려진 악성 IP 목록에 없습니다. 주요 CDN(Google, Cloudflare) IP 범위와 일치합니다.",
        "tags": ["CDN", "Legitimate"],
        "recommendation": "현재 위협 지표 없음. 정기적인 모니터링을 유지하세요.",
    },
    {
        "verdict": "MALICIOUS",
        "confidence": 88,
        "category": "봇넷 노드",
        "description": "Emotet 봇넷의 감염 노드로 보고된 IP입니다. 스팸 발송 및 추가 악성코드 다운로드에 사용됩니다.",
        "tags": ["Botnet", "Emotet", "Spam"],
        "recommendation": "방화벽에서 즉시 차단하고 해당 IP 대역 전체에 대한 트래픽을 모니터링하세요.",
    },
]

_DOMAIN_SAMPLES = [
    {
        "verdict": "MALICIOUS",
        "confidence": 98,
        "category": "피싱 도메인",
        "description": "유명 금융기관을 사칭한 도메인입니다. 타이포스쿼팅 패턴(l→1, o→0 치환)이 감지되며 최근 3일 내 등록됐습니다.",
        "tags": ["Phishing", "Typosquatting", "Newly Registered"],
        "recommendation": "즉시 DNS 차단하고 접속 사용자를 추적해 자격증명 변경을 안내하세요.",
    },
    {
        "verdict": "SUSPICIOUS",
        "confidence": 70,
        "category": "DGA 의심",
        "description": "도메인 생성 알고리즘(DGA)으로 생성된 것으로 의심됩니다. 랜덤 문자열 패턴과 최근 등록 이력이 확인됩니다.",
        "tags": ["DGA", "Suspicious"],
        "recommendation": "해당 도메인으로의 DNS 쿼리를 모니터링하고 지속적인 통신이 감지되면 차단하세요.",
    },
    {
        "verdict": "CLEAN",
        "confidence": 92,
        "category": "정상 도메인",
        "description": "장기간 운영된 신뢰할 수 있는 도메인입니다. WHOIS 정보와 SSL 인증서가 정상적으로 확인됩니다.",
        "tags": ["Legitimate", "Established"],
        "recommendation": "위협 없음. 정상 도메인으로 판단됩니다.",
    },
]

_HASH_SAMPLES = [
    {
        "verdict": "MALICIOUS",
        "confidence": 99,
        "category": "랜섬웨어",
        "description": "WannaCry 랜섬웨어 변종으로 확인된 파일 해시입니다. 45개 이상의 바이러스 백신 엔진에서 악성으로 탐지됩니다.",
        "tags": ["Ransomware", "WannaCry", "High Confidence"],
        "recommendation": "해당 파일을 즉시 격리하고 실행된 시스템을 네트워크에서 분리하세요. 전체 시스템 랜섬웨어 감염 여부를 점검하세요.",
    },
    {
        "verdict": "SUSPICIOUS",
        "confidence": 60,
        "category": "의심 파일",
        "description": "일부 위협 인텔리전스 피드에서 의심으로 분류됩니다. 난독화 코드와 의심스러운 API 호출 패턴이 포함됩니다.",
        "tags": ["Obfuscated", "Suspicious Behavior"],
        "recommendation": "샌드박스 환경에서 동적 분석을 수행하고 실제 위협 여부를 확인하세요.",
    },
    {
        "verdict": "CLEAN",
        "confidence": 95,
        "category": "정상 파일",
        "description": "알려진 정상 소프트웨어 서명과 일치합니다. Microsoft 또는 주요 벤더의 공식 서명된 파일로 확인됩니다.",
        "tags": ["Legitimate", "Signed"],
        "recommendation": "위협 없음. 정기적인 파일 무결성 검사를 유지하세요.",
    },
]

_EMAIL_SAMPLES = [
    {
        "verdict": "MALICIOUS",
        "confidence": 92,
        "category": "스피어 피싱",
        "description": "알려진 스피어 피싱 캠페인에 사용된 이메일 주소입니다. 발신 도메인이 최근 악성 활동으로 보고됐습니다.",
        "tags": ["Spear Phishing", "BEC", "Malicious Sender"],
        "recommendation": "해당 발신자의 모든 이메일을 차단하고, 수신된 이메일의 내용을 검토하세요.",
    },
    {
        "verdict": "SUSPICIOUS",
        "confidence": 55,
        "category": "의심 발신자",
        "description": "발신 도메인이 정상 기업 도메인과 유사하지만 일치하지 않습니다. 이메일 도용 시도 가능성이 있습니다.",
        "tags": ["Lookalike Domain", "Suspicious"],
        "recommendation": "발신자에게 별도 채널로 신원을 확인하고, 첨부파일이나 링크는 열지 마세요.",
    },
]

_UNKNOWN_SAMPLE = {
    "verdict": "UNKNOWN",
    "confidence": 0,
    "category": "분류 불가",
    "description": "IoC 유형을 자동으로 인식할 수 없습니다. IP 주소, 도메인, 파일 해시(MD5/SHA256), 이메일 형식으로 입력해 주세요.",
    "tags": [],
    "recommendation": "올바른 형식으로 다시 입력해 주세요.",
}


def detect_type(value: str) -> str:
    v = value.strip()
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash"
    if _EMAIL_RE.match(v):
        return "email"
    if _URL_RE.match(v) or ('.' in v and ' ' not in v):
        return "domain"
    return "unknown"


def _pick(samples: list, value: str) -> dict:
    return samples[len(value) % len(samples)]


def analyze_single_ioc(value: str) -> dict:
    ioc_type = detect_type(value)
    if ioc_type == "ip":
        result = _pick(_IP_SAMPLES, value)
    elif ioc_type == "domain":
        result = _pick(_DOMAIN_SAMPLES, value)
    elif ioc_type == "hash":
        result = _pick(_HASH_SAMPLES, value)
    elif ioc_type == "email":
        result = _pick(_EMAIL_SAMPLES, value)
    else:
        result = _UNKNOWN_SAMPLE

    return {"ioc": value, "ioc_type": ioc_type, **result, "_mock": True}


def generate_mock_ioc(content: str) -> list[dict]:
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    return [analyze_single_ioc(line) for line in lines]
