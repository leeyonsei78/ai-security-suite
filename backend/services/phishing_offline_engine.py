"""피싱/악성 콘텐츠 탐지기(App 2)의 오프라인(폐쇄망) 모드 — Claude/로컬 LLM 없이도 실제
입력을 정규식/키워드 기반으로 판정한다. App 3의 vuln_offline_engine.py와 동일한 설계
원칙: 입력 내용과 무관한 고정 샘플(mock)이 아니라, 실제로 붙여넣은 이메일/URL/텍스트를
파싱해 알려진 피싱 패턴과 대조한다. AI만큼 폭넓게 탐지하지 못하므로 결과에 항상
`engine_note`로 한계를 명시한다.
"""
import re

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 규칙/정규식 기반 오프라인 분석 엔진이 생성했습니다 — "
    "AI가 아니라 사전 정의된 패턴(URL 단축기, IP 기반 URL, 브랜드 사칭 도메인, 긴급성 유발 문구, "
    "자격증명 요구, 의심스러운 첨부파일 확장자)과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁고 "
    "새롭거나 정교한 피싱 기법은 놓칠 수 있습니다. 인터넷 또는 로컬 LLM을 사용할 수 있게 되면 "
    "AI 모드로 재분석하는 것을 권장합니다."
)

_URL_SHORTENER_RE = re.compile(
    r"https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorturl\.at|tiny\.cc)",
    re.I,
)
_IP_HOST_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}\b")
# 알려진 브랜드의 흔한 타이포스쿼팅/homograph 패턴(리트스피크 치환) — 완전한 유사도 매칭이
# 아니라 실제로 자주 관찰되는 변형만 소수 큐레이션(best-effort).
_BRAND_TYPOSQUAT_RE = re.compile(
    r"\b(paypa1|payp4l|g00gle|micr0soft|amaz0n|netfl1x|app1e|coup4ng|k4kao|nid-naver|"
    r"nonghyub|kb-st4r|shinh4n)\b",
    re.I,
)
_URGENCY_RE = re.compile(
    r"(24시간\s*내|즉시\s*확인|계정.{0,6}(정지|잠금|차단|해지)|마지막\s*경고|긴급.{0,4}(조치|확인)|"
    r"지금\s*(바로|즉시)|해킹.{0,6}(되었|당했)|verify\s*now|act\s*now|suspend(ed)?\s*within|"
    r"immediately|urgent(ly)?\s*action)",
    re.I,
)
_CREDENTIAL_REQUEST_RE = re.compile(
    r"(비밀번호|패스워드|카드\s*번호|주민등록번호|보안카드|계좌\s*비밀번호|"
    r"\botp\b|인증\s*번호|social\s*security|credit\s*card\s*number|login\s*credential)",
    re.I,
)
_SUSPICIOUS_ATTACHMENT_RE = re.compile(r"\.(exe|scr|js|hta|vbs|bat|jar|ps1)\b", re.I)
_GENERIC_GREETING_RE = re.compile(r"(고객님|dear\s*customer|dear\s*user|dear\s*sir/madam)", re.I)
_HTML_LINK_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.I)
_OFFICIAL_LOOKING_DOMAIN_RE = re.compile(
    r"\b(google|paypal|microsoft|amazon|netflix|apple|coupang|naver|kakao)\.com\b", re.I
)


def _extract_href_mismatch(content: str) -> str | None:
    for m in _HTML_LINK_RE.finditer(content):
        href, text = m.group(1), m.group(2).strip()
        # 표시 텍스트 자체가 도메인/URL처럼 생겼는데 실제 href의 호스트와 다르면 의심
        text_domain_match = re.search(r"([a-z0-9-]+\.[a-z]{2,})", text, re.I)
        href_domain_match = re.search(r"://([^/]+)", href)
        if text_domain_match and href_domain_match:
            text_domain = text_domain_match.group(1).lower()
            href_domain = href_domain_match.group(1).lower()
            if text_domain not in href_domain and href_domain not in text_domain:
                return f"표시된 링크 텍스트({text_domain})와 실제 목적지({href_domain})가 다릅니다."
    return None


def analyze_offline(content: str) -> dict:
    indicators: list[str] = []
    safe_indicators: list[str] = []
    score = 0

    if _BRAND_TYPOSQUAT_RE.search(content):
        indicators.append("잘 알려진 브랜드를 사칭한 것으로 보이는 타이포스쿼팅 도메인 패턴이 발견됐습니다.")
        score += 35
    if _IP_HOST_URL_RE.search(content):
        indicators.append("도메인이 아닌 IP 주소를 직접 가리키는 URL이 포함되어 있습니다.")
        score += 25
    if _URL_SHORTENER_RE.search(content):
        indicators.append("URL 단축 서비스가 사용되어 실제 목적지 주소가 가려져 있습니다.")
        score += 15
    if _URGENCY_RE.search(content):
        indicators.append("긴박감·공포심을 유발하는 문구가 포함되어 있습니다(예: 계정 정지, 즉시 확인).")
        score += 20
    if _CREDENTIAL_REQUEST_RE.search(content):
        indicators.append("비밀번호·카드번호·인증번호 등 민감한 자격증명 입력을 요구합니다.")
        score += 25
    if _SUSPICIOUS_ATTACHMENT_RE.search(content):
        indicators.append("실행 파일(.exe/.scr/.js 등) 확장자가 언급되어 악성코드 첨부 가능성이 있습니다.")
        score += 30
    href_mismatch = _extract_href_mismatch(content)
    if href_mismatch:
        indicators.append(href_mismatch)
        score += 20
    if _GENERIC_GREETING_RE.search(content) and (_BRAND_TYPOSQUAT_RE.search(content) or _OFFICIAL_LOOKING_DOMAIN_RE.search(content)):
        indicators.append("특정 수신자 이름 없이 '고객님' 등 일반 호칭을 쓰면서 유명 브랜드를 언급합니다.")
        score += 10

    score = min(99, score)

    if not indicators:
        safe_indicators.append("URL 단축기·IP 기반 URL·브랜드 사칭 도메인 패턴이 발견되지 않았습니다.")
        safe_indicators.append("긴박감을 유발하는 문구나 자격증명 요구가 발견되지 않았습니다.")

    if score >= 80:
        verdict = "MALICIOUS"
    elif score >= 60:
        verdict = "PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    summary_map = {
        "MALICIOUS": f"규칙 기반 오프라인 분석에서 심각한 피싱/악성 신호 {len(indicators)}건이 발견됐습니다. 즉시 격리하고 열람하지 마세요.",
        "PHISHING": f"규칙 기반 오프라인 분석에서 강한 피싱 신호 {len(indicators)}건이 발견됐습니다.",
        "SUSPICIOUS": f"규칙 기반 오프라인 분석에서 일부 의심 신호 {len(indicators)}건이 발견됐습니다. 주의해서 확인하세요.",
        "SAFE": "규칙 기반 오프라인 분석에서 알려진 피싱 패턴이 발견되지 않았습니다.",
    }
    recommendation_map = {
        "MALICIOUS": "이 콘텐츠를 즉시 격리/삭제하고 링크·첨부파일을 절대 열지 마세요. 보안팀에 신고하세요.",
        "PHISHING": "링크를 클릭하거나 자격증명을 입력하지 마세요. 발신자를 별도 채널로 확인하세요.",
        "SUSPICIOUS": "발신자 확인 후 신중하게 처리하세요. 링크는 직접 주소창에 입력해 접속하세요.",
        "SAFE": "특이 신호는 없으나, 규칙 기반 검사의 한계로 오탐/누락이 있을 수 있습니다. 일반적인 보안 주의사항을 유지하세요.",
    }

    return {
        "verdict": verdict,
        "score": score,
        "summary": summary_map[verdict],
        "indicators": indicators,
        "safe_indicators": safe_indicators,
        "recommendation": recommendation_map[verdict],
        "engine_note": ENGINE_DISCLAIMER,
    }
