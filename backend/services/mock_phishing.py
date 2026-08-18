import random

_PHISHING_SAMPLES = [
    {
        "verdict": "PHISHING",
        "score": 94,
        "summary": "전형적인 계정 탈취 피싱 이메일입니다. 긴박감을 조성하고 가짜 로그인 페이지로 유도합니다.",
        "indicators": [
            "발신 도메인이 공식 도메인과 유사하지만 다름 (paypa1.com vs paypal.com)",
            "긴박감 유발 문구: '24시간 내 조치 필요'",
            "링크 URL이 표시 텍스트와 다른 도메인을 가리킴",
            "개인정보(비밀번호, 카드번호) 입력 요구",
            "발신자 이름과 이메일 주소 불일치",
        ],
        "safe_indicators": [],
        "recommendation": "이메일을 즉시 삭제하고 링크를 클릭하지 마세요. 실제 서비스 접속은 직접 URL을 입력하세요.",
        "_mock": True,
    },
    {
        "verdict": "SUSPICIOUS",
        "score": 62,
        "summary": "일부 피싱 신호가 감지됩니다. 발신자 확인 후 주의해서 처리하세요.",
        "indicators": [
            "단축 URL 사용으로 실제 목적지 불명확",
            "첨부파일이 포함되어 있으나 요청하지 않은 파일",
            "HTML 형식 이메일에 외부 이미지 로드 포함",
        ],
        "safe_indicators": [
            "발신 도메인 SPF/DKIM 검증 통과",
            "과도한 긴박감 문구 없음",
        ],
        "recommendation": "첨부파일을 열기 전 발신자에게 별도 채널로 확인하세요. 단축 URL은 URL 확인 서비스로 먼저 검사하세요.",
        "_mock": True,
    },
    {
        "verdict": "SAFE",
        "score": 8,
        "summary": "피싱 신호가 거의 없습니다. 정상적인 이메일로 판단됩니다.",
        "indicators": [
            "이미지 내 텍스트 포함 (OCR 회피 시도 가능성 낮음)",
        ],
        "safe_indicators": [
            "발신 도메인이 공식 도메인과 일치",
            "링크 URL이 공식 도메인을 가리킴",
            "개인정보 요구 없음",
            "DKIM 서명 유효",
        ],
        "recommendation": "정상 이메일로 보입니다. 일반적인 보안 주의사항을 지키며 처리하세요.",
        "_mock": True,
    },
    {
        "verdict": "MALICIOUS",
        "score": 98,
        "summary": "악성코드 배포 목적의 스피어 피싱입니다. 첨부파일에 매크로 기반 드로퍼가 포함된 것으로 의심됩니다.",
        "indicators": [
            "실행 파일을 포함한 ZIP 첨부파일",
            "매크로 활성화 유도 문구 포함",
            "발신 IP가 알려진 악성 IP 범위에 해당",
            "수신자 이름/직책을 정확히 언급한 타깃형 공격",
            "공식 기관 사칭 (국세청, 금융감독원 등)",
        ],
        "safe_indicators": [],
        "recommendation": "즉시 이메일을 격리하고 보안팀에 신고하세요. 첨부파일을 절대 열지 마세요. 동일 이메일을 받은 다른 직원이 있는지 확인하세요.",
        "_mock": True,
    },
]

_VERDICT_COLORS = {
    "MALICIOUS": "red",
    "PHISHING": "orange",
    "SUSPICIOUS": "yellow",
    "SAFE": "green",
}


def generate_mock_phishing(content: str) -> dict:
    idx = len(content) % len(_PHISHING_SAMPLES)
    return _PHISHING_SAMPLES[idx]
