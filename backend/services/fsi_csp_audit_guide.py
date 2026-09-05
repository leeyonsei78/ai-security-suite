"""App 24(금융보안원 클라우드 CSP 평가)의 정적 참고 데이터.

⚠️ 출처 고지: 아래 분야/항목 수는 금융보안원(FSI)이 공개한 요약 정보(fsec.or.kr 공지, 관련
기사·2차 자료)를 참고해 구성한 것으로, 200여 개 세부항목의 원문 전체를 담고 있지 않다.
실제 CSP 안전성평가·클라우드 이용보고에 쓰이는 공식 원문은 금융보안원 홈페이지(fsec.or.kr),
금융보안 레그테크 포털(regtech.fsec.or.kr), CSP 안전성평가 통합지원시스템(csp.fsec.or.kr)에서
반드시 재확인해야 한다. 이 앱은 그 공식 절차를 대체하지 않는 보조 점검 도구다.
"""

DISCLAIMER = (
    "이 도구는 금융보안원이 공개한 CSP 안전성평가/클라우드 보안관리 참고서의 분야·항목 구조를 "
    "참고해 AI가 보조적으로 점검하는 도구이며, 공식 평가·인증 절차를 대체하지 않습니다. "
    "실제 규제 대응 및 최신 세부 기준은 금융보안원 공식 자료(fsec.or.kr, regtech.fsec.or.kr, "
    "csp.fsec.or.kr)와 담당 부서 확인을 통해 진행하세요."
)

ASSESSMENT_TYPES = {
    "csp_assessment": {
        "label": "CSP 안전성평가 (공급자 평가, 11개 분야)",
        "description": (
            "금융회사·전자금융업자가 클라우드서비스제공자(CSP)를 선정·이용보고할 때 CSP 자체의 "
            "조직·운영 보안 역량을 평가하는 기준. 11개 분야 54개 항목(필수 16 + 대체 38)으로 구성."
        ),
        "who_for": "CSP를 신규로 선정하거나, 기존 CSP의 안전성을 재평가하는 금융회사 정보보호 담당자",
        "input_hint": "CSP의 보안 정책/인증 현황 설명, CSP가 제공한 자가진단 응답, 계약서/SLA의 보안 조항 등",
        "domains": [
            {"name": "정보보호 정책 및 조직", "item_count": 5},
            {"name": "인적 보안", "item_count": 4},
            {"name": "자산관리", "item_count": 5},
            {"name": "서비스 공급망 관리", "item_count": 6},
            {"name": "침해사고 관리", "item_count": 5},
            {"name": "접근통제", "item_count": 7},
            {"name": "암호화 및 키 관리", "item_count": 6},
            {"name": "보안모니터링", "item_count": 5},
            {"name": "물리적 보안", "item_count": 4},
            {"name": "비즈니스 연속성", "item_count": 4},
            {"name": "사고 보고 및 분석", "item_count": 3},
        ],
        "process_stages": [
            "1단계: 업무 중요도 평가 — 클라우드로 처리할 업무의 규모·복잡성, 중단 시 영향, 침해사고 시 고객 영향, CSP 종속 위험 판단",
            "2단계: CSP 안전성 평가 수행 — 11개 분야 54개 항목 점검",
            "3단계: 안전성 확보조치 및 업무연속성계획(BCP) 수립",
            "4단계: 정보보호위원회 심의 및 감독원 보고",
        ],
    },
    "cloud_env_management": {
        "label": "클라우드 환경 보안관리 점검 (이용기관 자체 점검, 5개 분야)",
        "description": (
            "금융분야 상용 클라우드서비스 보안 관리 참고서 기준 — 금융회사가 실제로 구성한 "
            "클라우드 테넌트/환경 설정을 5개 분야 32개 기준으로 자체 점검. App 16(방화벽)·App 18(IAM)과 "
            "달리 '금융권 클라우드'라는 규제 맥락에 특화된 관점으로 점검한다."
        ),
        "who_for": "실제로 클라우드 환경을 구축·운영 중인 금융회사 클라우드/보안 담당자",
        "input_hint": "IAM 정책, 네트워크/보안그룹 설정, 암호화 키 관리 방식, 로깅/모니터링 구성 등 실제 설정 텍스트",
        "domains": [
            {"name": "가상자원 관리", "item_count": 7},
            {"name": "네트워크 관리", "item_count": 6},
            {"name": "계정 및 권한 관리", "item_count": 7},
            {"name": "암호키 관리", "item_count": 5},
            {"name": "로깅 및 모니터링 관리", "item_count": 7},
        ],
        "process_stages": [],
    },
}

ISSUE_TYPE_LABELS = {
    "policy_gap": "정책/체계 미비",
    "access_control_weakness": "접근통제 미흡",
    "encryption_gap": "암호화/키관리 미흡",
    "monitoring_gap": "보안모니터링/로깅 미흡",
    "incident_response_gap": "침해사고 대응체계 미흡",
    "continuity_gap": "비즈니스 연속성 미흡",
    "supply_chain_risk": "공급망/하도급 관리 미흡",
    "physical_security_gap": "물리적 보안 미흡",
    "compliance_gap": "기타 컴플라이언스 위반",
}

REFERENCE_LINKS = [
    {"label": "금융보안원 자료마당", "url": "https://www.fsec.or.kr/bbs/detail?menuNo=222"},
    {"label": "금융보안 레그테크 포털", "url": "https://regtech.fsec.or.kr"},
    {"label": "CSP 안전성평가 통합지원시스템", "url": "https://csp.fsec.or.kr"},
]
