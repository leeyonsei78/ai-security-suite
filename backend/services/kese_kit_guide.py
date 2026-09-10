"""App 26(KISA 보안 가이드라인 종합 점검)의 정적 참고 데이터.

⚠️ 출처 고지: 이 앱은 github.com/cdppcorp/KESE-KIT(KISA Enhanced Security Evaluation Kit,
Claude Code 플러그인, MIT License)이 공개한 "지원 가이드라인" 표에 나온 분야명·항목 수·참조
표준만 참고해 재구성한 것이다 — 560여 개(CII)/421여 개(제로트러스트)/103여 개(로봇) 등
세부 점검 항목의 원문 전체를 담고 있지 않다. 실제 점검 항목 원문은 KISA(한국인터넷진흥원,
kisa.or.kr)·과학기술정보통신부가 발행한 공식 가이드라인 원문을 반드시 재확인해야 한다.
이 앱은 그 공식 절차를 대체하지 않는 보조 점검 도구다 (App 24 fsi_csp_audit_guide.py와
동일한 고지 원칙).
"""

DISCLAIMER = (
    "이 도구는 KISA(한국인터넷진흥원) 공개 가이드라인 기반의 오픈소스 참고 자료(KESE-KIT)가 "
    "정리한 분야·항목 구조를 참고해 AI가 보조적으로 점검하는 도구이며, 공식 취약점 분석·평가나 "
    "인증 절차를 대체하지 않습니다. 실제 규제 대응 및 최신 세부 기준은 KISA 공식 자료(kisa.or.kr)와 "
    "담당 부서·전문 평가기관 확인을 통해 진행하세요."
)

REFERENCE_LINKS = [
    {"label": "KISA 홈페이지", "url": "https://www.kisa.or.kr"},
    {"label": "KESE-KIT (원본 스킬, GitHub)", "url": "https://github.com/cdppcorp/KESE-KIT"},
    {"label": "OWASP Top 10 for LLM", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
]

ASSESSMENT_TYPES = {
    "cii": {
        "label": "주요정보통신기반시설(CII) 취약점 분석·평가 — 560+항목",
        "description": (
            "정보통신기반 보호법상 주요정보통신기반시설 지정 기관 또는 유사 기준으로 자체 점검하려는 "
            "조직을 위한 기술적(12개 시스템 유형)·관리적(14개 영역)·물리적 취약점 분석·평가 항목 구조."
        ),
        "who_for": "주요정보통신기반시설 지정 기관의 정보보호 담당자, 또는 유사 수준으로 인프라를 자체 점검하려는 기업",
        "input_hint": "서버(Unix/Windows)·DBMS·네트워크·보안장비·클라우드 등의 실제 설정값, 계정/패스워드 정책, 또는 관리적·물리적 보안 현황 서술",
        "domains": [
            {"name": "Unix/Linux 서버", "item_count": 67},
            {"name": "Windows 서버", "item_count": 64},
            {"name": "웹 서비스", "item_count": 26},
            {"name": "보안 장비", "item_count": 23},
            {"name": "네트워크 장비", "item_count": 38},
            {"name": "제어시스템", "item_count": 46},
            {"name": "PC", "item_count": 18},
            {"name": "DBMS", "item_count": 26},
            {"name": "이동통신", "item_count": 4},
            {"name": "Web Application", "item_count": 21},
            {"name": "가상화 장비", "item_count": 25},
            {"name": "클라우드", "item_count": 19},
            {"name": "관리적 취약점(14개 영역)", "item_count": 127},
            {"name": "물리적 취약점", "item_count": 18},
        ],
        "process_stages": [],
    },
    "ai_security": {
        "label": "AI 보안 안내서 — 54+항목",
        "description": (
            "과기정통부·KISA 「인공지능(AI) 보안 안내서」 기준 — AI 개발자/서비스 제공자/이용자별로 "
            "생명주기 단계에 따른 보안 요구사항을 점검. App 12(AI 모델 감사)가 OWASP LLM Top 10 관점의 "
            "런타임 설계 감사라면, 이 유형은 KISA 기준의 AI 개발·운영 생명주기 전반을 점검한다."
        ),
        "who_for": "AI 모델을 직접 개발·학습시키는 팀, AI 서비스를 운영하는 조직, 또는 AI 이용 정책을 수립하는 담당자",
        "input_hint": "데이터 수집/검증 절차, 모델 개발·배포 프로세스, 접근통제/모니터링 체계, 또는 AI 이용 정책 서술",
        "domains": [
            {"name": "AI 개발자 (6단계: 계획→데이터→모델개발→배포→모니터링→파기)", "item_count": 54},
            {"name": "AI 서비스 제공자 (6단계: 계획→개발→운영→유지보수→피드백→파기)", "item_count": 43},
            {"name": "AI 이용자 (보안 수칙)", "item_count": 7},
        ],
        "process_stages": [],
    },
    "robot_security": {
        "label": "로봇 보안 — ~103항목",
        "description": (
            "KISA 「로봇 보안모델(고도화)」 및 점검 체크리스트 기준 — 산업용/서비스용/의료용 로봇(ISO 8373)을 "
            "대상으로 NIST SP 800-218(SSDF)·NIST SP 800-161(공급망)·IEC 62443·EU CRA/RED 등 국제 표준을 "
            "반영한 11개 카테고리 점검."
        ),
        "who_for": "산업용/서비스용/의료용 로봇을 개발·운영하는 제조사 및 도입 기업의 보안 담당자",
        "input_hint": "로봇 펌웨어/SW 개발 프로세스, 인증·접근통제 방식, 무선 통신 보안 설정, 공급망 부품 관리 현황 등",
        "domains": [
            {"name": "보안 SW 개발 (SSDF)", "item_count": 19},
            {"name": "공급망 보안", "item_count": 7},
            {"name": "식별 및 인증", "item_count": 11},
            {"name": "사용 통제", "item_count": 11},
            {"name": "시스템 무결성", "item_count": 11},
            {"name": "데이터 보호", "item_count": 4},
            {"name": "데이터 흐름 제한", "item_count": 2},
            {"name": "이벤트 대응", "item_count": 3},
            {"name": "자원 가용성", "item_count": 8},
            {"name": "사이버 복원력", "item_count": 13},
            {"name": "무선 보안", "item_count": 14},
        ],
        "process_stages": [],
    },
    "space_security": {
        "label": "우주 보안 — 53항목",
        "description": (
            "과기정통부·KISA 「우주 보안모델」 Part1(위성활용 서비스)·Part2(GSaaS/우주 공급망) 기준 — "
            "위성 운영사, GSaaS 제공자, 지상국 운영사, 우주 공급망 참여기업을 대상으로 CMMC·K-RMF·NIS2·"
            "ISMS-P·NIST IR 8401/8270 등을 반영한 12개 분야 점검."
        ),
        "who_for": "위성 운영사, GSaaS(지상국 as a Service) 제공자, 지상국 운영사, 우주 공급망 참여기업",
        "input_hint": "지상국/위성 접근통제 방식, 원격측정(telemetry) 암호화 여부, 공급망 부품 검증 절차, 비상 계획 등",
        "domains": [
            {"name": "접근통제", "item_count": 12},
            {"name": "식별 및 인증", "item_count": 2},
            {"name": "시스템 및 통신 보안", "item_count": 7},
            {"name": "시스템 및 정보 무결성", "item_count": 4},
            {"name": "시스템/서비스 운영관리", "item_count": 9},
            {"name": "사고 대응", "item_count": 2},
            {"name": "인원 보안", "item_count": 2},
            {"name": "물리보안", "item_count": 3},
            {"name": "위험평가 및 보안 평가", "item_count": 2},
            {"name": "보안 거버넌스", "item_count": 4},
            {"name": "비상 계획", "item_count": 2},
            {"name": "공급망 관리", "item_count": 4},
        ],
        "process_stages": [],
    },
    "secure_coding": {
        "label": "시큐어코딩 가이드 — 46항목",
        "description": (
            "KISA 「Javascript/Python 시큐어코딩 가이드(2023년 개정본)」 기준 — CWE/SANS Top 25, OWASP "
            "Top 10에 매핑된 7개 카테고리 46개 항목. App 3(취약점 스캐너)의 코드 스니펫 분석과 달리, "
            "KISA 시큐어코딩 가이드의 카테고리 체계(입력데이터 검증/보안기능/시간및상태/에러처리/코드오류/"
            "캡슐화/API오용)로 분류한다."
        ),
        "who_for": "JavaScript/Python 웹 개발자, AI 코딩 도구(Claude/Cursor/Copilot) 사용자, 바이브코딩 개발자",
        "input_hint": "점검할 소스 코드 스니펫 (JavaScript/Python/의사코드 무관)",
        "domains": [
            {"name": "입력데이터 검증 및 표현", "item_count": 16},
            {"name": "보안기능", "item_count": 16},
            {"name": "시간 및 상태", "item_count": 2},
            {"name": "에러처리", "item_count": 3},
            {"name": "코드오류", "item_count": 3},
            {"name": "캡슐화", "item_count": 4},
            {"name": "API 오용", "item_count": 2},
        ],
        "process_stages": [],
    },
    "zero_trust": {
        "label": "제로트러스트 보안 성숙도 평가 — ~421항목",
        "description": (
            "한국제로트러스트포럼·KISA 「제로트러스트 가이드라인 2.0」, NIST SP 800-207, CISA ZT Maturity "
            "Model 기준 — 8개 핵심요소(+OT/ICS 특화)를 기존(Traditional)→초기(Initial)→향상(Advanced)→"
            "최적화(Optimal) 4단계 성숙도로 평가."
        ),
        "who_for": "제로트러스트 도입을 추진하는 기업, OT/ICS 환경 운영자, 클라우드 전환 조직, 보안 성숙도 평가 담당자",
        "input_hint": "신원/기기 인증 방식, 네트워크 분리 구조, 애플리케이션 접근제어, 데이터 분류·암호화, 가시성/자동화 현황 등",
        "domains": [
            {"name": "식별자·신원", "item_count": 53},
            {"name": "기기·엔드포인트", "item_count": 36},
            {"name": "네트워크", "item_count": 54},
            {"name": "시스템", "item_count": 49},
            {"name": "애플리케이션·워크로드", "item_count": 60},
            {"name": "데이터", "item_count": 58},
            {"name": "가시성·분석", "item_count": 43},
            {"name": "자동화·통합", "item_count": 43},
            {"name": "OT/ICS 특화", "item_count": 25},
        ],
        "process_stages": [
            "성숙도 4단계: 기존(Traditional) → 초기(Initial) → 향상(Advanced) → 최적화(Optimal)",
        ],
    },
    "supply_chain": {
        "label": "SW 공급망 보안(SBOM) — 29항목",
        "description": (
            "국정원·과기정통부·KISA 「SW 공급망 보안 가이드라인」 기준 — NIST SP 800-161r1·NIST SP 800-218"
            "(SSDF)·NTIA/NIS-SBOM을 반영해 설계·개발·공급·운영·유지보수 5단계로 점검. App 17(인프라 취약점 "
            "스캐너)의 의존성 스캔이 '알려진 CVE 매칭'이라면, 이 유형은 SBOM 작성·서명·검증 등 공급망 "
            "프로세스 자체의 성숙도를 점검한다."
        ),
        "who_for": "SW 개발기업, 공공조달 납품사, 정부과제 개발자, 바이브코딩 개발자",
        "input_hint": "SBOM 작성 여부(SPDX/CycloneDX/NIS-SBOM), 오픈소스 라이선스 점검 절차, 서명·검증 프로세스, CI/CD 취약점 스캔 연동 현황 등",
        "domains": [
            {"name": "설계 단계", "item_count": 5},
            {"name": "개발 단계", "item_count": 11},
            {"name": "공급(유통) 단계", "item_count": 3},
            {"name": "도입 및 운영 단계", "item_count": 7},
            {"name": "유지보수 단계", "item_count": 3},
        ],
        "process_stages": [
            "SBOM 표준: SPDX(ISO/IEC 5962), CycloneDX(OWASP), NIS-SBOM(20개 기본항목)",
            "지원 도구 예시: Syft, Grype, CycloneDX CLI, npm audit, pip-audit, govulncheck",
        ],
    },
}

ISSUE_TYPE_LABELS = {
    "access_control_gap": "접근통제/인증 미흡",
    "network_segmentation_gap": "네트워크 분리/경계통제 미흡",
    "encryption_key_gap": "암호화/키관리 미흡",
    "logging_monitoring_gap": "로깅/모니터링/가시성 미흡",
    "patch_hardening_gap": "패치관리/시스템 하드닝 미흡",
    "secure_coding_flaw": "시큐어코딩/입력검증 결함",
    "supply_chain_gap": "공급망/SBOM/제3자 관리 미흡",
    "incident_resilience_gap": "사고대응/복원력/BCP 미흡",
    "governance_policy_gap": "거버넌스/정책/문서화 미흡",
    "physical_personnel_gap": "물리보안/인원보안 미흡",
}

# "이 앱이 대신 실행하지 않는다, 결과를 복사해 붙여넣으라"는 공용 안내문 — App 24의
# COMMAND_USAGE_NOTE와 동일한 역할(이 문구 없이 명령어만 나열하면 "여기다 치라는 건지"
# 헷갈린다는 실제 사용자 피드백이 App 3/24에서 반복 확인됨).
COMMAND_USAGE_NOTE = (
    "아래 명령어는 이 앱이 대신 실행해주지 않습니다 — 점검 대상 시스템에 접근 권한이 있는 곳(해당 "
    "서버의 터미널, 관리 콘솔의 CloudShell 등)에서 직접 실행한 뒤, 화면에 출력된 결과를 그대로 복사해 "
    "아래 '점검 대상 내용' 입력창에 붙여넣으세요."
)

# 유형별 정보 수집 가이드 — CII는 실제 CLI 명령이 있는 영역(서버/네트워크/DBMS/클라우드) 위주로,
# 나머지 6개는 대부분 "어느 문서/정책을 확인·요청하는지"가 핵심이라 App 24의 csp_assessment와
# 같은 where/how 형태를 쓴다. 14개 CII 도메인을 전부 1:1로 다루면 방대해지므로, 실제로 많이 쓰이는
# 시스템 계열 단위로 묶었다(App 3 recon_guide.py의 "카테고리 단위로 묶는다" 관행과 동일).
DATA_COLLECTION = {
    "cii": [
        {
            "domain": "Unix/Linux 서버",
            "where": "점검 대상 서버에 SSH 접속한 터미널",
            "what_to_check": "불필요 계정/서비스, 패스워드 정책, SUID/SGID 파일, 로그 설정",
            "commands": [
                "cat /etc/passwd  # 계정 목록",
                "awk -F: '($3 == 0) {print}' /etc/passwd  # UID 0(root 권한) 계정 확인",
                "cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_LEN'  # 패스워드 정책",
                "find / -perm -4000 -type f 2>/dev/null  # SUID 바이너리 목록",
                "ss -tulnp  # 리스닝 포트/서비스",
            ],
        },
        {
            "domain": "Windows 서버",
            "where": "점검 대상 서버의 PowerShell(관리자 권한 권장)",
            "what_to_check": "계정 정책, 공유 폴더, 불필요 서비스, 감사 정책",
            "commands": [
                "Get-LocalUser | Select Name, Enabled, PasswordRequired",
                "net accounts  # 패스워드/잠금 정책",
                "Get-SmbShare  # 공유 폴더 목록",
                "Get-Service | Where-Object {$_.Status -eq 'Running'}",
                "auditpol /get /category:*  # 감사 정책",
            ],
        },
        {
            "domain": "네트워크 장비",
            "where": "네트워크 장비 CLI (SSH/콘솔)",
            "what_to_check": "불필요 서비스(Telnet 등), SNMP 기본 커뮤니티스트링, ACL 구성",
            "commands": [
                "show running-config  # Cisco IOS 등 — 전체 설정 확인",
                "show ip access-lists",
                "show snmp community  # 기본값(public/private) 사용 여부",
            ],
        },
        {
            "domain": "DBMS",
            "where": "DBMS 클라이언트(mysql/psql/sqlplus 등)",
            "what_to_check": "기본 계정/패스워드, 원격 접속 허용 범위, 감사 로그 설정",
            "commands": [
                "SELECT user, host FROM mysql.user;  -- MySQL",
                "SHOW VARIABLES LIKE 'bind_address';  -- MySQL 원격 접속 허용 범위",
                "SELECT username, account_status FROM dba_users;  -- Oracle",
            ],
        },
        {
            "domain": "클라우드",
            "where": "클라우드 CLI(aws/az/gcloud) 또는 콘솔",
            "what_to_check": "IAM 과다 권한, 보안그룹 전체 공개, 로깅 활성화 여부 — App 16(방화벽)·18(IAM)과 대상 중복",
            "commands": [
                "aws iam get-account-authorization-details --output json",
                "aws ec2 describe-security-groups --output json",
                "aws cloudtrail describe-trails",
            ],
            "cross_link": "네트워크/권한 설정 자체를 더 상세히 보려면 방화벽 정책 감사기(/firewall-audit)·IAM 정책 감사기(/iam-audit)를 함께 활용하세요.",
        },
        {
            "domain": "관리적·물리적 취약점",
            "where": "정보보호 정책 문서, 출입통제 로그, 인력 보안 서약서 등",
            "what_to_check": "정보보호 조직·정책 문서화 여부, 출입통제·CCTV 등 물리적 보안 현황, 정기 교육 실시 여부",
            "commands": [],
            "cross_link": "이 항목은 명령어가 아니라 조직 내 정책 문서와 현장 확인이 필요합니다 — 해당 서술을 정리해 붙여넣으세요.",
        },
    ],
    "ai_security": [
        {
            "domain": "AI 개발자",
            "where": "모델 학습 파이프라인 코드, 데이터 관리 문서, 모델 카드(Model Card)",
            "how": "데이터 수집·검증 절차, 모델 학습 시 접근통제, 배포 전 취약점 점검(적대적 예제 테스트 등) 여부를 확인하세요.",
        },
        {
            "domain": "AI 서비스 제공자",
            "where": "서비스 운영 문서, API 접근통제 정책, 모니터링 대시보드",
            "how": "API 키 관리 방식, 이상 사용 탐지, 모델 드리프트 모니터링, 서비스 종료 시 데이터 파기 절차를 확인하세요.",
        },
        {
            "domain": "AI 이용자",
            "where": "사내 AI 이용 정책/가이드라인 문서",
            "how": "민감정보 입력 금지, 생성 결과 검증 절차, 승인된 AI 도구 목록 등이 문서화돼 있는지 확인하세요.",
        },
    ],
    "robot_security": [
        {
            "domain": "전반",
            "where": "로봇 펌웨어/SW 개발 문서, 부품 조달 기록, 무선 통신 설정",
            "how": "기본 비밀번호 변경 여부, 펌웨어 서명 검증, 무선 통신 암호화 방식, SBOM(부품 목록) 관리 여부를 확인하세요.",
        },
    ],
    "space_security": [
        {
            "domain": "전반",
            "where": "지상국 접근통제 정책, 위성 원격측정(telemetry) 암호화 설정, 공급망 계약서",
            "how": "지상국 접근 인증 방식, 명령/텔레메트리 링크 암호화 여부, 공급망 부품의 출처 검증 절차를 확인하세요.",
        },
    ],
    "secure_coding": [
        {
            "domain": "전반",
            "where": "소스 코드 저장소",
            "how": "점검할 함수/모듈의 코드를 그대로 복사해 붙여넣으세요 — 이 유형은 파일 대신 코드 스니펫을 직접 입력하는 것을 권장합니다.",
        },
    ],
    "zero_trust": [
        {
            "domain": "전반",
            "where": "IAM/MFA 설정, 네트워크 분리 구성도, 데이터 분류 정책, SIEM/가시성 도구 설정",
            "how": "신원·기기·네트워크·데이터 각 요소별로 현재 구성 방식을 서술해 붙여넣으세요 — 명령어보다는 아키텍처 설명이 더 유용합니다.",
        },
    ],
    "supply_chain": [
        {
            "domain": "설계~유지보수 전 단계",
            "where": "이 백엔드가 실행되는 PC 또는 CI/CD 파이프라인",
            "what_to_check": "SBOM 생성 여부, 알려진 취약점 스캔 결과, 서명 검증 절차",
            "commands": [
                "syft packages dir:. -o cyclonedx-json  # SBOM 생성 (CycloneDX 형식)",
                "grype dir:.  # 알려진 취약점 스캔",
                "pip-audit  # Python 의존성 취약점 스캔",
                "npm audit --json  # Node.js 의존성 취약점 스캔",
            ],
            "cross_link": "알려진 CVE 자체를 스캔하려면 인프라 취약점 스캐너(/infra-scan)의 의존성(SCA) 탭을 함께 활용하세요.",
        },
    ],
}
