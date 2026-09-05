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

# 도메인별로 "어디 가서 무엇을 확인/수집하는지"를 구체화한 가이드 — App 16(firewall_audit_guide.py)의
# 플랫폼별 CLI 명령어, App 11(policy_guide.py)의 environment_recon과 같은 목적의 데이터.
# cloud_env_management(자체 환경 점검)는 실제 CLI 명령을 그대로 실행하면 되지만,
# csp_assessment(공급자 평가)는 "내 시스템"이 아니라 "CSP라는 제3자"를 평가하는 것이라
# 명령어가 아니라 "어느 문서/페이지를 요청하거나 확인해야 하는지"가 핵심이라 형태가 다르다.

# 명령어만 덜렁 보여주면 "이걸 어디서 실행하고 결과를 어떻게 쓰라는 건지" 헷갈릴 수 있어
# (실제 사용자 피드백으로 확인됨) — cloud_env_management 패널 맨 위에 한 번만 명시하는 공용 안내문.
COMMAND_USAGE_NOTE = (
    "아래 명령어는 이 앱이 대신 실행해주지 않습니다 — 해당 클라우드 계정에 접근 권한이 있는 "
    "곳(AWS/Azure/GCP CLI가 설치·로그인된 PC, 또는 클라우드 콘솔의 CloudShell 등)에서 직접 "
    "실행한 뒤, 화면에 출력된 결과(JSON/텍스트)를 그대로 복사해서 아래 '점검 대상 내용' "
    "입력창에 붙여넣으세요. CLI 대신 콘솔 화면을 그대로 캡처하거나 표를 복사해 붙여넣어도 됩니다."
)

DATA_COLLECTION = {
    "cloud_env_management": [
        {
            "domain": "가상자원 관리",
            "where": "클라우드 콘솔의 컴퓨트(EC2/VM/Compute Engine)·스토리지·이미지 목록 화면, 또는 CLI",
            "what_to_check": "사용 중인 인스턴스/이미지/스토리지가 실제 운영 목적과 일치하는지, 불필요하게 남은 리소스(고아 인스턴스, 퍼블릭 버킷)가 없는지",
            "commands": [
                "aws ec2 describe-instances --output json  # AWS",
                "aws s3api list-buckets && aws s3api get-bucket-acl --bucket <버킷명>  # 퍼블릭 여부 확인",
                "az vm list --output json  # Azure",
                "az storage account list --output json",
                "gcloud compute instances list --format=json  # GCP",
                "gcloud storage buckets list --format=json",
            ],
        },
        {
            "domain": "네트워크 관리",
            "where": "VPC/네트워크 콘솔의 보안그룹(Security Group)·NSG·방화벽 규칙 화면 — App 16(방화벽 정책 감사기)과 동일한 대상",
            "what_to_check": "관리 포트(22/3389/3306 등)가 0.0.0.0/0으로 열려 있지 않은지, 세그먼트가 목적별로 분리돼 있는지",
            "commands": [
                "aws ec2 describe-security-groups --output json  # AWS",
                "az network nsg rule list --nsg-name <NSG이름> --resource-group <RG> --output json  # Azure",
                "gcloud compute firewall-rules list --format=json  # GCP",
            ],
            "cross_link": "이 도메인은 사실상 방화벽 규칙 감사와 같으므로, 더 상세한 규칙별 분석이 필요하면 방화벽 정책 감사기(/firewall-audit)를 함께 활용하세요.",
        },
        {
            "domain": "계정 및 권한 관리",
            "where": "IAM 콘솔의 사용자/역할/정책 화면 — App 18(클라우드 IAM 정책 감사기)과 동일한 대상",
            "what_to_check": "관리자 권한이 과도하게 부여돼 있지 않은지, MFA가 모든 관리자 계정에 적용됐는지, 장기 미사용 액세스 키가 없는지",
            "commands": [
                "aws iam get-account-authorization-details --output json  # AWS",
                "aws iam get-credential-report  # MFA·키 사용 이력",
                "az role assignment list --all --output json  # Azure",
                "gcloud projects get-iam-policy <프로젝트ID> --format=json  # GCP",
            ],
            "cross_link": "이 도메인도 클라우드 IAM 정책 감사기(/iam-audit)로 더 상세히 점검할 수 있습니다.",
        },
        {
            "domain": "암호키 관리",
            "where": "KMS(Key Management Service)/Key Vault 콘솔",
            "what_to_check": "저장 데이터(at-rest) 암호화가 적용돼 있는지, 키 순환(rotation) 정책이 설정돼 있는지, 키에 대한 접근 권한이 최소화돼 있는지",
            "commands": [
                "aws kms list-keys && aws kms get-key-rotation-status --key-id <키ID>  # AWS",
                "az keyvault list --output json && az keyvault key list --vault-name <이름>  # Azure",
                "gcloud kms keys list --keyring <키링> --location <위치> --format=json  # GCP",
            ],
        },
        {
            "domain": "로깅 및 모니터링 관리",
            "where": "CloudTrail(AWS)/Activity Log(Azure)/Cloud Audit Logs(GCP) 설정 화면",
            "what_to_check": "관리 이벤트 로깅이 전체 리전/구독에 켜져 있는지, 로그 보존 기간이 충분한지, 로그 자체가 변조 방지되는 저장소(예: 별도 계정의 S3, 삭제 방지 정책)에 보관되는지",
            "commands": [
                "aws cloudtrail describe-trails && aws cloudtrail get-trail-status --name <트레일명>  # AWS",
                "az monitor diagnostic-settings list --resource <리소스ID>  # Azure",
                "gcloud logging sinks list  # GCP",
            ],
        },
    ],
    "csp_assessment": [
        {
            "domain": "정보보호 정책 및 조직",
            "where": "CSP 공식 Trust/Compliance 센터(AWS: aws.amazon.com/compliance, Azure: azure.microsoft.com/trust-center, GCP: cloud.google.com/security/compliance)에 공개된 정보보호 정책·ISMS/ISO27001 인증서",
            "how": "계약 전 단계라면 RFP(제안요청서) 질의 항목에 '정보보호 조직도·정책 문서 제공'을 명시해 요청하세요.",
        },
        {
            "domain": "인적 보안",
            "where": "CSP가 제공하는 보안 백서(Security Whitepaper) 또는 SOC 2 Type II 리포트의 인적 보안(HR Security) 섹션",
            "how": "직원 채용 시 배경조사 여부, 보안 교육 주기, 퇴사자 접근권한 회수 절차 등을 SOC 2 리포트에서 확인하거나 RFP로 질의하세요.",
        },
        {
            "domain": "자산관리",
            "where": "SOC 2 Type II 리포트 또는 ISO 27001 인증서의 적용범위(Statement of Applicability, Annex A.8 자산관리)",
            "how": "인증서만으로는 세부 내용이 없으므로, 자산 분류·폐기 절차는 보안 백서나 RFP 질의로 보완하세요.",
        },
        {
            "domain": "서비스 공급망 관리",
            "where": "CSP의 서브프로세서(Subprocessor) 공개 페이지 — 대형 CSP는 대부분 공식 페이지로 운영 중(예: AWS/Azure/GCP 각각 'Subprocessors' 또는 '하위처리자' 명칭으로 검색)",
            "how": "재위탁업체 목록·변경 시 사전통지 절차가 계약서/약관에 명시돼 있는지 확인하세요. 목록에 없는 재위탁이 의심되면 CSP에 직접 문의하세요.",
        },
        {
            "domain": "침해사고 관리",
            "where": "계약서/SLA(Service Level Agreement)의 보안 사고 통보 조항, CSP Trust Center의 Incident Response 정책 페이지",
            "how": "침해사고 발생 시 통보 시한(예: 24시간/72시간 이내)이 계약서에 명시돼 있는지가 핵심 확인 포인트입니다 — 없다면 계약 갱신 시 반영을 요구하세요.",
        },
        {
            "domain": "접근통제",
            "where": "SOC 2 Type II 리포트의 Logical Access 섹션 — CSP 직원이 고객 데이터에 접근하는 절차와 통제",
            "how": "CSP 직원의 고객 환경 접근이 최소 권한·승인 절차·로깅을 거치는지가 리포트에 나와 있는지 확인하세요.",
        },
        {
            "domain": "암호화 및 키 관리",
            "where": "CSP 공식 문서의 암호화 옵션 안내(저장/전송 구간 암호화 기본 적용 여부, 고객 관리 키(CMK)/HSM 지원 여부)",
            "how": "AWS/Azure/GCP 모두 암호화 관련 공식 문서를 제공합니다 — '<CSP명> encryption at rest/in transit whitepaper'로 검색하면 찾을 수 있습니다.",
        },
        {
            "domain": "보안모니터링",
            "where": "CSP의 보안운영센터(SOC)·위협 탐지 체계 설명 — 보안 백서 또는 RFP 질의",
            "how": "CSP 자체 인프라에 대한 24/7 모니터링 체계가 있는지, 이상 징후 발견 시 고객에게 알리는 절차가 있는지 확인하세요.",
        },
        {
            "domain": "물리적 보안",
            "where": "데이터센터 관련 인증서(ISO 27001, SOC 2, PCI-DSS 등) — 일부 CSP는 NDA 하에 데이터센터 실사·문서를 추가 제공",
            "how": "인증서 자체보다는 인증서가 실제로 이용 중인 리전/데이터센터를 포함하는지 범위(scope)를 확인하는 것이 중요합니다.",
        },
        {
            "domain": "비즈니스 연속성",
            "where": "CSP 공식 SLA 문서의 가용성(Uptime) 수치, 멀티 리전/가용영역 구성 안내, DR(재해복구) 정책 문서",
            "how": "SLA 미달 시 보상(서비스 크레딧) 조항과 함께, 실제 이용 중인 서비스가 멀티 AZ/리전으로 구성돼 있는지 자체 콘솔에서도 대조 확인하세요.",
        },
        {
            "domain": "사고 보고 및 분석",
            "where": "CSP의 공개 Status Page(과거 장애 이력) — 예: status.aws.amazon.com, status.azure.com, status.cloud.google.com — 및 CSP가 발행하는 투명성 보고서(Transparency Report)",
            "how": "과거 대형 장애/침해 발생 시 CSP의 대응 시간과 사후 보고(Post-mortem) 공개 여부를 확인하세요.",
        },
    ],
}
