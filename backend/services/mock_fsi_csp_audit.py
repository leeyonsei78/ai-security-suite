"""금융보안원 클라우드 CSP 평가 Mock 데이터. App 16(firewall_audit)/App 18(iam_audit)와
동일한 스키마를 쓰되, `domain` 필드로 어느 분야(11개 또는 5개 중)에 해당하는지 표시한다."""

_TEMPLATES = {
    "csp_assessment": {
        "summary": (
            "해당 CSP는 인증(ISMS/ISO 27001 등) 자체는 보유하고 있으나, 침해사고 발생 시 금융회사에 "
            "통보하는 절차와 시간(SLA)이 계약서에 명시돼 있지 않고, 하도급(재위탁) 업체 목록도 "
            "공개되지 않아 공급망 리스크를 확인할 수 없습니다. 접근통제 분야의 관리자 권한 분리도 "
            "미흡해 종합적으로 개선이 필요한 상태입니다."
        ),
        "overall_risk": "HIGH",
        "findings": [
            {
                "domain": "침해사고 관리",
                "rule_reference": "계약서 제12조(보안사고 대응) — \"사고 발생 시 지체없이 통보한다\"",
                "issue_type": "incident_response_gap",
                "severity": "CRITICAL",
                "description": "\"지체없이\"라는 표현만 있고 구체적인 통보 시한(예: 24시간 이내)·통보 채널·1차 보고 항목이 명시돼 있지 않습니다. 실제 사고 시 금융회사가 감독당국 보고 기한(전자금융감독규정상 통상 24시간)을 지키지 못할 위험이 있습니다.",
                "recommendation": "계약서에 침해사고 인지 후 통보 시한(예: 인지 후 24시간 이내 1차 통보)과 통보 방법(전용 연락 채널·담당자)을 명문화하도록 CSP와 재협의하세요.",
            },
            {
                "domain": "서비스 공급망 관리",
                "rule_reference": "CSP 자가진단 응답 — \"일부 운영 업무는 협력사에 위탁\" (업체명·위탁범위 미기재)",
                "issue_type": "supply_chain_risk",
                "severity": "HIGH",
                "description": "재위탁(하도급) 업체의 명칭·위탁 범위·보안 수준이 확인되지 않습니다. 금융분야는 재위탁 현황을 파악하지 못하면 실제 데이터 접근 주체를 특정할 수 없어 사고 발생 시 책임 소재 확인이 어렵습니다.",
                "recommendation": "CSP에 재위탁 업체 목록과 각 업체의 접근 가능 범위·보안 서약 현황을 요청하고, 계약서에 재위탁 시 사전 통보·승인 조항을 추가하세요.",
            },
            {
                "domain": "접근통제",
                "rule_reference": "CSP 운영 조직도 — 인프라 운영팀이 고객사 데이터 접근 권한과 감사 로그 열람 권한을 동시 보유",
                "issue_type": "access_control_weakness",
                "severity": "HIGH",
                "description": "운영자가 자신의 접근 기록이 담긴 감사 로그까지 직접 열람·관리할 수 있어 직무 분리(Segregation of Duties)가 되지 않습니다. 부정 접근이 있어도 스스로 로그를 확인·수정할 수 있는 구조입니다.",
                "recommendation": "감사 로그의 열람·보관 권한은 운영팀과 분리된 별도 조직(보안팀 또는 제3자)에 부여하도록 CSP의 조직 체계 개선을 요구하거나, 최소한 로그의 별도 보관(이관) 여부를 확인하세요.",
            },
            {
                "domain": "비즈니스 연속성",
                "rule_reference": "SLA 문서 — 가용성 목표 \"99.9%\", DR(재해복구) 리전 명시 없음",
                "issue_type": "continuity_gap",
                "severity": "MEDIUM",
                "description": "가용성 수치 목표는 있으나 실제 재해복구 리전·RTO(목표복구시간)/RPO(목표복구시점)가 SLA에 명시돼 있지 않아, 리전 단위 장애 시 실제 복구 소요 시간을 예측할 수 없습니다.",
                "recommendation": "SLA에 DR 리전 위치, RTO/RPO 수치, 연 1회 이상의 DR 모의훈련 결과 공유 조항을 추가하도록 요청하세요.",
            },
            {
                "domain": "정보보호 정책 및 조직",
                "rule_reference": "CSP 자가진단 응답 — 최고정보보호책임자(CISO) 지정 여부 \"확인 불가\"",
                "issue_type": "policy_gap",
                "severity": "MEDIUM",
                "description": "정보보호 총괄 책임자의 지정 여부와 권한 범위가 확인되지 않아, 보안 관련 의사결정 체계의 신뢰성을 판단하기 어렵습니다.",
                "recommendation": "CSP에 정보보호 책임자 지정 현황과 조직 내 위상(경영진 직속 여부 등)을 서면으로 요청해 확인하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "전자금융감독규정", "note": "제34조의2 등 클라우드컴퓨팅서비스 이용 관련 안전성 확보조치 요건과 침해사고 통보 관련 조항 충족 여부를 재점검할 필요가 있습니다."},
            {"framework": "금융보안원 CSP 안전성평가", "note": "침해사고 관리·서비스 공급망 관리 분야는 필수 항목이 포함될 가능성이 높은 분야로, 공식 평가지에서 별도 확인이 필요합니다."},
        ],
    },
    "cloud_env_management": {
        "summary": (
            "가상자원과 네트워크 분리는 기본적인 수준은 갖췄으나, 암호화 키를 애플리케이션 코드에 "
            "직접 하드코딩하고 있고 관리 콘솔 접근에 IP 제한이나 MFA가 걸려 있지 않습니다. "
            "로그 보관 기간도 금융권 권고 기준(최소 1년~2년 수준)에 못 미쳐 사고 발생 시 원인 추적이 "
            "제한적일 수 있습니다."
        ),
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "domain": "암호키 관리",
                "rule_reference": "application.yml — `db.password: ${DB_PASSWORD:P@ssw0rd2024}` (환경변수 기본값으로 평문 하드코딩)",
                "issue_type": "encryption_gap",
                "severity": "CRITICAL",
                "description": "DB 접속 비밀번호가 설정 파일에 평문 기본값으로 박혀 있습니다. 소스 저장소나 이미지가 유출되면 즉시 DB 접근이 가능합니다. 별도의 키 관리 서비스(KMS/Secrets Manager)를 쓰고 있지 않습니다.",
                "recommendation": "비밀값은 클라우드 KMS/Secrets Manager에 저장하고 런타임에만 주입하도록 변경하세요. 코드/설정 파일에는 어떤 형태로도 평문 기본값을 남기지 마세요.",
            },
            {
                "domain": "계정 및 권한 관리",
                "rule_reference": "관리 콘솔 로그인 정책 — MFA \"선택\", 접근 가능 IP 대역 제한 없음",
                "issue_type": "access_control_weakness",
                "severity": "CRITICAL",
                "description": "클라우드 관리 콘솔에 전 세계 어디서든 비밀번호만으로 로그인할 수 있습니다. 자격증명이 유출되면 전체 인프라가 그대로 노출됩니다.",
                "recommendation": "관리 콘솔 로그인에 MFA를 강제하고, 가능하면 사내 VPN/고정 IP 대역에서만 콘솔 접근을 허용하는 조건부 접근 정책을 적용하세요.",
            },
            {
                "domain": "로깅 및 모니터링 관리",
                "rule_reference": "로그 보관 정책 — CloudTrail/Activity Log 보관기간 30일, 별도 이관 없음",
                "issue_type": "monitoring_gap",
                "severity": "HIGH",
                "description": "감사 로그 보관 기간이 30일로 짧아, 사고 인지 시점이 한 달을 넘기면 원인 추적에 필요한 로그가 이미 삭제되어 있을 수 있습니다. 금융권은 통상 더 긴 보관 기간을 권고합니다.",
                "recommendation": "로그를 별도의 장기보관 스토리지(WORM 옵션 등 변경 방지 저장소 권장)로 이관해 최소 1년 이상 보관하고, 실시간 이상탐지(SIEM 연동)도 함께 검토하세요.",
            },
            {
                "domain": "네트워크 관리",
                "rule_reference": "보안그룹 `db-sg` — Inbound 3306/tcp Source: 0.0.0.0/0",
                "issue_type": "access_control_weakness",
                "severity": "CRITICAL",
                "description": "데이터베이스 포트가 인터넷 전체에 열려 있습니다. 스캐너에 의해 즉시 발견되는 가장 흔한 침해 경로 중 하나입니다.",
                "recommendation": "DB 보안그룹의 Source를 애플리케이션 서버의 보안그룹/사설 IP 대역으로 한정하고, 가능하면 DB를 프라이빗 서브넷에만 배치하세요.",
            },
            {
                "domain": "가상자원 관리",
                "rule_reference": "VM 인벤토리 — 태그(Tag)/소유자 필드 미기재 인스턴스 다수, 사용 목적 불명 인스턴스 2대 실행 중",
                "issue_type": "compliance_gap",
                "severity": "MEDIUM",
                "description": "소유자·용도가 기록되지 않은 가상자원이 다수 발견됩니다. 자산 인벤토리가 정확하지 않으면 불필요한 리소스가 방치돼 공격 표면이 될 수 있고, 실제 자산 현황 파악(금융보안원 평가의 전제 조건)이 어렵습니다.",
                "recommendation": "모든 가상자원에 소유자·용도·생성일 태그를 의무화하고, 정기적으로(예: 분기별) 미사용/미상 리소스를 점검해 정리하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "금융분야 클라우드서비스 이용 가이드라인", "note": "네트워크 관리·계정 및 권한 관리 분야의 기준 미준수 소지가 있어 재점검이 필요합니다."},
            {"framework": "개인정보보호법", "note": "고객 개인정보가 포함된 DB가 인터넷에 노출된 경우 안전조치 의무 위반 소지가 있습니다."},
        ],
    },
}


def generate_mock_audit(assessment_type: str, content: str, context: str) -> dict:
    import copy
    template = _TEMPLATES.get(assessment_type, _TEMPLATES["cloud_env_management"])
    return copy.deepcopy(template)
