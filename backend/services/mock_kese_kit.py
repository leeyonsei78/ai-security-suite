"""App 26(KISA 보안 가이드라인 종합 점검) Mock 데이터. App 24(fsi_csp_audit)와 동일한 스키마를
쓰되, 7개 평가 유형(cii/ai_security/robot_security/space_security/secure_coding/zero_trust/
supply_chain) 각각에 대해 큐레이션된 샘플 1건씩을 제공한다."""

_TEMPLATES = {
    "cii": {
        "summary": (
            "Unix 서버의 root 원격 접속이 허용되어 있고 패스워드 정책도 미설정 상태이며, 클라우드 "
            "환경의 보안그룹이 SSH 포트를 전체 공개하고 있습니다. 관리적 취약점 측면에서도 정보보호 "
            "책임자 지정 여부가 확인되지 않아 종합적인 개선이 필요합니다."
        ),
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "domain": "Unix/Linux 서버",
                "rule_reference": "sshd_config — `PermitRootLogin yes`",
                "issue_type": "access_control_gap",
                "severity": "CRITICAL",
                "description": "root 계정으로 SSH 원격 로그인이 허용되어 있습니다. 무차별 대입 공격 시 즉시 최고 권한이 탈취될 수 있습니다.",
                "recommendation": "PermitRootLogin을 no로 변경하고, 일반 계정으로 로그인 후 sudo를 사용하도록 전환하세요.",
            },
            {
                "domain": "Unix/Linux 서버",
                "rule_reference": "/etc/login.defs — PASS_MAX_DAYS/PASS_MIN_LEN 항목 미설정",
                "issue_type": "access_control_gap",
                "severity": "HIGH",
                "description": "패스워드 최대 사용기간과 최소 길이 정책이 설정되어 있지 않아, 약하거나 오래된 패스워드가 방치될 수 있습니다.",
                "recommendation": "PASS_MAX_DAYS(예: 90일), PASS_MIN_LEN(예: 8자 이상)을 설정하고 기존 계정에도 적용하세요.",
            },
            {
                "domain": "클라우드",
                "rule_reference": "보안그룹 `web-sg` — Inbound 22/tcp Source: 0.0.0.0/0",
                "issue_type": "network_segmentation_gap",
                "severity": "CRITICAL",
                "description": "SSH 포트가 인터넷 전체에 열려 있어 스캐너에 의해 즉시 발견되는 흔한 침해 경로입니다.",
                "recommendation": "Source를 사내 고정 IP 대역이나 VPN 대역으로 제한하세요.",
            },
            {
                "domain": "관리적 취약점(14개 영역)",
                "rule_reference": "자가진단 응답 — 정보보호 책임자(CISO) 지정 여부 \"확인 불가\"",
                "issue_type": "governance_policy_gap",
                "severity": "MEDIUM",
                "description": "정보보호 총괄 책임자 지정 여부가 확인되지 않아 보안 의사결정 체계의 신뢰성을 판단하기 어렵습니다.",
                "recommendation": "정보보호 책임자 지정 현황과 조직 내 위상을 문서화하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "정보통신기반 보호법", "note": "주요정보통신기반시설로 지정된 경우 매년 기술적 취약점 분석·평가를 실시하고 결과를 관계기관에 제출해야 합니다."},
        ],
    },
    "ai_security": {
        "summary": (
            "모델 학습 데이터의 출처 검증 절차가 문서화되어 있지 않고, 배포 전 적대적 예제 테스트도 "
            "수행되지 않고 있습니다. API 키가 클라이언트 코드에 노출되어 있어 접근통제 측면의 보완도 "
            "필요합니다."
        ),
        "overall_risk": "HIGH",
        "findings": [
            {
                "domain": "AI 개발자 (6단계: 계획→데이터→모델개발→배포→모니터링→파기)",
                "rule_reference": "데이터 관리 문서 — 학습 데이터셋 출처 검증 절차 기재 없음",
                "issue_type": "governance_policy_gap",
                "severity": "HIGH",
                "description": "학습 데이터의 출처·수집 방식이 검증되지 않으면 데이터 오염(poisoning)이나 저작권/개인정보 문제가 모델에 그대로 반영될 수 있습니다.",
                "recommendation": "데이터셋 출처·라이선스·개인정보 포함 여부를 검증하는 절차를 데이터 수집 단계에 명문화하세요.",
            },
            {
                "domain": "AI 개발자 (6단계: 계획→데이터→모델개발→배포→모니터링→파기)",
                "rule_reference": "배포 전 점검 체크리스트 — 적대적 예제(adversarial example) 테스트 항목 없음",
                "issue_type": "governance_policy_gap",
                "severity": "MEDIUM",
                "description": "모델이 조작된 입력에 취약한지 사전에 검증하지 않고 배포하면, 운영 중 회피 공격에 노출될 수 있습니다.",
                "recommendation": "배포 전 체크리스트에 적대적 강건성(adversarial robustness) 테스트 항목을 추가하세요.",
            },
            {
                "domain": "AI 서비스 제공자 (6단계: 계획→개발→운영→유지보수→피드백→파기)",
                "rule_reference": "프론트엔드 코드 — API 키가 클라이언트 JS에 하드코딩됨",
                "issue_type": "access_control_gap",
                "severity": "CRITICAL",
                "description": "브라우저에서 API 키가 그대로 노출되어 누구나 개발자도구로 키를 탈취해 비용을 유발하거나 서비스를 오남용할 수 있습니다.",
                "recommendation": "API 키는 서버 사이드에서만 사용하고, 클라이언트는 인증된 세션을 통해 백엔드를 경유하도록 아키텍처를 변경하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "인공지능 기본법", "note": "고영향 AI 시스템에 해당하는 경우 안전성·신뢰성 확보조치 의무가 적용될 수 있습니다."},
        ],
    },
    "robot_security": {
        "summary": (
            "로봇 제어 인터페이스의 기본 비밀번호가 변경되지 않은 채 운영되고 있고, 펌웨어 업데이트 시 "
            "서명 검증도 수행되지 않습니다. 무선 통신 구간의 암호화도 확인되지 않아 원격 탈취 위험이 "
            "있습니다."
        ),
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "domain": "식별 및 인증",
                "rule_reference": "제어 인터페이스 계정 — 출고 시 기본 계정/비밀번호(admin/admin) 그대로 사용 중",
                "issue_type": "access_control_gap",
                "severity": "CRITICAL",
                "description": "기본 자격증명이 변경되지 않아 인터넷에서 흔히 스캔되는 기본 비밀번호 목록만으로도 제어권이 탈취될 수 있습니다.",
                "recommendation": "초기 설정 시 기본 비밀번호 변경을 강제하고, 가능하면 인증서 기반 인증으로 전환하세요.",
            },
            {
                "domain": "시스템 무결성",
                "rule_reference": "펌웨어 업데이트 절차 — 서명 검증 단계 없음",
                "issue_type": "patch_hardening_gap",
                "severity": "HIGH",
                "description": "펌웨어 업데이트 시 서명을 검증하지 않으면 변조된 펌웨어가 설치되어 로봇이 공격자에게 완전히 장악될 수 있습니다.",
                "recommendation": "펌웨어 업데이트 파이프라인에 코드 서명 및 검증 단계를 추가하세요(NIST SP 800-218 SSDF 참고).",
            },
            {
                "domain": "무선 보안",
                "rule_reference": "제어 통신 프로토콜 — 무선 구간 암호화 설정 확인 불가",
                "issue_type": "network_segmentation_gap",
                "severity": "HIGH",
                "description": "무선 제어 통신이 암호화되지 않으면 중간자 공격으로 제어 명령이 탈취·변조될 수 있습니다.",
                "recommendation": "무선 구간에 WPA3 또는 애플리케이션 레벨 암호화(TLS)를 적용하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "IEC 62443", "note": "산업용 로봇의 식별·인증(IA), 시스템 무결성(SI) 요구사항에 해당하는 항목입니다."},
        ],
    },
    "space_security": {
        "summary": (
            "지상국의 위성 명령 전송 채널에 대한 접근통제가 계정/비밀번호 수준에 그쳐 있고, 원격측정 "
            "데이터도 평문으로 전송되고 있습니다. 공급망 부품의 출처 검증 절차 또한 문서화되어 있지 "
            "않습니다."
        ),
        "overall_risk": "HIGH",
        "findings": [
            {
                "domain": "접근통제",
                "rule_reference": "지상국 명령 전송 시스템 — 계정/비밀번호 인증만 적용, MFA 없음",
                "issue_type": "access_control_gap",
                "severity": "CRITICAL",
                "description": "위성에 명령을 전송하는 시스템이 단일 요소 인증만 사용하고 있어, 자격증명 유출 시 위성 제어권이 탈취될 수 있습니다.",
                "recommendation": "지상국 명령 전송 시스템에 다단계 인증(MFA)과 역할 기반 접근통제를 적용하세요.",
            },
            {
                "domain": "시스템 및 통신 보안",
                "rule_reference": "원격측정(telemetry) 링크 — 암호화 미적용",
                "issue_type": "encryption_key_gap",
                "severity": "HIGH",
                "description": "원격측정 데이터가 평문으로 전송되면 도청을 통해 위성 상태 정보가 유출되거나, 향후 명령 위조의 단서가 될 수 있습니다.",
                "recommendation": "원격측정·명령 링크 모두에 표준 암호화(예: CCSDS 보안 프로토콜)를 적용하세요.",
            },
            {
                "domain": "공급망 관리",
                "rule_reference": "부품 조달 기록 — 출처 검증 절차 문서 없음",
                "issue_type": "supply_chain_gap",
                "severity": "MEDIUM",
                "description": "위성/지상국 부품의 출처가 검증되지 않으면 변조된 부품이 시스템에 유입될 위험을 배제할 수 없습니다.",
                "recommendation": "공급망 부품 출처 검증 절차를 수립하고 조달 기록을 문서화하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "K-RMF", "note": "접근통제 및 시스템/통신 보안 분야는 우주 보안모델의 핵심 점검 영역입니다."},
        ],
    },
    "secure_coding": {
        "summary": (
            "사용자 입력을 검증 없이 SQL 쿼리에 직접 연결하는 패턴과, 비밀번호를 평문 비교하는 로직이 "
            "발견됐습니다. 에러 메시지에 스택 트레이스가 그대로 노출되는 문제도 있습니다."
        ),
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "domain": "입력데이터 검증 및 표현",
                "rule_reference": "query = \"SELECT * FROM users WHERE id='\" + user_id + \"'\"",
                "issue_type": "secure_coding_flaw",
                "severity": "CRITICAL",
                "description": "사용자 입력이 검증·이스케이프 없이 SQL 쿼리 문자열에 직접 연결됩니다(CWE-89 SQL Injection).",
                "recommendation": "Prepared Statement 또는 ORM의 파라미터 바인딩으로 교체하세요.",
            },
            {
                "domain": "보안기능",
                "rule_reference": "if password == stored_password:",
                "issue_type": "secure_coding_flaw",
                "severity": "HIGH",
                "description": "비밀번호를 평문으로 저장·비교하고 있습니다(CWE-256). 데이터베이스 유출 시 모든 계정 비밀번호가 그대로 노출됩니다.",
                "recommendation": "bcrypt/scrypt/Argon2 등 솔트를 포함한 단방향 해시로 저장하고 비교하세요.",
            },
            {
                "domain": "에러처리",
                "rule_reference": "except Exception as e: return str(e), 500",
                "issue_type": "secure_coding_flaw",
                "severity": "MEDIUM",
                "description": "예외의 상세 내용(스택 트레이스 포함 가능)이 그대로 사용자 응답에 노출됩니다(CWE-209). 내부 구조 정보가 공격자에게 유출될 수 있습니다.",
                "recommendation": "사용자에게는 일반화된 에러 메시지만 반환하고, 상세 내용은 서버 로그에만 기록하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "CWE/SANS Top 25", "note": "SQL Injection(CWE-89)과 평문 비밀번호 저장(CWE-256)은 CWE Top 25에 포함되는 고위험 패턴입니다."},
        ],
    },
    "zero_trust": {
        "summary": (
            "사내 네트워크가 평면(flat) 구조로 세그먼트 분리가 되어 있지 않고, 관리자 계정에 MFA가 "
            "적용되지 않았습니다. 중앙화된 로그 수집·가시성 체계도 없어 전반적으로 '기존(Traditional)' "
            "성숙도 단계에 머물러 있습니다."
        ),
        "overall_risk": "HIGH",
        "findings": [
            {
                "domain": "식별자·신원",
                "rule_reference": "관리자 계정 인증 정책 — MFA 미적용",
                "issue_type": "access_control_gap",
                "severity": "CRITICAL",
                "description": "관리자 계정이 비밀번호만으로 인증되고 있어, 자격증명 유출 시 즉시 전체 권한이 탈취됩니다. 제로트러스트의 '신원을 지속적으로 검증한다'는 원칙에 위배됩니다.",
                "recommendation": "모든 관리자·권한 계정에 MFA를 강제 적용하고, 가능하면 조건부 접근 정책(디바이스 상태·위치 기반)을 도입하세요.",
            },
            {
                "domain": "네트워크",
                "rule_reference": "네트워크 구성도 — 전체 사내망이 단일 VLAN으로 구성",
                "issue_type": "network_segmentation_gap",
                "severity": "HIGH",
                "description": "네트워크가 세그먼트로 분리되어 있지 않아, 한 단말이 침해되면 마이크로세그멘테이션 없이 전체 네트워크로 공격이 확산될 수 있습니다. 현재 성숙도는 '기존(Traditional)' 단계입니다.",
                "recommendation": "업무/자산 중요도에 따라 네트워크를 세그먼트로 분리하고, 장기적으로 마이크로세그멘테이션(소프트웨어 정의 경계)을 도입하세요 — '초기(Initial)' 단계로의 전환을 목표로 하세요.",
            },
            {
                "domain": "가시성·분석",
                "rule_reference": "로그 수집 현황 — 중앙화된 SIEM/로그 수집 체계 없음, 서버별 개별 로그만 존재",
                "issue_type": "logging_monitoring_gap",
                "severity": "MEDIUM",
                "description": "로그가 중앙에서 상관분석되지 않아, 여러 시스템에 걸친 공격 패턴을 실시간으로 탐지하기 어렵습니다.",
                "recommendation": "SIEM 또는 중앙 로그 수집 체계를 도입해 신원·기기·네트워크 로그를 상관분석하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "제로트러스트 가이드라인 2.0", "note": "식별자·신원, 네트워크는 8개 핵심요소 중 가장 먼저 성숙도를 높이도록 권고되는 영역입니다."},
        ],
    },
    "supply_chain": {
        "summary": (
            "SBOM(소프트웨어 구성요소 명세서)을 생성하지 않고 있어 사용 중인 오픈소스의 전체 목록을 "
            "파악할 수 없습니다. CI/CD 파이프라인에 취약점 스캔 단계도 없고, 배포 아티팩트에 대한 서명 "
            "검증도 이뤄지지 않고 있습니다."
        ),
        "overall_risk": "HIGH",
        "findings": [
            {
                "domain": "개발 단계",
                "rule_reference": "빌드 파이프라인 — SBOM 생성 단계 없음",
                "issue_type": "supply_chain_gap",
                "severity": "HIGH",
                "description": "SBOM이 없으면 사용 중인 오픈소스 구성요소 전체를 파악할 수 없어, 신규 CVE 발표 시 영향받는 제품을 신속히 식별하기 어렵습니다.",
                "recommendation": "Syft 등으로 빌드 시점에 SBOM(CycloneDX/SPDX 형식)을 자동 생성하도록 CI/CD에 통합하세요.",
            },
            {
                "domain": "개발 단계",
                "rule_reference": "CI/CD 파이프라인 — 의존성 취약점 스캔 단계 없음",
                "issue_type": "patch_hardening_gap",
                "severity": "HIGH",
                "description": "알려진 취약점(CVE)이 있는 의존성이 그대로 빌드·배포될 수 있습니다.",
                "recommendation": "Grype/npm audit/pip-audit 등을 CI/CD 파이프라인에 통합해 취약점 발견 시 빌드를 실패시키세요.",
            },
            {
                "domain": "공급(유통) 단계",
                "rule_reference": "배포 아티팩트 — 코드 서명 및 검증 절차 없음",
                "issue_type": "supply_chain_gap",
                "severity": "MEDIUM",
                "description": "배포되는 패키지/이미지가 서명되지 않으면, 유통 과정에서 변조된 아티팩트를 구분할 수 없습니다.",
                "recommendation": "배포 아티팩트에 디지털 서명을 적용하고, 설치/배포 시 서명 검증을 의무화하세요(예: Sigstore/cosign).",
            },
        ],
        "compliance_notes": [
            {"framework": "NIS-SBOM", "note": "공공조달 납품 시 NIS-SBOM 기본 20개 항목 제출이 요구될 수 있습니다."},
            {"framework": "EU CRA", "note": "2026년 하반기 시행 예정인 EU 사이버복원력법은 SBOM 제공을 요구사항으로 포함합니다."},
        ],
    },
}


def generate_mock_audit(assessment_type: str, content: str, context: str) -> dict:
    import copy
    template = _TEMPLATES.get(assessment_type, _TEMPLATES["cii"])
    return copy.deepcopy(template)
