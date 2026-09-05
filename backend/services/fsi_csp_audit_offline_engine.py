"""App 24(금융보안원 클라우드 CSP 평가)의 오프라인(폐쇄망) 모드 — 이 앱의 입력은 구조화된
설정이 아니라 서술형 텍스트라, 도메인별 키워드 부재/존재 기반 휴리스틱으로 점검한다.
하드코딩 시크릿은 App 19 secret_scanner_service를 재사용."""
import re

from services.secret_scanner_service import scan_text as _scan_secrets
from services.fsi_csp_audit_guide import ASSESSMENT_TYPES

# 각 issue_type을 어떤 도메인에 귀속시킬지 — 평가 유형별 도메인 목록이 서로 달라(11개/5개)
# assessment_type마다 별도 매핑을 둔다. 값은 ASSESSMENT_TYPES[...]["domains"]의 실제 한글 이름과
# 정확히 일치해야 한다(AI 프롬프트도 "verbatim"으로 요구하는 것과 동일한 제약).
_DOMAIN_MAP = {
    "csp_assessment": {
        "policy_gap": "정보보호 정책 및 조직",
        "access_control_weakness": "접근통제",
        "encryption_gap": "암호화 및 키 관리",
        "monitoring_gap": "보안모니터링",
        "incident_response_gap": "침해사고 관리",
        "continuity_gap": "비즈니스 연속성",
        "supply_chain_risk": "서비스 공급망 관리",
        "physical_security_gap": "물리적 보안",
        "compliance_gap": "사고 보고 및 분석",
    },
    "cloud_env_management": {
        "policy_gap": "가상자원 관리",
        "access_control_weakness": "계정 및 권한 관리",
        "encryption_gap": "암호키 관리",
        "monitoring_gap": "로깅 및 모니터링 관리",
        "incident_response_gap": "로깅 및 모니터링 관리",
        "continuity_gap": "가상자원 관리",
        "compliance_gap": "네트워크 관리",
        # supply_chain_risk/physical_security_gap: cloud_env_management의 5개 도메인엔 대응 항목이
        # 없어 이 평가 유형에서는 검사하지 않는다(아래 로직에서 스킵).
    },
}


def _mk(domain: str, rule_reference: str, issue_type: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "domain": domain,
        "rule_reference": rule_reference.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


def analyze_offline(assessment_type: str, content: str, context: str) -> dict:
    domain_map = _DOMAIN_MAP.get(assessment_type, _DOMAIN_MAP["cloud_env_management"])
    findings: list[dict] = []

    def add(issue_type: str, rule_reference: str, severity: str, description: str, recommendation: str):
        domain = domain_map.get(issue_type)
        if domain is None:
            return  # 이 평가 유형의 도메인 목록에 대응 항목이 없으면 검사 스킵
        findings.append(_mk(domain, rule_reference, issue_type, severity, description, recommendation))

    if re.search(r"통보\s*시한\s*미명시|시한이?\s*(?:정의되지|명시되지)\s*않", content):
        add("incident_response_gap", "침해사고 통보 관련 서술", "HIGH",
            "침해사고 통보 시한이 명시되지 않은 것으로 보입니다.",
            "전자금융감독규정 등에서 요구하는 통보 시한을 명확히 문서화하세요.")
    elif not re.search(r"침해사고|사고\s*대응|incident", content, re.I):
        add("incident_response_gap", "전체 서술", "MEDIUM",
            "침해사고 대응/통보 절차에 대한 언급이 전혀 없습니다.",
            "침해사고 탐지-통보-조치 절차와 시한을 명문화하세요.")

    if re.search(r"0\.0\.0\.0/0|모든\s*IP|전체\s*공개|전체\s*허용", content):
        add("access_control_weakness", "네트워크/접근 관련 서술", "CRITICAL",
            "DB 또는 관리 콘솔 등이 전체 IP에 공개된 것으로 보입니다.",
            "접근 가능 IP를 화이트리스트로 제한하세요.")
    if re.search(r"MFA\s*미적용|다단계\s*인증\s*미적용|MFA\s*not\s*enabled", content, re.I):
        add("access_control_weakness", "인증 관련 서술", "HIGH",
            "관리 콘솔에 다단계 인증(MFA)이 적용되지 않은 것으로 보입니다.",
            "모든 관리자 계정에 MFA를 강제 적용하세요.")

    secret_findings = _scan_secrets(content).get("findings", [])
    for f in secret_findings:
        add("encryption_gap", f"{f['line']}번째 줄", f["severity"],
            f"{f['pattern_label']}(으)로 추정되는 값이 하드코딩되어 있습니다 (마스킹됨: {f['matched_masked']}).",
            f["recommendation"])
    if re.search(r"평문\s*저장|암호화\s*미적용|암호화되지\s*않", content):
        add("encryption_gap", "암호화 관련 서술", "HIGH",
            "민감 정보가 평문으로 저장되거나 암호화가 적용되지 않은 것으로 보입니다.",
            "저장 데이터 암호화 및 키 관리 절차를 도입하세요.")

    if not re.search(r"로그|모니터링|logging|monitoring|알림", content, re.I):
        add("monitoring_gap", "전체 서술", "MEDIUM",
            "로깅/모니터링 체계에 대한 언급이 전혀 없습니다.",
            "실시간 보안 모니터링과 로그 보관 정책을 수립하세요.")

    if not re.search(r"BCP|RTO|RPO|재해\s*복구|업무연속성|비즈니스\s*연속성", content, re.I):
        add("continuity_gap", "전체 서술", "MEDIUM",
            "재해복구(BCP)/RTO/RPO 등 비즈니스 연속성 관련 내용이 없습니다.",
            "RTO/RPO 목표치를 포함한 BCP를 수립하고 주기적으로 테스트하세요.")

    if re.search(r"재위탁\s*미공개|하도급.*확인되지\s*않", content):
        add("supply_chain_risk", "공급망 관련 서술", "HIGH",
            "재위탁/하도급업체 현황이 공개되지 않은 것으로 보입니다.",
            "재위탁 현황을 투명하게 공개하고 계약서에 보안 요구사항을 반영하세요.")
    elif not re.search(r"재위탁|하도급|제3자|subcontractor", content, re.I):
        add("supply_chain_risk", "전체 서술", "LOW",
            "재위탁/하도급/제3자 접근 관련 언급이 전혀 없습니다.",
            "공급망 관리 현황을 명시하세요.")

    if not re.search(r"정보보호\s*정책|운영\s*절차|보안\s*조직", content):
        add("policy_gap", "전체 서술", "LOW",
            "정보보호 정책/조직 체계에 대한 언급이 보이지 않습니다.",
            "정보보호 정책과 담당 조직 체계를 문서화하세요.")

    if assessment_type == "csp_assessment" and not re.search(r"물리적\s*보안|데이터센터|data\s*center", content, re.I):
        add("physical_security_gap", "전체 서술", "LOW",
            "데이터센터 등 물리적 보안에 대한 확인 내용이 없습니다.",
            "CSP의 데이터센터 물리적 보안 인증(예: ISO 27001) 여부를 확인하세요.")

    if not findings:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위험 키워드 패턴이 발견되지 않았습니다. 이 엔진이 모르는 문제는 놓칠 수 있습니다."
        overall_risk = "INFO"
    else:
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        if crit:
            summary = f"규칙 기반 오프라인 분석에서 심각(CRITICAL) {crit}건을 포함해 총 {len(findings)}건의 문제가 발견됐습니다."
            overall_risk = "CRITICAL"
        elif high:
            summary = f"규칙 기반 오프라인 분석에서 높음(HIGH) {high}건을 포함해 총 {len(findings)}건의 문제가 발견됐습니다."
            overall_risk = "HIGH"
        else:
            summary = f"규칙 기반 오프라인 분석에서 총 {len(findings)}건의 개선 사항이 발견됐습니다."
            overall_risk = "MEDIUM"

    return {
        "summary": summary,
        "overall_risk": overall_risk,
        "findings": findings,
        "compliance_notes": [],
        "engine_note": (
            "이 결과는 네트워크 연결 없이 동작하는 규칙 기반 오프라인 분석 엔진이 생성했습니다 — "
            "AI가 아니라 서술형 텍스트의 키워드 존재/부재 매칭 결과이므로 AI 분석보다 정확도와 "
            "탐지 범위가 훨씬 좁습니다(예: 실제로 잘 되어 있어도 관련 단어가 없으면 미비로 표시될 "
            "수 있음). 인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 강력히 "
            "권장하며, 공식 평가는 반드시 금융보안원 자료를 확인하세요."
        ),
    }
