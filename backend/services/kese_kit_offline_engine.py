"""App 26(KISA 보안 가이드라인 종합 점검)의 오프라인(폐쇄망) 모드 — 7개 평가 유형 각각에 대해
서술형 텍스트/코드의 키워드 존재·부재 및 정규식 패턴으로 점검한다 (App 24
fsi_csp_audit_offline_engine.py와 동일한 접근). 하드코딩 시크릿은 App 19 secret_scanner_service를,
SQLi/XSS/eval 등 코드 패턴은 App 3 vuln_offline_engine의 검증된 정규식을 그대로 재사용해
중복 구현하지 않는다."""
import re

from services.secret_scanner_service import scan_text as _scan_secrets
from services.vuln_offline_engine import (
    _SQL_FSTRING_RE, _SQL_CONCAT_RE, _XSS_RE, _EVAL_EXEC_RE, _WEAK_HASH_RE,
)

ENGINE_NOTE = (
    "이 결과는 네트워크 연결 없이 동작하는 규칙 기반 오프라인 분석 엔진이 생성했습니다 — "
    "AI가 아니라 서술형 텍스트/코드의 키워드·정규식 매칭 결과이므로 AI 분석보다 탐지 범위가 "
    "훨씬 좁습니다(예: 실제로 잘 되어 있어도 관련 단어가 없으면 미비로 표시될 수 있음). "
    "인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 강력히 권장하며, "
    "공식 점검은 반드시 KISA 등 공식 자료를 확인하세요."
)


def _mk(domain: str, rule_reference: str, issue_type: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "domain": domain,
        "rule_reference": rule_reference.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


def _secret_findings(content: str, domain: str) -> list[dict]:
    out = []
    for f in _scan_secrets(content).get("findings", []):
        out.append(_mk(
            domain, f"{f['line']}번째 줄", "encryption_key_gap", f["severity"],
            f"{f['pattern_label']}(으)로 추정되는 값이 하드코딩되어 있습니다 (마스킹됨: {f['matched_masked']}).",
            f["recommendation"],
        ))
    return out


def _check_cii(content: str) -> list[dict]:
    findings = []
    if re.search(r"PermitRootLogin\s+yes", content, re.I):
        findings.append(_mk("Unix/Linux 서버", "sshd_config — PermitRootLogin yes", "access_control_gap", "CRITICAL",
            "root 계정으로 SSH 원격 로그인이 허용되어 있습니다.", "PermitRootLogin을 no로 변경하세요."))
    if re.search(r"telnet", content, re.I) and not re.search(r"telnet\s*(비활성|disabled|사용\s*안\s*함)", content, re.I):
        findings.append(_mk("네트워크 장비", "Telnet 관련 서술", "network_segmentation_gap", "HIGH",
            "암호화되지 않은 Telnet 서비스가 활성화된 것으로 보입니다.", "Telnet을 비활성화하고 SSH로 전환하세요."))
    if re.search(r"0\.0\.0\.0/0|전체\s*공개|전체\s*허용", content):
        findings.append(_mk("클라우드", "네트워크/보안그룹 관련 서술", "network_segmentation_gap", "CRITICAL",
            "관리 포트 또는 서비스가 전체 IP(0.0.0.0/0)에 공개된 것으로 보입니다.", "접근 가능 IP를 화이트리스트로 제한하세요."))
    findings.extend(_secret_findings(content, "Web Application"))
    if re.search(r"vsftpd\s*2\.3\.4|Apache/2\.2\.\d|OpenSSH_[1-5]\.", content):
        findings.append(_mk("Unix/Linux 서버", "서비스 배너 문자열", "patch_hardening_gap", "HIGH",
            "알려진 취약점이 있는 오래된 소프트웨어 버전이 실행 중인 것으로 보입니다.", "해당 소프트웨어를 최신 안정 버전으로 업그레이드하세요."))
    if not re.search(r"출입통제|CCTV|물리적\s*보안|access\s*control\s*(?:system|door)", content, re.I):
        findings.append(_mk("물리적 취약점", "전체 서술", "physical_personnel_gap", "LOW",
            "출입통제/CCTV 등 물리적 보안에 대한 언급이 없습니다.", "서버실 등 주요 시설의 물리적 보안 현황을 점검·문서화하세요."))
    if not re.search(r"정보보호\s*정책|보안\s*조직|정보보호\s*책임자", content):
        findings.append(_mk("관리적 취약점(14개 영역)", "전체 서술", "governance_policy_gap", "LOW",
            "정보보호 정책/조직 체계에 대한 언급이 보이지 않습니다.", "정보보호 정책과 담당 조직 체계를 문서화하세요."))
    return findings


def _check_ai_security(content: str) -> list[dict]:
    findings = []
    dev = "AI 개발자 (6단계: 계획→데이터→모델개발→배포→모니터링→파기)"
    svc = "AI 서비스 제공자 (6단계: 계획→개발→운영→유지보수→피드백→파기)"
    if not re.search(r"데이터\s*검증|데이터셋\s*출처|data\s*validation", content, re.I):
        findings.append(_mk(dev, "전체 서술", "governance_policy_gap", "MEDIUM",
            "학습 데이터 출처·검증 절차에 대한 언급이 없습니다.", "데이터셋 출처·라이선스 검증 절차를 문서화하세요."))
    if not re.search(r"적대적|adversarial", content, re.I):
        findings.append(_mk(dev, "전체 서술", "governance_policy_gap", "LOW",
            "적대적 예제(adversarial) 테스트에 대한 언급이 없습니다.", "배포 전 체크리스트에 적대적 강건성 테스트를 추가하세요."))
    for f in _secret_findings(content, svc):
        f["issue_type"] = "access_control_gap"  # API 키/자격증명 노출은 이 유형에서 접근통제 미흡으로 분류
        findings.append(f)
    if not re.search(r"모니터링|드리프트|drift|monitoring", content, re.I):
        findings.append(_mk(svc, "전체 서술", "logging_monitoring_gap", "MEDIUM",
            "운영 중 모니터링/모델 드리프트 관련 언급이 없습니다.", "이상 사용 탐지와 모델 성능 드리프트 모니터링 체계를 구축하세요."))
    if not re.search(r"이용\s*정책|가이드라인|사용\s*수칙", content):
        findings.append(_mk("AI 이용자 (보안 수칙)", "전체 서술", "governance_policy_gap", "LOW",
            "AI 이용 정책/가이드라인에 대한 언급이 없습니다.", "민감정보 입력 금지 등을 포함한 AI 이용 정책을 수립하세요."))
    return findings


def _check_robot_security(content: str) -> list[dict]:
    findings = []
    if re.search(r"admin\s*/\s*admin|기본\s*비밀번호|default\s*password", content, re.I):
        findings.append(_mk("식별 및 인증", "계정/인증 관련 서술", "access_control_gap", "CRITICAL",
            "기본 계정/비밀번호가 변경되지 않고 그대로 사용 중인 것으로 보입니다.", "초기 설정 시 기본 비밀번호 변경을 강제하세요."))
    if re.search(r"펌웨어", content) and not re.search(r"서명\s*검증|firmware\s*sign", content, re.I):
        findings.append(_mk("시스템 무결성", "펌웨어 관련 서술", "patch_hardening_gap", "HIGH",
            "펌웨어 업데이트 시 서명 검증 절차가 확인되지 않습니다.", "펌웨어 업데이트 파이프라인에 코드 서명·검증 단계를 추가하세요."))
    if re.search(r"무선|wireless", content, re.I) and not re.search(r"암호화|encrypt", content, re.I):
        findings.append(_mk("무선 보안", "무선 통신 관련 서술", "network_segmentation_gap", "HIGH",
            "무선 통신 구간의 암호화 적용 여부가 확인되지 않습니다.", "무선 구간에 WPA3 또는 애플리케이션 레벨 암호화를 적용하세요."))
    if not re.search(r"SBOM|부품\s*목록|부품\s*관리", content, re.I):
        findings.append(_mk("공급망 보안", "전체 서술", "supply_chain_gap", "MEDIUM",
            "부품/구성요소 목록(SBOM) 관리에 대한 언급이 없습니다.", "하드웨어/소프트웨어 부품 목록을 관리하고 출처를 검증하세요."))
    return findings


def _check_space_security(content: str) -> list[dict]:
    findings = []
    if not re.search(r"MFA|다단계\s*인증|multi-factor", content, re.I):
        findings.append(_mk("접근통제", "인증 관련 서술", "access_control_gap", "CRITICAL",
            "지상국/명령 전송 시스템에 다단계 인증(MFA) 적용 여부가 확인되지 않습니다.", "명령 전송 시스템에 MFA와 역할 기반 접근통제를 적용하세요."))
    if re.search(r"평문", content) and re.search(r"원격측정|telemetry", content, re.I):
        findings.append(_mk("시스템 및 통신 보안", "원격측정 관련 서술", "encryption_key_gap", "HIGH",
            "원격측정(telemetry) 데이터가 평문으로 전송되는 것으로 보입니다.", "원격측정·명령 링크에 표준 암호화를 적용하세요."))
    if not re.search(r"공급망|출처\s*검증|supply\s*chain", content, re.I):
        findings.append(_mk("공급망 관리", "전체 서술", "supply_chain_gap", "MEDIUM",
            "부품/공급망 출처 검증 절차에 대한 언급이 없습니다.", "공급망 부품 출처 검증 절차를 수립하고 문서화하세요."))
    if not re.search(r"비상\s*계획|BCP|contingency", content, re.I):
        findings.append(_mk("비상 계획", "전체 서술", "incident_resilience_gap", "LOW",
            "비상 계획(Contingency Plan)에 대한 언급이 없습니다.", "장애/사고 발생 시 대응 절차를 포함한 비상 계획을 수립하세요."))
    return findings


def _check_secure_coding(content: str) -> list[dict]:
    findings = []
    inp = "입력데이터 검증 및 표현"
    if _SQL_FSTRING_RE.search(content) or _SQL_CONCAT_RE.search(content):
        findings.append(_mk(inp, "쿼리 조합 코드", "secure_coding_flaw", "CRITICAL",
            "사용자 입력으로 보이는 값이 문자열 포매팅/연결로 SQL 쿼리에 직접 삽입되는 패턴이 발견됐습니다(CWE-89).",
            "Prepared Statement 또는 ORM의 파라미터 바인딩으로 교체하세요."))
    if _XSS_RE.search(content):
        findings.append(_mk(inp, "출력 처리 코드", "secure_coding_flaw", "HIGH",
            "사용자 입력이 HTML 이스케이프 없이 그대로 출력/삽입되는 패턴이 발견됐습니다(CWE-79).",
            "출력 시 HTML 이스케이프를 적용하거나 innerHTML 대신 textContent를 사용하세요."))
    if _EVAL_EXEC_RE.search(content):
        findings.append(_mk("코드오류", "동적 실행 코드", "secure_coding_flaw", "HIGH",
            "eval()/exec()로 문자열을 코드로 실행하는 패턴이 발견됐습니다(CWE-95).",
            "eval/exec 사용을 제거하고 명시적 파싱 로직으로 대체하세요."))
    if _WEAK_HASH_RE.search(content):
        findings.append(_mk("보안기능", "해시 함수 사용 코드", "secure_coding_flaw", "MEDIUM",
            "취약한 해시 함수(MD5/SHA1)가 사용되고 있습니다(CWE-327).",
            "비밀번호 등 민감정보는 bcrypt/scrypt/Argon2 등으로 해싱하세요."))
    if re.search(r"password\s*==\s*\w*password|stored_password", content, re.I):
        findings.append(_mk("보안기능", "비밀번호 비교 코드", "secure_coding_flaw", "HIGH",
            "비밀번호를 평문으로 비교하는 것으로 보입니다(CWE-256).", "솔트를 포함한 단방향 해시로 저장·비교하세요."))
    if re.search(r"except[^:\n]*:\s*(?:\n\s*)?return\s+str\(e\)|traceback\.format_exc\(\)\s*\)?\s*,?\s*200|print\(traceback", content, re.I):
        findings.append(_mk("에러처리", "예외 처리 코드", "secure_coding_flaw", "MEDIUM",
            "예외의 상세 내용이 그대로 사용자 응답에 노출될 수 있습니다(CWE-209).",
            "사용자에게는 일반화된 에러 메시지만 반환하고 상세 내용은 서버 로그에만 기록하세요."))
    findings.extend(_secret_findings(content, "보안기능"))
    return findings


def _check_zero_trust(content: str) -> list[dict]:
    findings = []
    if not re.search(r"MFA|다단계\s*인증", content, re.I):
        findings.append(_mk("식별자·신원", "인증 관련 서술", "access_control_gap", "CRITICAL",
            "관리자/권한 계정의 다단계 인증(MFA) 적용 여부가 확인되지 않습니다.", "모든 관리자 계정에 MFA를 강제 적용하세요."))
    if re.search(r"단일\s*VLAN|flat\s*network|세그먼트\s*없음|평면\s*구조", content, re.I):
        findings.append(_mk("네트워크", "네트워크 구조 관련 서술", "network_segmentation_gap", "HIGH",
            "네트워크가 세그먼트로 분리되지 않은 평면(flat) 구조인 것으로 보입니다.", "업무/자산 중요도에 따라 네트워크를 세그먼트로 분리하세요."))
    if not re.search(r"SIEM|중앙\s*로그|로그\s*수집|log\s*aggregation", content, re.I):
        findings.append(_mk("가시성·분석", "전체 서술", "logging_monitoring_gap", "MEDIUM",
            "중앙화된 로그 수집/SIEM 체계에 대한 언급이 없습니다.", "SIEM 또는 중앙 로그 수집 체계를 도입해 상관분석하세요."))
    if re.search(r"데이터", content) and not re.search(r"암호화|encrypt", content, re.I):
        findings.append(_mk("데이터", "데이터 관련 서술", "encryption_key_gap", "MEDIUM",
            "데이터에 대한 암호화 적용 여부가 확인되지 않습니다.", "민감 데이터는 분류 후 저장/전송 구간 모두 암호화하세요."))
    if not re.search(r"자동화|orchestration|정책\s*자동", content, re.I):
        findings.append(_mk("자동화·통합", "전체 서술", "governance_policy_gap", "LOW",
            "보안 정책 자동화/오케스트레이션에 대한 언급이 없습니다.", "탐지-대응을 자동화하는 SOAR 등의 도입을 검토하세요."))
    return findings


def _check_supply_chain(content: str) -> list[dict]:
    findings = []
    if not re.search(r"SBOM", content, re.I):
        findings.append(_mk("개발 단계", "전체 서술", "supply_chain_gap", "CRITICAL",
            "SBOM(소프트웨어 구성요소 명세서) 생성에 대한 언급이 없습니다.", "빌드 시점에 SBOM(CycloneDX/SPDX)을 자동 생성하도록 CI/CD에 통합하세요."))
    if not re.search(r"취약점\s*스캔|vulnerability\s*scan|grype|pip-audit|npm\s*audit", content, re.I):
        findings.append(_mk("개발 단계", "전체 서술", "patch_hardening_gap", "HIGH",
            "의존성 취약점 스캔에 대한 언급이 없습니다.", "CI/CD 파이프라인에 의존성 취약점 스캔 단계를 추가하세요."))
    if re.search(r"배포|아티팩트|artifact", content, re.I) and not re.search(r"서명|sign", content, re.I):
        findings.append(_mk("공급(유통) 단계", "배포 관련 서술", "supply_chain_gap", "MEDIUM",
            "배포 아티팩트의 서명/검증 절차가 확인되지 않습니다.", "배포 아티팩트에 디지털 서명을 적용하고 설치 시 검증을 의무화하세요."))
    findings.extend(_secret_findings(content, "개발 단계"))
    return findings


_CHECKERS = {
    "cii": _check_cii,
    "ai_security": _check_ai_security,
    "robot_security": _check_robot_security,
    "space_security": _check_space_security,
    "secure_coding": _check_secure_coding,
    "zero_trust": _check_zero_trust,
    "supply_chain": _check_supply_chain,
}

# 7개 평가 유형이 서로 완전히 다른 검사기로 매핑되어 있는데, 이 앱의 검사는 대부분 "특정
# 키워드가 없으면 미비로 표시"하는 방식이라(App3/7/12처럼 아예 탐지가 0건이 되는 게 아니라)
# 유형을 잘못 고르면 findings 개수는 비슷하게 나오지만 내용이 완전히 엉뚱해진다 — 실제로
# SSH root 로그인 허용+Telnet+0.0.0.0/0 노출이 담긴 CII 텍스트를 "ai_security"로 잘못 선택해
# 분석하면 "학습 데이터 검증 언급 없음" 같은 무관한 항목 4건이 나오고 실제 CRITICAL 노출은
# 전혀 언급되지 않으며 위험도가 MEDIUM으로 낮게 나오는 것을 실측으로 확인함 — 조용히 틀린
# 결과라 오히려 findings가 0건인 경우보다 알아채기 어렵다.
_ASSESSMENT_TYPE_LABELS = {
    "cii": "주요정보통신기반시설(CII)", "ai_security": "AI 보안", "robot_security": "로봇 보안",
    "space_security": "우주 보안", "secure_coding": "시큐어코딩", "zero_trust": "제로트러스트",
    "supply_chain": "SW 공급망 보안",
}
_ASSESSMENT_TYPE_SIGNATURES = {
    "cii": (r"기반시설|SCADA|\bICS\b|국가\s*안보|PermitRootLogin|sshd_config|vsftpd|nginx\.conf",),
    "ai_security": (r"AI\s*모델|학습\s*데이터|추론|\bLLM\b|프롬프트|적대적\s*예제|모델\s*드리프트",),
    "robot_security": (r"로봇|액추에이터|\bRTOS\b|로보틱스|\brobot\b",),
    "space_security": (r"위성|지상국|궤도|우주|원격측정|telemetry|ground\s*station",),
    "zero_trust": (r"제로트러스트|zero\s*trust|마이크로\s*세그먼트|지속적\s*검증|least\s*privilege",),
    "supply_chain": (r"SBOM|공급망\s*보안|빌드\s*파이프라인|타사\s*라이브러리|dependency\s*scan",),
}
_ASSESSMENT_TYPE_SIGNATURES_RE = {
    t: [re.compile(p, re.I) for p in pats] for t, pats in _ASSESSMENT_TYPE_SIGNATURES.items()
}
# secure_coding은 이미 컴파일된 정규식(App3 vuln_offline_engine에서 그대로 가져온 것)을 재사용 —
# .pattern으로 문자열만 뽑아 다시 컴파일하면 원본 플래그가 소실될 수 있어 객체를 그대로 쓴다.
_ASSESSMENT_TYPE_SIGNATURES_RE["secure_coding"] = [_SQL_FSTRING_RE, _SQL_CONCAT_RE, _XSS_RE, _EVAL_EXEC_RE, _WEAK_HASH_RE]


def _detect_assessment_type_mismatch(content: str, assessment_type: str) -> str | None:
    if not content.strip():
        return None
    own_patterns = _ASSESSMENT_TYPE_SIGNATURES_RE.get(assessment_type, [])
    if any(p.search(content) for p in own_patterns):
        return None
    for other_type, patterns in _ASSESSMENT_TYPE_SIGNATURES_RE.items():
        if other_type == assessment_type:
            continue
        if any(p.search(content) for p in patterns):
            return (
                f"⚠️ 선택하신 평가 유형은 '{_ASSESSMENT_TYPE_LABELS.get(assessment_type, assessment_type)}'인데, "
                f"내용은 '{_ASSESSMENT_TYPE_LABELS.get(other_type, other_type)}'에 더 가까워 보입니다 — "
                "유형을 잘못 선택하면 findings 개수는 비슷해도 내용이 실제 문제와 무관해질 수 있습니다. "
                "유형을 다시 확인하세요."
            )
    return None


def analyze_offline(assessment_type: str, content: str, context: str) -> dict:
    checker = _CHECKERS.get(assessment_type, _check_cii)
    findings = checker(content)
    mismatch_warning = _detect_assessment_type_mismatch(content, assessment_type)

    if not findings:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위험 키워드/패턴이 발견되지 않았습니다. 이 엔진이 모르는 문제는 놓칠 수 있습니다."
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

    if mismatch_warning:
        summary = f"{mismatch_warning} {summary}"

    return {
        "summary": summary,
        "overall_risk": overall_risk,
        "findings": findings,
        "compliance_notes": [],
        "engine_note": ENGINE_NOTE,
    }
