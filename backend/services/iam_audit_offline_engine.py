"""App 18(클라우드 IAM 정책 감사기)의 오프라인(폐쇄망) 모드 — 실제 정책/사용자 텍스트를
정규식·키워드로 분석한다. firewall_audit_offline_engine.py와 동일한 설계 원칙."""
import re


def _mk(rule_reference: str, issue_type: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "rule_reference": rule_reference.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


_WILDCARD_ACTION_RESOURCE_RE = re.compile(
    r'"Action"\s*:\s*(?:"\*"|\[[^\]]*"\*"[^\]]*\])[^}]*?"Resource"\s*:\s*(?:"\*"|\[[^\]]*"\*"[^\]]*\])'
    r'|"Action"\s*:\s*"\*:\*"',
    re.I | re.S,
)
_ADMIN_ROLE_RE = re.compile(r"AdministratorAccess|\bOwner\b.*(?:subscription|scope)|roles/owner|roles/editor", re.I)
_ESCALATION_RE = re.compile(
    r"iam:PutUserPolicy|iam:AttachUserPolicy|iam:CreateAccessKey|iam:AddUserToGroup"
    r"|roleAssignments/write|serviceAccountTokenCreator|serviceAccountUser",
    re.I,
)
_PUBLIC_TRUST_RE = re.compile(r'"Principal"\s*:\s*"\*"|allUsers|allAuthenticatedUsers', re.I)
_MFA_MENTION_RE = re.compile(r"\bmfa\b|다단계\s*인증|multi-?factor", re.I)
_ADMIN_CONTEXT_RE = re.compile(r"\badmin\b|\broot\b|콘솔|console|관리자", re.I)
_STALE_HINT_RE = re.compile(r"never expire|만료\s*없음|미사용|unused|rotat", re.I)
_ACCESS_KEY_MENTION_RE = re.compile(r"access\s*key|액세스\s*키", re.I)
_SHARED_ACCOUNT_RE = re.compile(r"공유\s*계정|shared\s*account|team\s*account|공용\s*계정", re.I)


def analyze_offline(source_type: str, content: str, context: str) -> dict:
    findings: list[dict] = []

    m = _WILDCARD_ACTION_RESOURCE_RE.search(content)
    if m:
        findings.append(_mk(
            m.group(0), "excessive_privilege", "CRITICAL",
            "Action과 Resource가 모두 와일드카드(*)로 설정되어 사실상 전체 권한을 부여합니다.",
            "실제로 필요한 개별 액션/리소스로 범위를 좁히세요(최소 권한 원칙).",
        ))
    m = _ADMIN_ROLE_RE.search(content)
    if m:
        findings.append(_mk(
            m.group(0), "excessive_privilege", "HIGH",
            "관리자급 역할(AdministratorAccess/Owner/roles·owner 등)이 광범위한 범위에 부여되어 있습니다.",
            "필요한 개별 권한만 담은 커스텀 역할로 교체하고, 관리자 권한은 그룹/PIM 등으로 임시 승격하는 방식을 검토하세요.",
        ))

    for m in _ESCALATION_RE.finditer(content):
        findings.append(_mk(
            m.group(0), "privilege_escalation_path", "CRITICAL",
            f"'{m.group(0)}' 권한은 스스로 또는 타인에게 권한을 추가로 부여할 수 있는 권한 상승 경로가 될 수 있습니다.",
            "이 권한이 정말 필요한지 재검토하고, 필요하다면 조건부(Condition)로 범위를 제한하세요.",
        ))
        break  # 종류별 대표 1건만 — 소음 방지

    m = _PUBLIC_TRUST_RE.search(content)
    if m:
        findings.append(_mk(
            m.group(0), "misconfigured_trust", "CRITICAL",
            "Principal이 '*' 이거나 allUsers/allAuthenticatedUsers 바인딩이 있어 사실상 누구나 접근 가능합니다.",
            "신뢰할 특정 계정/서비스만 Principal로 지정하세요.",
        ))

    if _ADMIN_CONTEXT_RE.search(content) and not _MFA_MENTION_RE.search(content):
        findings.append(_mk(
            "관리자/콘솔 계정 관련 서술", "missing_mfa", "HIGH",
            "관리자/콘솔 계정이 언급되어 있으나 MFA(다단계 인증) 적용 여부가 확인되지 않습니다.",
            "모든 관리자 계정에 MFA를 강제 적용하세요.",
        ))

    if _ACCESS_KEY_MENTION_RE.search(content) and _STALE_HINT_RE.search(content):
        findings.append(_mk(
            "액세스 키 관련 서술", "stale_credential", "MEDIUM",
            "만료되지 않거나 오래 미사용된 액세스 키로 보이는 서술이 있습니다.",
            "액세스 키를 주기적으로(예: 90일) 로테이션하고 미사용 키는 폐기하세요.",
        ))

    m = _SHARED_ACCOUNT_RE.search(content)
    if m:
        findings.append(_mk(
            m.group(0), "shared_credential", "MEDIUM",
            "여러 사람이 공유하는 계정/자격증명으로 보이는 서술이 있어 행위 추적이 어렵습니다.",
            "개인별로 구분되는 계정으로 전환하세요.",
        ))

    if not findings:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위험 패턴이 발견되지 않았습니다. 이 엔진이 모르는 문제는 놓칠 수 있습니다."
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
            "AI가 아니라 사전 정의된 패턴(와일드카드 권한, 권한상승 액션, 공개 신뢰관계, MFA/로테이션 "
            "키워드 부재 등)과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁습니다. 인터넷 또는 로컬 "
            "LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 권장합니다."
        ),
    }
