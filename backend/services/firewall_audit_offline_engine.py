"""App 16(방화벽 정책 감사기)의 오프라인(폐쇄망) 모드 — Claude/로컬 LLM 둘 다 쓸 수 없을 때도
실제 규칙 텍스트를 정규식으로 분석한다. vulnerability_service.py/vuln_offline_engine.py와 동일한
패턴: 8개 플랫폼 공용 검사 + 라우터/스위치·VPN 게이트웨이 전용 검사(insecure_management/
weak_authentication은 이 두 플랫폼에서만 의미가 있다는 SYSTEM_PROMPT의 제약을 그대로 따른다).
"""
import json
import re

_SENSITIVE_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
    "6379": "Redis", "1433": "MSSQL", "27017": "MongoDB", "9200": "Elasticsearch", "445": "SMB",
}
_OPEN_ANY_RE = re.compile(r"(0\.0\.0\.0/0|::/0|\bany\b|\*)", re.I)
_PORT_RE = re.compile(r"\b(" + "|".join(_SENSITIVE_PORTS) + r")\b")
# Azure NSG 등은 "access": "Deny" 같은 명시적 차단 규칙도 규칙 목록에 함께 들어있다 —
# 이런 규칙은 CIDR+포트가 같이 있어도 "과도 허용"이 아니라 오히려 의도된 차단이므로 제외한다.
_DENY_ACTION_RE = re.compile(r'"(?:access|action|ruleaction|effect)"\s*:\s*"(?:deny|reject|drop|block)"', re.I)


def _mk(rule_reference: str, issue_type: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "rule_reference": rule_reference.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


def _overly_permissive_finding(rule_reference: str, port: str) -> dict:
    svc = _SENSITIVE_PORTS[port]
    return _mk(
        rule_reference, "overly_permissive", "CRITICAL" if port in ("22", "3389", "3306", "6379") else "HIGH",
        f"출발지가 전체 공개(0.0.0.0/0·any·*)로 설정된 규칙이 민감 포트 {port}({svc})를 허용하고 있습니다.",
        f"출발지를 꼭 필요한 IP 대역으로 제한하세요 — {svc}는 특히 관리용 포트라 전체 공개 시 위험이 큽니다.",
    )


def _json_overly_permissive_checks(data) -> list[dict]:
    """AWS/Azure/GCP 네이티브 export처럼 JSON으로 파싱되는 입력은 실제 객체 구조를 따라가며
    같은 규칙(dict) 안에서만 전체공개 CIDR과 민감 포트를 짝짓는다 — 이 프로젝트가 실제
    AWS `describe-security-groups` 출력(필드가 여러 줄에 걸쳐 pretty-print됨)을 테스트하며
    발견한 문제: 줄 단위 근접도로 추정하면 규칙 블록이 서로 가까울 때(예: 10여 줄 간격의
    인접 보안그룹 규칙) 다른 규칙의 포트와 잘못 엮이거나, 반대로 필드가 멀리 떨어지면
    아예 못 잡는다. 실제 dict 경계를 알고 있으니 둘 다 정확히 해결된다."""
    findings: list[dict] = []

    def walk(node) -> bool:
        matched_below = False
        if isinstance(node, dict):
            for value in node.values():
                if walk(value):
                    matched_below = True
            if not matched_below:
                if "denied" in node and "allowed" not in node:
                    return False  # GCP: allowed 없이 denied만 있으면 명시적 차단 규칙
                flat = json.dumps(node, ensure_ascii=False)
                if _DENY_ACTION_RE.search(flat):
                    return False
                if _OPEN_ANY_RE.search(flat):
                    for port in dict.fromkeys(_PORT_RE.findall(flat)):
                        findings.append(_overly_permissive_finding(flat, port))
                        matched_below = True
        elif isinstance(node, list):
            for item in node:
                if walk(item):
                    matched_below = True
        return matched_below

    walk(data)
    return findings


def _generic_checks(content: str) -> list[dict]:
    findings: list[dict] = []
    lines = [l for l in content.splitlines() if l.strip()]

    # 과도 허용: JSON으로 파싱되면(AWS/Azure/GCP) 구조를 따라가며 정확히 판정하고,
    # 그 외(iptables/CLI 표/라우터 config 등 한 줄에 규칙이 다 있는 텍스트)는 같은 줄에서
    # 0.0.0.0/0·any·* + 민감 포트 조합을 찾는다.
    try:
        parsed_json = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed_json = None

    if parsed_json is not None:
        findings.extend(_json_overly_permissive_checks(parsed_json))
    else:
        for line in lines:
            if _OPEN_ANY_RE.search(line):
                port_match = _PORT_RE.search(line)
                if port_match:
                    findings.append(_overly_permissive_finding(line, port_match.group(1)))

    # 중복 규칙: 주석/빈 줄을 뺀 완전히 동일한 줄이 2회 이상 등장 — JSON 입력은 규칙이 달라도
    # 공통 필드 줄("IpProtocol": "tcp" 등)이 구조적으로 반복되므로 이 검사 대상에서 제외
    if parsed_json is None:
        seen: dict[str, int] = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("#", "//", "!")):
                continue
            seen[stripped] = seen.get(stripped, 0) + 1
        for line, count in seen.items():
            if count > 1 and len(line) > 5:
                findings.append(_mk(
                    line, "redundant", "LOW",
                    f"동일한 규칙이 {count}번 반복되어 있습니다 — 관리 혼란과 정책 파악을 어렵게 만듭니다.",
                    "중복된 규칙을 하나로 정리하세요.",
                ))

    # 로깅 언급이 전혀 없으면 누락된 통제로 best-effort 플래그
    if not re.search(r"\blog\b|logging|로그|로깅", content, re.I):
        findings.append(_mk(
            "규칙셋 전체", "missing_control", "LOW",
            "붙여넣은 내용에서 로깅/감사 관련 설정이 전혀 보이지 않습니다.",
            "허용/차단 트래픽에 대한 로깅을 활성화해 사고 조사·감사에 대비하세요.",
        ))

    return findings


_ROUTER_CHECKS = [
    (re.compile(r"transport input[^\n]*\btelnet\b", re.I), "insecure_management", "HIGH",
     "VTY 라인에서 Telnet 접속이 허용되어 있어 모든 관리 트래픽이 평문으로 전송됩니다.",
     "transport input ssh 로 변경해 Telnet을 비활성화하세요."),
    (re.compile(r"snmp-server community\s+(public|private)\b", re.I), "insecure_management", "CRITICAL",
     "SNMP 커뮤니티 스트링이 기본값(public/private)으로 설정되어 있습니다.",
     "SNMPv3로 전환하거나 최소한 추측 불가능한 커뮤니티 스트링으로 교체하세요."),
    (re.compile(r"\bip http server\b", re.I), "insecure_management", "MEDIUM",
     "평문 HTTP 관리 서버가 활성화되어 있습니다.",
     "ip http server를 비활성화하고 ip http secure-server(HTTPS)만 사용하세요."),
    (re.compile(r"^enable password\b", re.I | re.M), "weak_authentication", "HIGH",
     "enable password는 가역적으로 복호화 가능한 평문에 가까운 방식입니다.",
     "enable secret 명령으로 교체해 강한 해시로 저장하세요."),
    (re.compile(r"password 7 \S+", re.I), "weak_authentication", "HIGH",
     "Type 7 암호화(사실상 평문 복호화 가능)로 저장된 비밀번호가 발견됐습니다.",
     "Type 5/8/9(강한 해시)로 재설정하세요."),
]

_VPN_CHECKS = [
    (re.compile(r"split-tunnel(?:ing)?\s+enable", re.I), "overly_permissive", "HIGH",
     "Split-tunneling이 활성화되어 있어, 감염된 단말이 검사 없이 인터넷과 내부망을 동시에 오갈 수 있습니다.",
     "Split-tunneling을 비활성화하고 모든 트래픽을 터널로 통과시키세요."),
    (re.compile(r"ssl-min-proto-ver[^\n]*tls1-0|\btls\s*1\.0\b|\bsslv3\b", re.I), "insecure_management", "HIGH",
     "오래된 SSL/TLS 버전(SSLv3, TLS 1.0)이 허용되어 있습니다.",
     "TLS 1.2 이상만 허용하도록 설정하세요."),
    (re.compile(r"idle-timeout\s+0\b", re.I), "missing_control", "MEDIUM",
     "유휴 타임아웃이 0(무제한)으로 설정되어 있습니다.",
     "적절한 유휴 타임아웃(예: 15~30분)을 설정하세요."),
]


def analyze_offline(source_type: str, content: str, context: str) -> dict:
    findings = _generic_checks(content)

    if source_type in ("router_switch", "vpn_gateway"):
        for rx, issue_type, severity, desc, rec in _ROUTER_CHECKS + _VPN_CHECKS:
            m = rx.search(content)
            if m:
                findings.append(_mk(m.group(0), issue_type, severity, desc, rec))

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
            "AI가 아니라 사전 정의된 패턴(전체 공개+민감포트, 중복 규칙, Telnet/SNMP 기본값 등 "
            "관리방식 안티패턴)과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁습니다. 인터넷 또는 "
            "로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 권장합니다."
        ),
    }
