"""App 1(보안 로그 분석 대시보드)/App 23(실시간 공격 모니터링)이 공유하는
claude_service.analyze_logs()의 "오프라인(폐쇄망)" 모드 — 정규식/키워드 기반으로 실제
로그 텍스트를 분석한다(mock_data.generate_mock_analysis()처럼 내용과 무관하게 무작위
샘플을 뽑는 것이 아님).

두 앱 모두 이 함수를 거치므로, 사람이 자유 형식으로 붙여넣는 일반 보안 로그(SSH/웹 서버
접근 로그 등)와 App 23이 PowerShell로 수집해 넘기는 정형화된 라인
(windows_security[4625]:, windows_defender:, windows_firewall:, network: New listener...),
그리고 App 23 "AWS 활동 모니터링" 탭이 aws_activity_monitor.py로 수집해 넘기는
aws_cloudtrail[...] 라인(IAM 와일드카드 권한 변경, 보안그룹 전체공개) 셋 다 인식하도록
설계했다. App 3의 vuln_offline_engine.py와 같은 설계 원칙(실제 입력을 분석, 한계는
engine_note로 고지)을 따른다.
"""
import re
from collections import defaultdict
from urllib.parse import unquote

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 규칙/정규식 기반 오프라인 분석 엔진이 생성했습니다 — "
    "AI가 아니라 사전 정의된 패턴(반복된 인증 실패, SQLi/XSS 페이로드, 알려진 공격 도구 시그니처, "
    "인코딩된 PowerShell, 방화벽 차단 다건 등)과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁고 "
    "새롭거나 변형된 위협은 놓칠 수 있습니다. 인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 "
    "재분석하는 것을 권장합니다."
)

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_BRUTE_FORCE_THRESHOLD = 3
_PORT_SCAN_DROP_THRESHOLD = 5

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TS_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")

_AUTH_FAIL_RE = re.compile(
    r"(failed password|authentication failure|invalid user|failed logon|login failed|access denied for user)",
    re.I,
)
_SQLI_RE = re.compile(
    r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1|xp_cmdshell|sleep\(\d+\)|benchmark\(|;\s*drop\s+table|information_schema)",
    re.I,
)
_XSS_RE = re.compile(r"(<script|onerror\s*=|javascript:|%3cscript|document\.cookie)", re.I)
_TOOL_SIG_RE = re.compile(r"(sqlmap|nikto|masscan|acunetix|dirbuster|gobuster|wpscan|nmap scripting engine)", re.I)
_ENCODED_PS_RE = re.compile(r"(-enc(odedcommand)?\b|frombase64string|invoke-expression|\biex\s*\(|-nop\s+-w\s+hidden)", re.I)
_DEFENDER_THREAT_RE = re.compile(r"windows_defender:\s*threat detected", re.I)
_NEW_LISTENER_RE = re.compile(r"network:\s*new listener opened", re.I)
_FIREWALL_DROP_RE = re.compile(r"windows_firewall:.*\bDROP\b", re.I)
_NO_SIGNAL_RE = re.compile(r"status:\s*no suspicious signals observed", re.I)

# App 23 "AWS 활동 모니터링" 탭(aws_activity_monitor.py)이 넘기는 aws_cloudtrail[...] 라인 전용
_AWS_IAM_ESCALATION_RE = re.compile(
    r"aws_cloudtrail\[(CreatePolicy|PutUserPolicy|PutRolePolicy|PutGroupPolicy|"
    r"AttachUserPolicy|AttachRolePolicy|AttachGroupPolicy|UpdateAssumeRolePolicy)\]"
)
_WILDCARD_PERM_RE = re.compile(r'"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"|"Principal"\s*:\s*"\*"|"AWS"\s*:\s*"\*"', re.I)
_AWS_SG_INGRESS_RE = re.compile(r"aws_cloudtrail\[AuthorizeSecurityGroupIngress\]")
_AWS_OPEN_CIDR_RE = re.compile(r"0\.0\.0\.0/0|::/0")
_AWS_SENSITIVE_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
    "6379": "Redis", "1433": "MSSQL", "27017": "MongoDB", "9200": "Elasticsearch", "445": "SMB",
}
_AWS_PORT_RE = re.compile(r"\b(" + "|".join(_AWS_SENSITIVE_PORTS) + r")\b")


def _first_ip(text: str) -> str | None:
    m = _IP_RE.search(text)
    return m.group(0) if m else None


def _timestamp_of(line: str) -> str | None:
    m = _TS_RE.match(line)
    return m.group(1) if m else None


def _mk(idx: int, ts, severity: str, category: str, description: str, source_ip, affected: str, remediation: str) -> dict:
    return {
        "id": f"EVT-{idx:03d}",
        "timestamp": ts,
        "severity": severity,
        "category": category,
        "description": description,
        "source_ip": source_ip,
        "affected_resource": affected,
        "remediation": remediation,
    }


def _empty_result(summary: str, threat_level: str = "INFO") -> dict:
    return {
        "summary": summary,
        "threat_level": threat_level,
        "events": [],
        "statistics": {"total_events": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "engine_note": ENGINE_DISCLAIMER,
    }


def analyze_offline(log_content: str) -> dict:
    lines = [l for l in log_content.splitlines() if l.strip()]
    if not lines:
        return _empty_result("분석할 로그 내용이 없습니다.")

    # App 23의 collect_real_signals()가 "이상 없음"만 보고한 단일 라인인 경우 조기 종료
    if len(lines) == 1 and _NO_SIGNAL_RE.search(lines[0]):
        return _empty_result("규칙 기반 오프라인 분석 결과, 관찰된 신호에서 특이사항이 발견되지 않았습니다.")

    events: list[dict] = []
    idx = 1
    auth_fail_ips: dict[str, list[str]] = defaultdict(list)
    firewall_drop_ips: dict[str, int] = defaultdict(int)

    for line in lines:
        ts = _timestamp_of(line)
        ip = _first_ip(line)
        # 웹 서버 접근 로그의 쿼리스트링은 흔히 퍼센트 인코딩되어 있어(예: %20OR%201=1) 원문
        # 그대로는 SQLi/XSS 패턴이 매칭되지 않는다 — 매칭·표시 모두 디코딩된 사본으로 한다.
        decoded = unquote(line)

        if _AUTH_FAIL_RE.search(decoded):
            auth_fail_ips[ip or "unknown"].append(line)
            continue  # 개별 실패는 아래에서 IP별로 집계해 브루트포스 여부만 보고(소음 방지)

        if _DEFENDER_THREAT_RE.search(decoded):
            events.append(_mk(
                idx, ts, "CRITICAL", "Malware",
                f"Windows Defender가 실제 위협을 탐지했습니다: {decoded.strip()[:200]}",
                ip, "이 시스템 (Windows Defender)",
                "격리된 프로세스/파일을 확인하고 전체 검사를 실행하세요. 필요시 호스트를 네트워크에서 격리하세요.",
            ))
            idx += 1
            continue

        if _AWS_IAM_ESCALATION_RE.search(decoded) and _WILDCARD_PERM_RE.search(decoded):
            events.append(_mk(
                idx, ts, "CRITICAL", "AWS IAM Privilege Escalation",
                f"AWS IAM에서 와일드카드 권한(Action:*/Principal:*)이 포함된 정책 변경이 감지됐습니다: {decoded.strip()[:200]}",
                None, "AWS IAM",
                "해당 정책/역할을 즉시 검토하고, 필요 이상의 권한이 실제로 필요한지 확인하세요. 클라우드 IAM 정책 감사기(App 18)로 전체 계정을 점검하는 것을 권장합니다.",
            ))
            idx += 1
            continue

        if _AWS_SG_INGRESS_RE.search(decoded) and _AWS_OPEN_CIDR_RE.search(decoded):
            port_match = _AWS_PORT_RE.search(decoded)
            if port_match:
                port = port_match.group(1)
                svc = _AWS_SENSITIVE_PORTS[port]
                events.append(_mk(
                    idx, ts, "CRITICAL" if port in ("22", "3389", "3306", "6379") else "HIGH",
                    "AWS Security Group Exposure",
                    f"AWS 보안그룹이 인터넷 전체(0.0.0.0/0)에 민감 포트 {port}({svc})를 허용하도록 변경됐습니다: {decoded.strip()[:200]}",
                    None, "AWS 보안그룹",
                    f"해당 보안그룹 규칙을 즉시 검토하고 출발지를 꼭 필요한 IP 대역으로 제한하세요({svc}는 특히 관리용 포트라 위험이 큽니다). 방화벽 정책 감사기(App 16)로 전체 규칙을 점검하는 것을 권장합니다.",
                ))
                idx += 1
                continue

        if _SQLI_RE.search(decoded):
            events.append(_mk(
                idx, ts, "CRITICAL", "SQL Injection",
                f"SQL Injection 의심 페이로드가 포함된 요청이 발견됐습니다: {decoded.strip()[:200]}",
                ip, "웹 애플리케이션",
                "해당 IP를 차단하고 입력 검증/파라미터화 쿼리 적용 여부를 점검하세요.",
            ))
            idx += 1
            continue

        if _XSS_RE.search(decoded):
            events.append(_mk(
                idx, ts, "HIGH", "XSS",
                f"XSS 의심 페이로드가 포함된 요청이 발견됐습니다: {decoded.strip()[:200]}",
                ip, "웹 애플리케이션",
                "출력 인코딩/이스케이프 처리와 CSP 적용 여부를 점검하세요.",
            ))
            idx += 1
            continue

        tool_match = _TOOL_SIG_RE.search(decoded)
        if tool_match:
            events.append(_mk(
                idx, ts, "HIGH", "Reconnaissance",
                f"알려진 공격/스캐닝 도구({tool_match.group(1)}) 시그니처가 발견됐습니다: {decoded.strip()[:200]}",
                ip, "네트워크/웹 서비스",
                "해당 IP를 차단하고 스캔 대상이 된 서비스의 노출 범위를 점검하세요.",
            ))
            idx += 1
            continue

        if _ENCODED_PS_RE.search(decoded):
            events.append(_mk(
                idx, ts, "HIGH", "Suspicious Execution",
                f"인코딩된 PowerShell 명령/난독화된 실행 패턴이 발견됐습니다: {decoded.strip()[:200]}",
                ip, "호스트 프로세스",
                "인코딩된 값을 디코딩해 실제 실행 내용을 확인하고, 필요시 호스트를 격리하세요.",
            ))
            idx += 1
            continue

        if _NEW_LISTENER_RE.search(decoded):
            events.append(_mk(
                idx, ts, "MEDIUM", "Suspicious Network Change",
                f"모든 인터페이스(0.0.0.0/::)에 새 리스닝 포트가 열렸습니다: {decoded.strip()[:200]}",
                None, "네트워크 리스너",
                "해당 프로세스가 의도된 것인지 확인하고, 불필요하면 방화벽으로 차단하세요.",
            ))
            idx += 1
            continue

        if _FIREWALL_DROP_RE.search(decoded):
            firewall_drop_ips[ip or "unknown"] += 1
            continue

    for ip, fail_lines in auth_fail_ips.items():
        ts = _timestamp_of(fail_lines[0])
        real_ip = ip if ip != "unknown" else None
        if len(fail_lines) >= _BRUTE_FORCE_THRESHOLD:
            events.append(_mk(
                idx, ts, "CRITICAL", "Brute Force",
                f"IP {ip}에서 {len(fail_lines)}건의 반복된 인증 실패가 감지됐습니다.",
                real_ip, "인증 서비스 (SSH/로그인 등)",
                "해당 IP를 즉시 차단하고 fail2ban 등 무차별 대입 방지 대책을 적용하세요.",
            ))
        else:
            events.append(_mk(
                idx, ts, "LOW", "Authentication",
                f"IP {ip}에서 {len(fail_lines)}건의 인증 실패가 있었습니다(브루트포스 임계치 미만).",
                real_ip, "인증 서비스",
                "지속되면 브루트포스로 이어질 수 있으니 모니터링하세요.",
            ))
        idx += 1

    for ip, count in firewall_drop_ips.items():
        if count >= _PORT_SCAN_DROP_THRESHOLD:
            real_ip = ip if ip != "unknown" else None
            events.append(_mk(
                idx, None, "MEDIUM", "Port Scan",
                f"{count}건의 방화벽 차단(DROP) 기록이 발견되어 포트 스캔/무작위 접속 시도 가능성이 있습니다"
                + (f" (IP: {ip})" if real_ip else "") + ".",
                real_ip, "방화벽",
                "해당 IP의 평판을 조회하고 지속되면 차단 목록에 추가하세요.",
            ))
            idx += 1

    events.sort(key=lambda e: _SEV_RANK.get(e["severity"], 9))
    for i, e in enumerate(events, start=1):
        e["id"] = f"EVT-{i:03d}"

    stats = {"total_events": len(events), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in events:
        key = e["severity"].lower()
        if key in stats:
            stats[key] += 1

    threat_level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if stats[s.lower()] > 0), "INFO")

    if not events:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위협 패턴이 발견되지 않았습니다."
    elif stats["critical"] > 0:
        summary = f"규칙 기반 오프라인 분석에서 심각(CRITICAL) {stats['critical']}건을 포함해 총 {len(events)}건의 위협이 발견됐습니다. 즉각적인 조치가 필요합니다."
    elif stats["high"] > 0:
        summary = f"규칙 기반 오프라인 분석에서 높음(HIGH) {stats['high']}건을 포함해 총 {len(events)}건의 위협이 발견됐습니다."
    else:
        summary = f"규칙 기반 오프라인 분석에서 총 {len(events)}건의 사항이 발견됐습니다."

    return {
        "summary": summary,
        "threat_level": threat_level,
        "events": events,
        "statistics": stats,
        "engine_note": ENGINE_DISCLAIMER,
    }
