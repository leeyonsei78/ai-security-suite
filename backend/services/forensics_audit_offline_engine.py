"""App 25(포렌식 실습·분석 센터) '아티팩트 감사기' 탭의 오프라인(폐쇄망) 모드 —
firewall_audit_offline_engine.py와 동일한 패턴: Claude/로컬 LLM을 쓸 수 없을 때도
실제 아티팩트 텍스트를 정규식으로 분석해 findings/timeline/iocs를 만든다.

2026-09-06 확장: 클라우드(AWS 루트계정/CloudTrail 중지/IAM 조작)·네트워크 장비
(Cisco 설정변경+아웃바운드 허용, Fortinet 정책변경+로깅비활성화, Palo Alto/Juniper
commit 이벤트) 벤더별 패턴 추가. Cisco의 %SYS-5-CONFIG_I, Juniper의 UI_COMMIT은
공식 문서화된 안정적인 로그 메시지라 신뢰도가 높지만, Fortinet/Palo Alto의 필드
구성은 버전·설정에 따라 달라질 수 있어 상대적으로 best-effort에 가깝다 — 이 한계는
engine_note에 항상 고지한다."""

import re
from datetime import datetime

_TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _mk(ref: str, issue_type: str, severity: str, mitre: str, description: str, recommendation: str) -> dict:
    return {
        "artifact_reference": ref.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "mitre_technique": mitre,
        "description": description,
        "recommendation": recommendation,
    }


_STATIC_CHECKS = [
    (re.compile(r"\bevent\s*id[:\s]*1102\b|\b1102\b.{0,40}(clear|삭제)", re.I),
     "anti_forensic_technique", "CRITICAL", "T1070.001 - Clear Windows Event Logs",
     "보안 이벤트 로그 삭제(Event ID 1102)가 발견됐습니다 — 공격자가 흔적을 지우려 한 명백한 안티포렌식 행위입니다.",
     "중앙 로그 수집(SIEM)으로 로그를 실시간 백업하고, 1102 이벤트 발생 시 즉시 알림이 가도록 설정하세요."),
    (re.compile(r"wevtutil\s+(cl\b|clear-log)", re.I),
     "anti_forensic_technique", "CRITICAL", "T1070.001 - Clear Windows Event Logs",
     "wevtutil로 이벤트 로그를 직접 삭제하는 명령이 발견됐습니다.",
     "해당 명령 실행 계정과 시점을 확인하고, 로그 삭제 명령 실행 자체를 탐지·알림하도록 설정하세요."),
    (re.compile(r"vssadmin\s+delete\s+shadows", re.I),
     "anti_forensic_technique", "CRITICAL", "T1490 - Inhibit System Recovery",
     "볼륨 섀도우 복사본을 삭제하는 명령(vssadmin delete shadows)이 발견됐습니다 — 랜섬웨어가 복구를 막기 위해 흔히 사용합니다.",
     "백업이 별도의 오프라인/불변(immutable) 저장소에도 있는지 확인하고, 해당 호스트를 즉시 격리하세요."),
    (re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I),
     "evidence_of_compromise", "HIGH", "T1059.001 - PowerShell",
     "Base64로 인코딩된 명령을 실행하는 PowerShell 호출이 발견됐습니다 — 탐지 우회 목적의 페이로드 실행일 가능성이 있습니다.",
     "인코딩 문자열을 디코딩해 실제 실행 내용을 확인하고, 해당 호스트를 격리해 추가 분석을 진행하세요."),
    (re.compile(r"\\Run(Once)?\\", re.I),
     "persistence_mechanism", "HIGH", "T1547.001 - Registry Run Keys / Startup Folder",
     "레지스트리 Run/RunOnce 키에 대한 참조가 발견됐습니다 — 재부팅 시 자동 실행되도록 등록하는 대표적인 지속성 확보 기법입니다.",
     "등록된 값이 정상 소프트웨어인지 확인하고, 알 수 없는 항목은 제거 전 export로 증거를 보존하세요."),
    (re.compile(r"\b(psexec|wmic\s+/node|invoke-wmimethod|ipc\$)\b", re.I),
     "lateral_movement_evidence", "HIGH", "T1021 - Remote Services",
     "PsExec/WMI 등 원격 실행 도구 사용 흔적이 발견됐습니다 — 내부망 이동(lateral movement)에 흔히 악용됩니다.",
     "해당 도구가 정상 관리 목적으로 사용됐는지 담당자에게 확인하고, 사용 이력이 없다면 침해 범위를 다른 호스트로 확장해 조사하세요."),
    (re.compile(r"(svchost|lsass|csrss|explorer)\.exe[^\n]{0,80}(users\\public|appdata\\|\\temp\\|downloads\\)", re.I),
     "evidence_of_compromise", "HIGH", "T1036.005 - Match Legitimate Name or Location",
     "정상 시스템 프로세스와 동일한 이름이 시스템 폴더가 아닌 위치에서 실행되고 있습니다 — 프로세스 마스커레이딩(위장)으로 의심됩니다.",
     "해당 프로세스를 격리·해시 확인하고, 정상 경로(C:\\Windows\\System32)에서 실행 중인 동일 이름 프로세스와 비교하세요."),
    # 클라우드 감사 로그(cloud_audit_log)용
    (re.compile(r'"type"\s*:\s*"Root"|userIdentity\.type[=\s]*Root', re.I),
     "evidence_of_compromise", "CRITICAL", "T1078.004 - Valid Accounts: Cloud Accounts",
     "루트/최상위 관리자 계정의 API 호출 또는 로그인 이벤트가 발견됐습니다 — 평소 루트 계정을 쓰지 않는 조직에서는 그 자체가 강한 위험 신호입니다.",
     "루트 계정 자격증명을 즉시 재설정하고 MFA를 강제 적용하세요. 이후 일상 관리에는 별도 계정/역할을 사용하세요."),
    (re.compile(r"StopLogging|DeleteTrail|logging\s+disabled", re.I),
     "anti_forensic_technique", "CRITICAL", "T1562.008 - Disable Cloud Logs",
     "클라우드 감사 로그(CloudTrail 등)를 중지하거나 삭제하는 이벤트가 발견됐습니다 — 이후 활동의 증거를 남기지 않으려는 안티포렌식 행위입니다.",
     "로깅을 즉시 재활성화하고, 로깅이 꺼져 있던 구간에 다른 로그 소스(VPC Flow Logs, 애플리케이션 로그 등)로 활동을 재구성할 수 있는지 확인하세요."),
    (re.compile(r"PutUserPolicy|AttachUserPolicy|CreateAccessKey", re.I),
     "persistence_mechanism", "HIGH", "T1098 - Account Manipulation",
     "IAM 계정에 정책을 부여하거나 새 액세스 키를 발급하는 이벤트가 발견됐습니다 — 권한 상승 또는 지속적인 접근권 확보 시도일 수 있습니다.",
     "해당 변경이 승인된 작업인지 확인하고, 승인되지 않았다면 부여된 정책을 제거하고 발급된 키를 즉시 폐기하세요."),
    # 방화벽/스위치 로그(network_device_log)용
    (re.compile(r"configured from console by \S+", re.I),
     "evidence_of_compromise", "MEDIUM", "T1078 - Valid Accounts",
     "장비 설정이 콘솔/원격 세션을 통해 변경된 이력이 발견됐습니다 — 변경 주체와 시점이 정상 변경관리 절차와 일치하는지 확인이 필요합니다.",
     "변경 계정의 소유자와 실제 승인 여부를 담당자에게 확인하고, 미승인 변경이면 계정 자격증명을 재발급하세요."),
    (re.compile(r"permit\s+ip\s+any\s+host\s+((?:\d{1,3}\.){3}\d{1,3})", re.I),
     "data_exfiltration_evidence", "HIGH", "T1048 - Exfiltration Over Alternative Protocol",
     "낯선 목적지 IP로의 아웃바운드 트래픽을 허용하는 규칙이 로그에서 발견됐습니다 — 데이터 유출 경로로 악용됐을 수 있습니다.",
     "해당 규칙의 등록 경위를 확인하고, 필요하지 않다면 즉시 제거한 뒤 해당 목적지와의 실제 트래픽 발생 여부를 확인하세요."),
    # Fortinet FortiGate (key=value 로그 형식)
    (re.compile(r'logdesc="Policy configuration changed"', re.I),
     "evidence_of_compromise", "MEDIUM", "T1078 - Valid Accounts",
     "FortiGate 정책 설정이 변경된 로그가 발견됐습니다 — 변경 주체와 시점이 정상 변경관리 절차와 일치하는지 확인이 필요합니다.",
     "로그의 관리자 계정과 변경 내용을 확인하고, 미승인 변경이면 즉시 이전 설정으로 롤백하세요."),
    (re.compile(r'logdesc="Logging disabled"|log-setting[^\n]{0,40}disable', re.I),
     "anti_forensic_technique", "HIGH", "T1562.008 - Disable Cloud Logs",
     "FortiGate 로깅이 비활성화된 흔적이 발견됐습니다 — 이후 활동의 증거를 남기지 않으려는 시도일 수 있습니다.",
     "로깅을 즉시 재활성화하고, 비활성 구간의 활동을 다른 로그 소스(FortiAnalyzer 등)로 재구성할 수 있는지 확인하세요."),
    # Palo Alto Networks (PAN-OS)
    (re.compile(r"commit succeeded[^\n]{0,60}admin[:=\s]*[\w.-]+", re.I),
     "evidence_of_compromise", "MEDIUM", "T1078 - Valid Accounts",
     "Palo Alto 장비에 설정 변경이 커밋(commit)된 로그가 발견됐습니다 — 변경 계정과 승인 여부 확인이 필요합니다.",
     "commit을 수행한 계정 소유자에게 실제 변경 여부를 확인하고, 미승인 변경이면 이전 설정으로 롤백하세요."),
    # Juniper (Junos) — UI_COMMIT은 잘 문서화된 안정적인 syslog 메시지 이름
    (re.compile(r"UI_COMMIT", re.I),
     "evidence_of_compromise", "MEDIUM", "T1078 - Valid Accounts",
     "Junos 장비에서 설정 커밋(commit) 이벤트(UI_COMMIT)가 발견됐습니다 — 변경 계정과 승인 여부 확인이 필요합니다.",
     "commit을 수행한 계정 소유자에게 실제 변경 여부를 확인하고, 미승인 변경이면 이전 설정으로 롤백하세요."),
]

_BRUTE_FORCE_RE = re.compile(r"\b4625\b|로그온\s*실패|logon\s*fail", re.I)


def _brute_force_check(content: str) -> dict | None:
    count = len(_BRUTE_FORCE_RE.findall(content))
    if count >= 5:
        return _mk(
            f"로그온 실패 관련 항목 {count}건",
            "evidence_of_compromise", "HIGH", "T1110 - Brute Force",
            f"짧은 구간에 로그온 실패로 추정되는 항목이 {count}건 발견됐습니다 — 브루트포스/자격증명 스터핑 공격의 전형적인 패턴입니다.",
            "해당 계정의 비밀번호를 재설정하고 계정 잠금 정책과 MFA를 적용하세요.",
        )
    return None


def _timeline_gap_check(content: str) -> dict | None:
    timestamps = []
    for m in _TS_RE.findall(content):
        try:
            timestamps.append(datetime.strptime(m.replace("T", " "), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
    if len(timestamps) < 3:
        return None
    timestamps.sort()
    max_gap = None
    gap_start = gap_end = None
    for a, b in zip(timestamps, timestamps[1:]):
        gap = (b - a).total_seconds()
        if max_gap is None or gap > max_gap:
            max_gap, gap_start, gap_end = gap, a, b
    if max_gap and max_gap > 3600:
        hours = max_gap / 3600
        return _mk(
            f"{gap_start} ~ {gap_end}",
            "timeline_gap", "LOW" if hours < 6 else "MEDIUM", "",
            f"타임라인 상 {gap_start}부터 {gap_end}까지 약 {hours:.1f}시간 동안 기록된 이벤트가 없습니다 — 로그 미수집 구간일 수도 있고, 의도적인 로그 삭제로 생긴 공백일 수도 있습니다.",
            "해당 구간에 다른 로그 소스(방화벽, 프록시, EDR 등)에 관련 기록이 있는지 교차 확인하세요.",
        )
    return None


def analyze_offline(artifact_type: str, content: str, context: str) -> dict:
    findings: list[dict] = []

    for rx, issue_type, severity, mitre, desc, rec in _STATIC_CHECKS:
        m = rx.search(content)
        if m:
            findings.append(_mk(m.group(0), issue_type, severity, mitre, desc, rec))

    bf = _brute_force_check(content)
    if bf:
        findings.append(bf)

    gap = _timeline_gap_check(content)
    if gap:
        findings.append(gap)

    iocs = sorted(set(_IPV4_RE.findall(content)))[:5] + sorted(set(_URL_RE.findall(content)))[:5]

    if not findings:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위험 패턴이 발견되지 않았습니다. 이 엔진이 모르는 문제는 놓칠 수 있습니다."
        overall_severity = "INFO"
    else:
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        if crit:
            summary = f"규칙 기반 오프라인 분석에서 심각(CRITICAL) {crit}건을 포함해 총 {len(findings)}건의 흔적이 발견됐습니다."
            overall_severity = "CRITICAL"
        elif high:
            summary = f"규칙 기반 오프라인 분석에서 높음(HIGH) {high}건을 포함해 총 {len(findings)}건의 흔적이 발견됐습니다."
            overall_severity = "HIGH"
        else:
            summary = f"규칙 기반 오프라인 분석에서 총 {len(findings)}건의 참고할 만한 흔적이 발견됐습니다."
            overall_severity = "MEDIUM"

    return {
        "summary": summary,
        "overall_severity": overall_severity,
        "timeline": [],
        "findings": findings,
        "iocs": iocs,
        "engine_note": (
            "이 결과는 네트워크 연결 없이 동작하는 규칙 기반 오프라인 분석 엔진이 생성했습니다 — "
            "AI가 아니라 사전 정의된 패턴(로그 삭제, 인코딩된 PowerShell, Run 키, 원격 실행 도구, "
            "프로세스 위장, 반복된 로그온 실패, 타임라인 공백, 클라우드 루트계정/CloudTrail 중지/IAM "
            "조작, Cisco·Fortinet·Palo Alto·Juniper 설정 변경 이벤트)과의 매칭 결과이므로, 사건을 "
            "서사적으로 재구성하는 timeline은 만들지 못합니다(타임라인 공백 탐지만 가능). Cisco/Juniper의 "
            "패턴은 공식 문서화된 안정적인 로그 메시지라 신뢰도가 높지만, Fortinet/Palo Alto는 필드 "
            "구성이 버전·설정에 따라 달라질 수 있어 상대적으로 놓치는 경우가 많을 수 있습니다. 인터넷 "
            "또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 권장합니다."
        ),
    }
