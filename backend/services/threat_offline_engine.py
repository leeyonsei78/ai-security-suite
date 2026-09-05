"""App 7(위협 분석 랩)의 오프라인(폐쇄망) 모드 — 4개 입력 유형(malware/forensics/memory/
threat_intel) 각각에 대해 실제 입력 텍스트를 정규식/키워드로 분석한다.

threat_intel(위협 행위자 프로파일링)은 정직하게 한계를 인정한다: 실제 행위자 귀속(attribution)은
로컬 위협 인텔리전스 DB 없이는 근본적으로 불가능하므로, 이 엔진은 행위자를 지어내지 않고
"알 수 없음"으로 명시한 채 입력에서 뽑아낼 수 있는 IOC/기법 키워드만 정리해 보여준다.
"""
import re

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 규칙/정규식 기반 오프라인 분석 엔진이 생성했습니다 — "
    "AI가 아니라 사전 정의된 패턴과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁고 새롭거나 "
    "변형된 위협은 놓칠 수 있습니다. 인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 "
    "재분석하는 것을 권장합니다."
)

_IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.(?:[a-zA-Z]{2,}\.)?(?:com|net|org|io|ru|cn|info|xyz|top|club|kr)\b(?:\[?\.\]?)?", re.I),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.I),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "registry": re.compile(r"\bHK(?:LM|CU|CR|U)\\[^\s\"']+", re.I),
}

# 흔히 언급되는 기법 키워드 → MITRE ATT&CK 매핑(정확한 자동 귀속이 아니라 best-effort 안내용)
_TECHNIQUE_KEYWORDS = [
    (re.compile(r"powershell|-enc\b|encodedcommand", re.I), "T1059.001", "PowerShell", "Execution", "orange"),
    (re.compile(r"mshta", re.I), "T1218.005", "Mshta", "Defense Evasion", "purple"),
    (re.compile(r"scheduled task|schtasks", re.I), "T1053.005", "Scheduled Task", "Persistence", "yellow"),
    (re.compile(r"run key|\\run\\|currentversion\\run", re.I), "T1547.001", "Registry Run Keys / Startup", "Persistence", "yellow"),
    (re.compile(r"mimikatz|lsass|sekurlsa|credential dump", re.I), "T1003", "OS Credential Dumping", "Credential Access", "pink"),
    (re.compile(r"psexec|lateral movement|횡적 이동", re.I), "T1021", "Remote Services", "Lateral Movement", "teal"),
    (re.compile(r"amsi", re.I), "T1562.001", "Disable or Modify Tools (AMSI)", "Defense Evasion", "purple"),
    (re.compile(r"process hollowing|process injection|인젝션", re.I), "T1055", "Process Injection", "Defense Evasion", "purple"),
    (re.compile(r"c2|command and control|beacon|비콘", re.I), "T1071", "Application Layer Protocol (C2)", "Command and Control", "violet"),
    (re.compile(r"exfil|유출|압축.*전송|7zip|robocopy", re.I), "T1041", "Exfiltration Over C2 Channel", "Exfiltration", "amber"),
    (re.compile(r"phishing|피싱|스피어피싱", re.I), "T1566", "Phishing", "Initial Access", "red"),
    (re.compile(r"ransomware|랜섬웨어|암호화.*몸값|encrypt.*files", re.I), "T1486", "Data Encrypted for Impact", "Impact", "rose"),
    (re.compile(r"이벤트 로그.*삭제|wevtutil|clear.*log|vss.*삭제|shadow copy", re.I), "T1070", "Indicator Removal", "Defense Evasion", "purple"),
]

_TIMESTAMP_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\b")
_SEVERITY_KEYWORDS = [
    (re.compile(r"dump|덤프|delete.*log|삭제|exfil|유출|encrypt|암호화|mimikatz|c2\b", re.I), "CRITICAL"),
    (re.compile(r"inject|인젝션|lateral|횡적|psexec|privilege|권한 상승", re.I), "HIGH"),
]


def _extract_iocs(text: str) -> list[dict]:
    iocs = []
    seen = set()
    for ioc_type, rx in _IOC_PATTERNS.items():
        for m in rx.finditer(text):
            value = m.group(0)
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "description": "입력 텍스트에서 패턴 매칭으로 추출됨"})
    return iocs[:20]


def _extract_techniques(text: str) -> list[dict]:
    techniques = []
    seen = set()
    for rx, tid, name, tactic, color in _TECHNIQUE_KEYWORDS:
        if rx.search(text) and tid not in seen:
            seen.add(tid)
            techniques.append({"id": tid, "name": name, "tactic": tactic, "color": color})
    return techniques


def _line_severity(line: str) -> str:
    for rx, sev in _SEVERITY_KEYWORDS:
        if rx.search(line):
            return sev
    return "MEDIUM"


def _overall_threat_level(signal_count: int, has_critical: bool) -> str:
    if has_critical or signal_count >= 4:
        return "CRITICAL" if has_critical else "HIGH"
    if signal_count >= 2:
        return "HIGH"
    if signal_count >= 1:
        return "MEDIUM"
    return "LOW"


def _analyze_malware(text: str) -> dict:
    iocs = _extract_iocs(text)
    techniques = _extract_techniques(text)
    capabilities = []
    cap_map = [
        (r"keylog|키로깅", "키로깅 의심"),
        (r"screenshot|화면 캡처|screen capture", "화면 캡처 의심"),
        (r"clipboard|클립보드", "클립보드 탈취 의심"),
        (r"credential|자격증명|비밀번호.*탈취|browser.*password", "자격증명 탈취 의심"),
        (r"upload|download|파일.*전송", "파일 업로드/다운로드 기능 의심"),
    ]
    for pattern, label in cap_map:
        if re.search(pattern, text, re.I):
            capabilities.append(label)

    threat_level = _overall_threat_level(len(techniques), any(t["tactic"] in ("Impact", "Exfiltration") for t in techniques))
    return {
        "analysis_type": "malware",
        "malware_type": "규칙 기반으로는 특정 불가 — 아래 기능/기법 패턴 참고",
        "threat_level": threat_level,
        "confidence": min(90, 30 + 10 * (len(techniques) + len(iocs))),
        "summary": f"규칙 기반 오프라인 분석에서 IOC {len(iocs)}건, MITRE 기법 패턴 {len(techniques)}건, 악성 기능 의심 신호 {len(capabilities)}건을 발견했습니다.",
        "capabilities": capabilities or ["규칙 기반 분석에서 뚜렷한 기능 신호를 찾지 못했습니다"],
        "iocs": iocs,
        "mitre_techniques": techniques,
        "behavior": {
            "network": "IOC 섹션의 IP/도메인/URL 참고" if iocs else "네트워크 관련 신호 없음",
            "file_system": "-", "registry": "-", "processes": "-",
        },
        "recommendations": [
            "발견된 IOC(IP/도메인/해시)를 방화벽·EDR에 등록해 추가 확산을 차단하세요.",
            "AI 모드(Cloud/로컬 LLM)로 재분석하면 더 상세한 행위 분석을 받을 수 있습니다.",
        ],
    }


def _analyze_forensics(text: str) -> dict:
    lines = text.splitlines()
    timeline = []
    for line in lines:
        m = _TIMESTAMP_RE.search(line)
        if m:
            timeline.append({"time": m.group(1), "event": line.strip()[:200], "severity": _line_severity(line)})
    timeline.sort(key=lambda e: e["time"])

    iocs = _extract_iocs(text)
    artifacts = [{"type": "ip" if ioc["type"] == "ip" else "file", "value": ioc["value"], "suspicious": True,
                  "description": "IOC 패턴 매칭으로 추출됨"} for ioc in iocs[:10]]

    findings = []
    if timeline:
        findings.append(f"타임스탬프가 포함된 이벤트 {len(timeline)}건을 시간순으로 정렬했습니다.")
    if any(re.search(r"삭제|delete|wevtutil|clear", e["event"], re.I) for e in timeline):
        findings.append("로그/증거 삭제 시도로 보이는 이벤트가 발견되어 안티포렌식(흔적 지우기) 가능성이 있습니다.")

    has_critical = any(e["severity"] == "CRITICAL" for e in timeline)
    threat_level = _overall_threat_level(len(timeline), has_critical)
    return {
        "analysis_type": "forensics",
        "threat_level": threat_level,
        "confidence": min(85, 30 + 5 * len(timeline)),
        "summary": f"규칙 기반 오프라인 분석에서 타임스탬프 포함 이벤트 {len(timeline)}건, IOC {len(iocs)}건을 발견했습니다.",
        "timeline": timeline or [{"time": "N/A", "event": "타임스탬프 패턴(YYYY-MM-DD HH:MM:SS)을 가진 로그 라인을 찾지 못했습니다", "severity": "LOW"}],
        "artifacts": artifacts,
        "findings": findings or ["규칙 기반 분석에서 뚜렷한 발견 사항이 없습니다 — AI 모드로 재분석을 권장합니다."],
        "recommendations": [
            "타임라인상 최초 이벤트 시점 전후의 로그를 추가로 수집·보존하세요.",
            "AI 모드(Cloud/로컬 LLM)로 재분석하면 공격 단계별 해석을 받을 수 있습니다.",
        ],
    }


_MASQUERADE_RE = re.compile(r"\b(svch0st|scvhost|lsas+\d|explor3r|exp1orer|iexplor3|csrs+\d)\b", re.I)
_ENCODED_PS_RE = re.compile(r"-enc(odedcommand)?\b|FromBase64String", re.I)
_ESTABLISHED_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}:\d+\s+(?:->\s*)?((?:\d{1,3}\.){3}\d{1,3}):(\d+)\s+ESTABLISHED", re.I)
_PRIVATE_IP_RE = re.compile(r"^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0)")
_PROC_LINE_RE = re.compile(r"\bPID[:\s]+(\d+).{0,60}?\b(?:parent|ppid)[:\s]+(\d+)", re.I)


def _analyze_memory(text: str) -> dict:
    suspicious_processes = []
    if _MASQUERADE_RE.search(text):
        m = _MASQUERADE_RE.search(text)
        suspicious_processes.append({
            "pid": 0, "name": m.group(0), "parent_pid": 0, "parent_name": "?",
            "risk": "HIGH", "issue": "정상 시스템 프로세스와 이름이 유사하지만 철자가 다른 프로세스(마스커레이딩 의심)",
        })

    network_artifacts = []
    for m in _ESTABLISHED_RE.finditer(text):
        ip = m.group(1)
        suspicious = not bool(_PRIVATE_IP_RE.match(ip))
        network_artifacts.append({
            "local": "-", "remote": f"{ip}:{m.group(2)}", "state": "ESTABLISHED",
            "process": "-", "suspicious": suspicious,
        })

    strings_of_interest = []
    if _ENCODED_PS_RE.search(text):
        strings_of_interest.append("인코딩된 PowerShell 명령(-enc/-EncodedCommand 또는 FromBase64String) 발견")

    signal_count = len(suspicious_processes) + sum(1 for n in network_artifacts if n["suspicious"]) + len(strings_of_interest)
    threat_level = _overall_threat_level(signal_count, False)
    return {
        "analysis_type": "memory",
        "threat_level": threat_level,
        "confidence": min(80, 25 + 15 * signal_count),
        "summary": f"규칙 기반 오프라인 분석에서 의심 프로세스 {len(suspicious_processes)}건, 외부 네트워크 연결 {sum(1 for n in network_artifacts if n['suspicious'])}건, 인코딩된 명령 {len(strings_of_interest)}건을 발견했습니다.",
        "suspicious_processes": suspicious_processes,
        "injected_code": [],
        "network_artifacts": network_artifacts,
        "strings_of_interest": strings_of_interest or ["규칙 기반 분석에서 주목할 문자열을 찾지 못했습니다"],
        "recommendations": [
            "외부 IP로의 활성 연결이 있다면 평판 조회 후 차단하세요.",
            "AI 모드(Cloud/로컬 LLM)로 재분석하면 프로세스 인젝션 등 더 깊은 분석을 받을 수 있습니다.",
        ],
    }


def _analyze_threat_intel(text: str) -> dict:
    iocs = _extract_iocs(text)
    techniques = _extract_techniques(text)
    return {
        "analysis_type": "threat_intel",
        "threat_level": _overall_threat_level(len(techniques), False),
        "confidence": 20,  # 행위자 귀속은 로컬 규칙으로 신뢰도 있게 할 수 없음을 낮은 confidence로 명시
        "summary": (
            f"규칙 기반 오프라인 분석에서는 위협 행위자를 특정할 수 없습니다(로컬 위협 인텔리전스 "
            f"데이터베이스 없음). 대신 입력에서 IOC {len(iocs)}건, MITRE 기법 키워드 {len(techniques)}건을 "
            "추출했습니다 — 아래 기법을 실제 위협 인텔리전스 피드(MITRE ATT&CK Navigator, 벤더 리포트 등)와 "
            "직접 대조해보세요."
        ),
        "threat_actor": {
            "name": "알 수 없음 (오프라인 모드 — 행위자 귀속 불가)",
            "aliases": [], "origin": "-", "motivation": "-", "active_since": "-",
            "targets": [], "sophistication": "-",
        },
        "mitre_techniques": techniques,
        "similar_campaigns": [],
        "detection_opportunities": [f"IOC {ioc['value']} ({ioc['type']}) 모니터링" for ioc in iocs[:5]] or ["규칙 기반 분석에서 추출된 IOC가 없습니다"],
        "recommendations": [
            "행위자 귀속이 필요하면 인터넷 또는 로컬 LLM 연결 후 AI 모드로 재분석하세요.",
            "추출된 IOC를 오프라인으로 반입한 위협 인텔리전스 피드/CSV와 직접 대조하세요.",
        ],
    }


_ANALYZERS = {
    "malware": _analyze_malware,
    "forensics": _analyze_forensics,
    "memory": _analyze_memory,
    "threat_intel": _analyze_threat_intel,
}


def analyze_offline(analysis_type: str, input_data: str, context: str) -> dict:
    analyzer = _ANALYZERS.get(analysis_type, _analyze_malware)
    text = f"{context}\n{input_data}" if context else input_data
    result = analyzer(text)
    result["engine_note"] = ENGINE_DISCLAIMER
    return result
