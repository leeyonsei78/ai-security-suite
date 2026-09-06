import os
import json
from dotenv import load_dotenv
from services.mock_forensics_audit import generate_mock_audit
from services.forensics_audit_offline_engine import analyze_offline
from services import mode_manager, local_llm_client, usage_log

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

ARTIFACT_LABELS = {
    "event_log": "시스템/보안 이벤트 로그",
    "browser_history": "브라우저 히스토리/다운로드 기록",
    "persistence_artifacts": "지속성 메커니즘 (자동 실행 등록)",
    "filesystem_timeline": "파일시스템 타임라인",
    "process_list": "실행 중 프로세스 목록",
    "cloud_audit_log": "클라우드 감사 로그",
    "network_device_log": "방화벽/스위치 로그",
}

ISSUE_TYPE_LABELS = {
    "evidence_of_compromise": "침해 증거",
    "anti_forensic_technique": "안티포렌식 기법",
    "persistence_mechanism": "지속성 메커니즘",
    "data_exfiltration_evidence": "데이터 유출 증거",
    "lateral_movement_evidence": "내부 이동 증거",
    "timeline_gap": "타임라인 공백/조작 의심",
    "other": "기타",
}

SYSTEM_PROMPT = """You are a senior DFIR (Digital Forensics & Incident Response) analyst reviewing artifacts
collected during an investigation to reconstruct what happened and find evidence of compromise. The
artifact may come from any platform — Windows/Linux/macOS event or auth logs, browser history, OS-specific
persistence mechanisms (Windows Run keys, Linux cron/systemd, macOS LaunchAgents), filesystem timelines,
process lists, cloud provider audit logs (AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs), or
network device logs (Cisco IOS, FortiGate, Palo Alto, Juniper) — infer the platform from the artifact_type
and the content itself, and interpret platform-specific fields/commands accordingly.

The user provides: the artifact type, the raw artifact text, and optional investigation context.

Reconstruct a plausible timeline of events from the artifact (only using timestamps/ordering actually
present in the data — do not invent timestamps), then classify each finding you make using:
- evidence_of_compromise: direct evidence an attacker was present or acted (malicious process, suspicious login, masquerading process name/path, unusual outbound connection referenced in the artifact, etc.)
- anti_forensic_technique: an attempt to hide or destroy evidence (event log clearing, timestomping, shadow copy deletion, self-deleting files)
- persistence_mechanism: a mechanism that keeps attacker access across reboots/logoffs (Run keys, scheduled tasks, services, startup folder entries)
- data_exfiltration_evidence: signs that data left the environment (uploads to unfamiliar destinations, unusual outbound volume, DNS/HTTP-based exfil patterns)
- lateral_movement_evidence: signs of movement to other hosts (PsExec/WMI/RDP usage, admin share access, pass-the-hash indicators)
- timeline_gap: a suspicious gap or inconsistency in the timeline that suggests missing or tampered logs
- other: anything real but not covered above

For each finding, cite the specific artifact line/value it is based on, and where applicable tag a MITRE ATT&CK technique ID (e.g. "T1070.001 - Clear Windows Event Logs"); leave mitre_technique empty ("") if none clearly applies.

Also extract any IOCs (IP addresses, domains, file names/hashes, account names) mentioned in the artifact that are worth tracking.

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of what likely happened, in plain language",
  "overall_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "timeline": [
    {"timestamp": "timestamp or ordering description from the artifact", "event": "what happened", "significance": "why this matters to the investigation"}
  ],
  "findings": [
    {
      "artifact_reference": "the specific line/value/event this finding is about",
      "issue_type": "evidence_of_compromise|anti_forensic_technique|persistence_mechanism|data_exfiltration_evidence|lateral_movement_evidence|timeline_gap|other",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "mitre_technique": "MITRE ATT&CK technique id and name, or empty string",
      "description": "what was found and why it matters",
      "recommendation": "concrete next investigative or containment step"
    }
  ],
  "iocs": ["extracted indicator strings"]
}

Only flag real issues actually present in the given artifact — do not invent problems or timestamps. If the artifact looks benign, return few findings, an empty or short timeline, and a low overall_severity. This is investigative support, not a legal/official forensic report. Respond in Korean for all natural-language fields."""


def _real_analyze(artifact_type: str, content: str, context: str, backend: str = "cloud") -> dict:
    label = ARTIFACT_LABELS.get(artifact_type, artifact_type)
    context_line = f"\n조사 컨텍스트: {context}" if context.strip() else ""
    user_prompt = f"아티팩트 유형: {label}{context_line}\n\n아티팩트 내용:\n{content}"

    if backend == "local":
        text = local_llm_client.call_local_llm(SYSTEM_PROMPT, user_prompt, max_tokens=4096)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        usage_log.log_usage("forensics_artifact_audit", message.usage, model="claude-sonnet-4-6")
        text = message.content[0].text

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Parse failed", "raw": text}


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _enrich(data: dict) -> dict:
    findings = data.get("findings", [])
    stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        f["issue_type_label"] = ISSUE_TYPE_LABELS.get(f.get("issue_type"), f.get("issue_type", ""))
        sev = f.get("severity", "INFO")
        stats[sev.lower()] = stats.get(sev.lower(), 0) + 1

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 0), reverse=True)

    if not data.get("overall_severity"):
        top = findings[0]["severity"] if findings else "INFO"
        data["overall_severity"] = top

    data["findings"] = findings
    data["stats"] = stats
    data.setdefault("timeline", [])
    data.setdefault("iocs", [])
    return data


async def analyze_artifact(artifact_type: str, content: str, context: str) -> dict:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_audit(artifact_type, content, context)
    elif mode in ("local", "cloud"):
        try:
            data = _real_analyze(artifact_type, content, context, backend=mode)
        except Exception as e:
            data = analyze_offline(artifact_type, content, context)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else '외부 AI API'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(artifact_type, content, context)

    data["mode"] = mode
    return _enrich(data)


def generate_markdown_report(entry: dict) -> str:
    label = ARTIFACT_LABELS.get(entry.get("artifact_type", ""), entry.get("artifact_type", "N/A"))
    lines = [
        "# 포렌식 아티팩트 감사 리포트",
        "",
        f"**아티팩트 유형:** {label}  ",
        f"**종합 심각도:** {entry.get('overall_severity', 'N/A')}  ",
        "",
        "> AI가 붙여넣은 아티팩트 텍스트만으로 분석한 조사 지원 자료입니다. 법적 절차에 쓰이는 공식",
        "> 포렌식 보고서를 대체하지 않으며, 자격을 갖춘 담당자의 검토가 필요합니다.",
        "",
        "---",
        "",
        "## 종합 평가",
        "",
        entry.get("summary", ""),
        "",
    ]

    timeline = entry.get("timeline") or []
    if timeline:
        lines += ["## 재구성된 타임라인", ""]
        for t in timeline:
            lines.append(f"- **{t.get('timestamp', '')}** — {t.get('event', '')} _{t.get('significance', '')}_")
        lines.append("")

    stats = entry.get("stats", {})
    lines += [
        "## 발견 사항 요약",
        "",
        f"전체 {stats.get('total', 0)}건 — CRITICAL {stats.get('critical', 0)} / HIGH {stats.get('high', 0)} / MEDIUM {stats.get('medium', 0)} / LOW {stats.get('low', 0)} / INFO {stats.get('info', 0)}",
        "",
        "---",
        "",
        "## 상세 발견 사항",
        "",
    ]

    for f in entry.get("findings", []):
        mitre = f" (`{f.get('mitre_technique')}`)" if f.get("mitre_technique") else ""
        lines += [
            f"### [{f.get('severity')}] {f.get('issue_type_label', f.get('issue_type'))}{mitre}",
            "",
            f"**근거:** `{f.get('artifact_reference', '')}`  ",
            "",
            f"{f.get('description', '')}",
            "",
            f"**다음 조치:** {f.get('recommendation', '')}",
            "",
            "---",
            "",
        ]

    iocs = entry.get("iocs") or []
    if iocs:
        lines += ["## 추출된 IOC", ""]
        for ioc in iocs:
            lines.append(f"- `{ioc}`")
        lines.append("")

    lines += [
        "## 다음 단계",
        "",
        "- 추출된 IOC는 [IoC 분석기](/ioc)로 평판을 추가 확인해보세요.",
        "- 침해 계정의 권한 범위를 확인하려면 [클라우드 IAM 정책 감사기](/iam-audit)를,",
        "  네트워크 경로를 확인하려면 [방화벽 정책 감사기](/firewall-audit)를 이어서 활용하세요.",
        "- 실제 조사에 필요한 추가 증거는 '증거 수집 도구' 탭에서 이 PC의 실제 아티팩트를 수집해보세요.",
    ]

    return "\n".join(lines)
