import os
import json
from dotenv import load_dotenv
from services.mock_firewall_audit import generate_mock_audit

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

SOURCE_LABELS = {
    "iptables": "Linux iptables/nftables",
    "aws_sg": "AWS 보안그룹(Security Group)",
    "azure_nsg": "Azure NSG(네트워크 보안 그룹)",
    "gcp_fw": "GCP 방화벽 규칙(Firewall Rules)",
    "router_switch": "라우터/스위치 (Cisco IOS 등)",
    "windows_fw": "Windows 방화벽",
    "other": "기타/벤더 장비 (Fortinet, Palo Alto 등)",
}

ISSUE_TYPE_LABELS = {
    "overly_permissive": "과도 허용",
    "redundant": "중복 규칙",
    "shadowed": "가려진 규칙 (Shadowed)",
    "unused": "미사용/근거 불명",
    "conflicting": "충돌 규칙",
    "missing_control": "누락된 통제",
    "compliance_gap": "컴플라이언스 위반",
    "insecure_management": "안전하지 않은 관리 방식",
    "weak_authentication": "취약한 인증/자격증명",
    "other": "기타",
}

SYSTEM_PROMPT = """You are a senior network security auditor reviewing an EXISTING firewall rule set OR router/switch device configuration (not drafting a new one) to find what is wrong and what should change.

The user provides: the platform type, the raw rule text/config export, and optional environment context.

For each problem you find, cite the specific rule/config line (by index, name, or the text itself) and classify it. Look specifically for:
- overly_permissive: rules allowing overly broad source/destination/port (e.g. 0.0.0.0/0 on management or database ports, "any-any" rules)
- redundant: duplicate rules with no effect beyond clutter
- shadowed: a broad rule earlier in evaluation order makes a later, more specific rule unreachable
- conflicting: rules that contradict each other (one allows what another denies for the same traffic)
- unused: rules with no clear justification, stale comments, or clearly dead references
- missing_control: important controls that are absent entirely (e.g. no outbound restriction, no logging, no port security, no AAA)
- compliance_gap: a violation of a common compliance requirement, only when clearly applicable
- insecure_management: for router/switch configs specifically — insecure management protocols or exposure (e.g. Telnet enabled instead of SSH-only, SNMP v1/v2c with a default/guessable community string like "public"/"private", HTTP management server enabled instead of HTTPS-only, no access-class restricting VTY lines)
- weak_authentication: for router/switch configs specifically — weak credential/authentication handling (e.g. reversible "enable password" instead of "enable secret", plaintext/type-7 passwords, no AAA/TACACS+/RADIUS, shared local accounts instead of per-admin accounts, missing password complexity)

insecure_management and weak_authentication are only relevant to router/switch device configs — do not use them for cloud/firewall rule sets where they don't apply.

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the policy/configuration's overall security posture and the most pressing issue",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "findings": [
    {
      "rule_reference": "the specific rule/config line, name, or index this finding is about",
      "issue_type": "overly_permissive|redundant|shadowed|conflicting|unused|missing_control|compliance_gap|insecure_management|weak_authentication|other",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what is wrong and why it matters, specific to this rule",
      "recommendation": "the concrete fix — ideally the corrected rule or exact command/config change"
    }
  ],
  "compliance_notes": [
    {"framework": "name of a compliance framework this policy risks violating (only if genuinely applicable)", "note": "which requirement and why"}
  ]
}

Only flag real issues actually present in the given rules — do not invent problems. If the rule set looks reasonably sound, return few findings and a low overall_risk. Respond in Korean for all natural-language fields."""


def _real_analyze(source_type: str, content: str, context: str) -> dict:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    label = SOURCE_LABELS.get(source_type, source_type)
    context_line = f"\n환경 컨텍스트: {context}" if context.strip() else ""
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"방화벽 플랫폼: {label}{context_line}\n\n방화벽 규칙:\n{content}",
        }],
    )
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

    if not data.get("overall_risk"):
        top = findings[0]["severity"] if findings else "INFO"
        data["overall_risk"] = top

    data["findings"] = findings
    data["stats"] = stats
    data.setdefault("compliance_notes", [])
    return data


def analyze_firewall(source_type: str, content: str, context: str) -> dict:
    if IS_MOCK:
        return _enrich(generate_mock_audit(source_type, content, context))
    return _enrich(_real_analyze(source_type, content, context))


def generate_markdown_report(entry: dict) -> str:
    label = SOURCE_LABELS.get(entry.get("source_type", ""), entry.get("source_type", "N/A"))
    lines = [
        "# 방화벽 정책 감사 리포트",
        "",
        f"**대상 플랫폼:** {label}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        "> AI가 붙여넣은 규칙 텍스트만으로 분석한 결과입니다. 실제 반영 전 담당자 검토와 스테이징 환경 검증을 거치세요.",
        "",
        "---",
        "",
        "## 종합 평가",
        "",
        entry.get("summary", ""),
        "",
        "## 발견 사항 요약",
        "",
    ]
    stats = entry.get("stats", {})
    lines.append(f"전체 {stats.get('total', 0)}건 — CRITICAL {stats.get('critical', 0)} / HIGH {stats.get('high', 0)} / MEDIUM {stats.get('medium', 0)} / LOW {stats.get('low', 0)} / INFO {stats.get('info', 0)}")
    lines += ["", "---", "", "## 상세 발견 사항", ""]

    for f in entry.get("findings", []):
        lines += [
            f"### [{f.get('severity')}] {f.get('issue_type_label', f.get('issue_type'))}",
            "",
            f"**해당 규칙:** `{f.get('rule_reference', '')}`  ",
            "",
            f"{f.get('description', '')}",
            "",
            f"**권장 조치:** {f.get('recommendation', '')}",
            "",
            "---",
            "",
        ]

    compliance_notes = entry.get("compliance_notes") or []
    if compliance_notes:
        lines += ["## 컴플라이언스 참고", "", "> 참고용이며, 정확한 인증기준 충족 여부는 전문가 검토가 필요합니다.", ""]
        for c in compliance_notes:
            lines.append(f"- **{c.get('framework')}:** {c.get('note')}")
        lines.append("")

    lines += [
        "## 다음 단계",
        "",
        "- 위 권장 조치를 반영한 새 정책 초안이 필요하다면 [보안 정책 생성기](/policy)를 이용해 환경을 설명하고 다시 생성해보세요.",
        "- 규칙 반영 후에는 nmap -p- <대상 IP> 등으로 의도한 포트만 열려 있는지 실제로 재검증하세요.",
    ]

    return "\n".join(lines)
