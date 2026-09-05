import os
import json
from dotenv import load_dotenv
from services.mock_fsi_csp_audit import generate_mock_audit
from services.fsi_csp_audit_guide import ASSESSMENT_TYPES, ISSUE_TYPE_LABELS, DISCLAIMER
from services.fsi_csp_audit_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a financial-sector cloud security compliance reviewer familiar with South Korea's
Financial Security Institute (금융보안원, FSI) cloud security framework. The user gives you an assessment
type (either "csp_assessment" — evaluating a Cloud Service Provider's own organizational security posture
across 11 domains, or "cloud_env_management" — evaluating a financial company's own configured cloud
environment across 5 domains), the relevant domain list with item counts, and free-text describing either
the CSP's security posture/self-assessment answers or actual cloud environment configuration.

Review the given content against the given domains and flag concrete gaps. For each finding, cite the
specific part of the input it's about, name which domain (from the given list, use the exact Korean name)
it belongs to, and classify it using one of these issue types:
- policy_gap: missing/vague information security policy, organization, or governance structure
- access_control_weakness: weak access control, missing MFA, overly broad network/IP exposure, poor segregation of duties
- encryption_gap: missing/weak encryption, hardcoded secrets, poor key management
- monitoring_gap: insufficient logging, short retention, no real-time monitoring/alerting
- incident_response_gap: vague or missing incident notification timelines/procedures
- continuity_gap: missing DR/BCP details, no RTO/RPO, no continuity testing
- supply_chain_risk: undisclosed subcontractors/resellers, unclear third-party access
- physical_security_gap: physical security of data centers not confirmed
- compliance_gap: anything else relevant to Korean financial cloud compliance (전자금융감독규정, 개인정보보호법 등)

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the overall posture and most pressing gap",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "findings": [
    {
      "domain": "one of the given domain names, verbatim",
      "rule_reference": "the specific part of the input this finding is about",
      "issue_type": "policy_gap|access_control_weakness|encryption_gap|monitoring_gap|incident_response_gap|continuity_gap|supply_chain_risk|physical_security_gap|compliance_gap",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what is missing/wrong and why it matters for a Korean financial institution specifically",
      "recommendation": "the concrete fix"
    }
  ],
  "compliance_notes": [
    {"framework": "관련 규정/기준 이름 (전자금융감독규정, 금융보안원 CSP 안전성평가, 개인정보보호법 등)", "note": "어떤 요건과 관련 있는지"}
  ]
}

Only flag real issues actually inferable from the given content — do not invent problems not supported by
the input. If the input looks reasonably sound for the given domains, return few findings and a low
overall_risk. Respond in Korean for all natural-language fields."""


def _real_analyze(assessment_type: str, content: str, context: str, backend: str = "cloud") -> dict:
    meta = ASSESSMENT_TYPES.get(assessment_type, ASSESSMENT_TYPES["cloud_env_management"])
    domain_lines = "\n".join(f"- {d['name']} ({d['item_count']}개 항목)" for d in meta["domains"])
    context_line = f"\n환경/추가 컨텍스트: {context}" if context.strip() else ""
    user_prompt = (
        f"평가 유형: {meta['label']}\n대상 분야 목록:\n{domain_lines}{context_line}\n\n"
        f"점검 대상 입력:\n{content}"
    )

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


async def analyze(assessment_type: str, content: str, context: str) -> dict:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_audit(assessment_type, content, context)
    elif mode in ("local", "cloud"):
        try:
            data = _real_analyze(assessment_type, content, context, backend=mode)
        except Exception as e:
            data = analyze_offline(assessment_type, content, context)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(assessment_type, content, context)

    data["mode"] = mode
    return _enrich(data)


def generate_markdown_report(entry: dict) -> str:
    assessment_type = entry.get("assessment_type", "cloud_env_management")
    meta = ASSESSMENT_TYPES.get(assessment_type, ASSESSMENT_TYPES["cloud_env_management"])
    lines = [
        "# 금융보안원 클라우드 CSP 평가 리포트",
        "",
        f"**평가 유형:** {meta['label']}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        f"> {DISCLAIMER}",
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
            f"### [{f.get('severity')}] {f.get('domain', '')} — {f.get('issue_type_label', f.get('issue_type'))}",
            "",
            f"**해당 부분:** `{f.get('rule_reference', '')}`  ",
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
        lines += ["## 관련 규정/기준 참고", "", "> 참고용이며, 정확한 기준 충족 여부는 전문가 검토 및 금융보안원 공식 자료 확인이 필요합니다.", ""]
        for c in compliance_notes:
            lines.append(f"- **{c.get('framework')}:** {c.get('note')}")
        lines.append("")

    lines += [
        "## 다음 단계",
        "",
        "- 네트워크/IAM 설정 자체에 대한 더 상세한 점검은 [방화벽 정책 감사기](/firewall-audit), [클라우드 IAM 정책 감사기](/iam-audit)를 함께 활용하세요.",
        "- 공식 CSP 안전성평가·이용보고 절차는 금융보안원 공식 자료(fsec.or.kr, regtech.fsec.or.kr, csp.fsec.or.kr)를 반드시 확인하세요.",
    ]

    return "\n".join(lines)
