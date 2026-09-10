import os
import json
from dotenv import load_dotenv
from services.mock_kese_kit import generate_mock_audit
from services.kese_kit_guide import ASSESSMENT_TYPES, ISSUE_TYPE_LABELS, DISCLAIMER
from services.kese_kit_offline_engine import analyze_offline
from services import mode_manager, local_llm_client, usage_log

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a Korean information-security compliance reviewer familiar with KISA
(한국인터넷진흥원, Korea Internet & Security Agency) public guidelines covering Critical Information
Infrastructure (CII), AI security, robot security, space security, secure coding, Zero Trust, and
SW supply chain security (SBOM). The user gives you an assessment type, the relevant domain list with
item counts for that type, and free-text describing either actual system configuration, source code,
or a security posture/policy description relevant to that domain.

Review the given content against the given domains and flag concrete gaps. For each finding, cite the
specific part of the input it's about, name which domain (from the given list, use the exact Korean name
verbatim) it belongs to, and classify it using one of these issue types:
- access_control_gap: weak/missing access control, authentication, MFA, excessive privilege, default credentials
- network_segmentation_gap: missing network segmentation, overly broad exposure (e.g. 0.0.0.0/0), insecure wireless/communication links
- encryption_key_gap: missing/weak encryption, hardcoded secrets, poor key management
- logging_monitoring_gap: insufficient logging, no centralized visibility/monitoring, no drift/anomaly detection
- patch_hardening_gap: missing patches, outdated/vulnerable software versions, missing firmware signature verification, missing vulnerability scanning
- secure_coding_flaw: concrete code-level vulnerabilities (injection, XSS, weak hashing, plaintext password compare, verbose error leakage, etc.) mapped to CWE where applicable
- supply_chain_gap: missing SBOM, unverified third-party/subcontractor components, missing artifact signing
- incident_resilience_gap: missing incident response/BCP/contingency plan, no RTO/RPO
- governance_policy_gap: missing/vague policy, governance, documented procedures, data validation procedures
- physical_personnel_gap: physical security or personnel security (background checks, training) not confirmed

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the overall posture and most pressing gap",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "findings": [
    {
      "domain": "one of the given domain names, verbatim",
      "rule_reference": "the specific part of the input this finding is about",
      "issue_type": "access_control_gap|network_segmentation_gap|encryption_key_gap|logging_monitoring_gap|patch_hardening_gap|secure_coding_flaw|supply_chain_gap|incident_resilience_gap|governance_policy_gap|physical_personnel_gap",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what is missing/wrong and why it matters for this specific domain",
      "recommendation": "the concrete fix",
      "maturity_level": "기존|초기|향상|최적화 (ONLY include this field for the zero_trust assessment type, otherwise omit it entirely)"
    }
  ],
  "compliance_notes": [
    {"framework": "관련 법령/표준 이름 (정보통신기반 보호법, 인공지능 기본법, IEC 62443, NIST SP 800-207 등)", "note": "어떤 요건과 관련 있는지"}
  ]
}

Only flag real issues actually inferable from the given content — do not invent problems not supported by
the input. If the input looks reasonably sound for the given domains, return few findings and a low
overall_risk. For the secure_coding assessment type specifically, treat the input as source code and look
for concrete code-level vulnerabilities rather than policy gaps.

If the given assessment type clearly does not match what the content is actually about (e.g. assessment
type is "AI 보안" but the content is obviously about generic server/network hardening with no AI-specific
angle, or vice versa), say so plainly in Korean at the start of the summary (e.g. "⚠️ 선택하신 평가
유형(AI 보안)과 실제 내용(일반 서버/네트워크 점검으로 보임)이 일치하지 않는 것 같습니다 — 평가
유형을 다시 확인하세요.") before proceeding with the review for the given assessment type.

Respond in Korean for all natural-language fields."""


def _real_analyze(assessment_type: str, content: str, context: str, backend: str = "cloud") -> dict:
    meta = ASSESSMENT_TYPES.get(assessment_type, ASSESSMENT_TYPES["cii"])
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
        usage_log.log_usage("kese_kit_audit", message.usage, model="claude-sonnet-4-6")
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
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else '외부 AI API'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(assessment_type, content, context)

    data["mode"] = mode
    return _enrich(data)


def generate_markdown_report(entry: dict) -> str:
    assessment_type = entry.get("assessment_type", "cii")
    meta = ASSESSMENT_TYPES.get(assessment_type, ASSESSMENT_TYPES["cii"])
    lines = [
        "# KISA 보안 가이드라인 종합 점검 리포트",
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
        maturity = f" (성숙도: {f['maturity_level']})" if f.get("maturity_level") else ""
        lines += [
            f"### [{f.get('severity')}] {f.get('domain', '')} — {f.get('issue_type_label', f.get('issue_type'))}{maturity}",
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
        lines += ["## 관련 법령/표준 참고", "", "> 참고용이며, 정확한 기준 충족 여부는 전문가 검토 및 KISA 공식 자료 확인이 필요합니다.", ""]
        for c in compliance_notes:
            lines.append(f"- **{c.get('framework')}:** {c.get('note')}")
        lines.append("")

    lines += [
        "## 다음 단계",
        "",
        "- 네트워크/IAM/코드 자체에 대한 더 상세한 점검은 [방화벽 정책 감사기](/firewall-audit), "
        "[클라우드 IAM 정책 감사기](/iam-audit), [취약점 스캐너](/vuln)를 함께 활용하세요.",
        "- 공식 점검 항목 원문과 최신 기준은 KISA 공식 자료(kisa.or.kr)를 반드시 확인하세요.",
    ]

    return "\n".join(lines)
