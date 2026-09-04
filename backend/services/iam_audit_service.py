import os
import json
from dotenv import load_dotenv
from services.mock_iam_audit import generate_mock_audit

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

SOURCE_LABELS = {
    "aws_iam": "AWS IAM",
    "azure_rbac": "Azure RBAC",
    "gcp_iam": "GCP IAM",
}

ISSUE_TYPE_LABELS = {
    "excessive_privilege": "과도한 권한",
    "missing_mfa": "MFA 미적용",
    "stale_credential": "오래된/미사용 자격증명",
    "privilege_escalation_path": "권한 상승 경로",
    "misconfigured_trust": "잘못된 신뢰 관계/공개 노출",
    "shared_credential": "공유 계정/자격증명",
    "other": "기타",
}

SYSTEM_PROMPT = """You are a senior cloud IAM security auditor reviewing EXISTING identity and access management configuration (policies, role assignments, users, service accounts, credentials) — not designing new permissions from scratch — to find what is wrong.

The user provides: the cloud IAM platform type, the raw policy/user/role export text, and optional environment context.

For each problem you find, cite the specific policy statement, role assignment, user, or credential (by name/ARN/ID or the text itself) and classify it. Look specifically for:
- excessive_privilege: permissions broader than needed (wildcard actions/resources like "*:*", admin-equivalent roles attached directly to individual users instead of via groups/roles, unused permissions)
- missing_mfa: user/admin accounts without multi-factor authentication enabled
- stale_credential: access keys, secrets, or accounts that are old, unrotated, unused for a long time, or configured to never expire
- privilege_escalation_path: a permission combination that lets a principal grant themselves or others more privilege (e.g. iam:PutUserPolicy/iam:AttachUserPolicy on themselves, roleAssignments/write with broad scope, serviceAccountTokenCreator + serviceAccountUser combined)
- misconfigured_trust: overly permissive trust/assume-role policies, or public exposure (e.g. Principal "*" with no conditions, allUsers/allAuthenticatedUsers bindings)
- shared_credential: a single account/credential shared across multiple people or systems instead of individually attributable ones
- other: anything else clearly wrong that doesn't fit the above

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the IAM posture and the most pressing issue",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "findings": [
    {
      "rule_reference": "the specific policy/role/user/credential text, name, or ARN this finding is about",
      "issue_type": "excessive_privilege|missing_mfa|stale_credential|privilege_escalation_path|misconfigured_trust|shared_credential|other",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what is wrong and why it matters, specific to this finding",
      "recommendation": "the concrete fix — ideally the corrected policy statement or exact command"
    }
  ],
  "compliance_notes": [
    {"framework": "name of a compliance framework this risks violating (only if genuinely applicable)", "note": "which requirement and why"}
  ]
}

Only flag real issues actually present in the given input — do not invent problems. If the IAM configuration looks reasonably sound (least privilege, MFA enforced, credentials rotated), return few findings and a low overall_risk. Respond in Korean for all natural-language fields."""


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
            "content": f"IAM 플랫폼: {label}{context_line}\n\nIAM 정책/사용자 정보:\n{content}",
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


def analyze_iam(source_type: str, content: str, context: str) -> dict:
    if IS_MOCK:
        return _enrich(generate_mock_audit(source_type, content, context))
    return _enrich(_real_analyze(source_type, content, context))


def generate_markdown_report(entry: dict) -> str:
    label = SOURCE_LABELS.get(entry.get("source_type", ""), entry.get("source_type", "N/A"))
    lines = [
        "# 클라우드 IAM 정책 감사 리포트",
        "",
        f"**대상 플랫폼:** {label}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        "> AI가 붙여넣은 IAM 정책/사용자 정보 텍스트만으로 분석한 결과입니다. 실제 반영 전 담당자 검토와 최소 권한 원칙에 따른 검증을 거치세요.",
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
            f"**해당 정책/계정:** `{f.get('rule_reference', '')}`  ",
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
        "- 발견된 과도한 권한은 AWS IAM Access Analyzer / Azure AD Access Reviews / GCP Policy Analyzer 등으로 실제 사용 이력을 대조한 뒤 축소하세요.",
        "- 네트워크/방화벽 규칙도 함께 점검하려면 [방화벽 정책 감사기](/firewall-audit)를 이용해보세요.",
    ]

    return "\n".join(lines)
