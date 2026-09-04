import os
import json
from dotenv import load_dotenv
from services.mock_container_audit import generate_mock_audit

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

SOURCE_LABELS = {
    "dockerfile": "Dockerfile",
    "compose": "docker-compose.yml",
}

ISSUE_TYPE_LABELS = {
    "running_as_root": "root로 실행",
    "excessive_capabilities": "과도한 권한/기능 (privileged 등)",
    "baked_in_secret": "이미지에 시크릿 굽기",
    "unpinned_base_image": "베이스 이미지 버전 미고정",
    "insecure_mount_or_network": "안전하지 않은 마운트/네트워크",
    "missing_control": "누락된 통제",
    "other": "기타",
}

SYSTEM_PROMPT = """You are a senior container security auditor reviewing an EXISTING Dockerfile or docker-compose.yml (not writing a new one) to find what is wrong.

The user provides: the file type (Dockerfile or docker-compose.yml), the raw file text, and optional environment context.

For each problem you find, cite the specific instruction/line (e.g. "FROM node:latest", "USER root", the exact line text) and classify it. Look specifically for:
- running_as_root: no USER instruction (or USER root explicitly) so the container's main process runs as root inside the container — increases blast radius of a container escape
- excessive_capabilities: privileged: true, cap_add with broad capabilities (e.g. SYS_ADMIN), --privileged, network_mode: host, pid: host, or other namespace-sharing that weakens container isolation
- baked_in_secret: secrets (passwords, API keys, private keys, .env files with real-looking values) copied into the image or set via ENV/ARG so they persist in image layers even if later removed
- unpinned_base_image: FROM using :latest or no tag at all, making builds non-reproducible and silently pulling in unvetted new versions
- insecure_mount_or_network: mounting the Docker socket (/var/run/docker.sock) into a container (near-equivalent to root on the host), overly broad bind mounts (e.g. mounting `/` or the whole home directory), or binding a sensitive port to 0.0.0.0 unnecessarily
- missing_control: no HEALTHCHECK, no resource limits (mem_limit/cpus in compose), running package manager without cleaning caches (bloats image and leaves stale package lists), no .dockerignore awareness leading to secrets/large files being copied in, missing multi-stage build for compiled languages (leaves build tools/source in the final image)
- other: anything else clearly wrong that doesn't fit the above

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the container security posture and the most pressing issue",
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "findings": [
    {
      "rule_reference": "the specific instruction/line text this finding is about",
      "issue_type": "running_as_root|excessive_capabilities|baked_in_secret|unpinned_base_image|insecure_mount_or_network|missing_control|other",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "what is wrong and why it matters, specific to this line",
      "recommendation": "the concrete fix — ideally the corrected instruction/line"
    }
  ],
  "compliance_notes": [
    {"framework": "name of a compliance framework this risks violating (only if genuinely applicable)", "note": "which requirement and why"}
  ]
}

Only flag real issues actually present in the given file — do not invent problems. If the file looks reasonably sound (non-root user, pinned image, no secrets, healthcheck present), return few findings and a low overall_risk. Respond in Korean for all natural-language fields."""


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
            "content": f"파일 유형: {label}{context_line}\n\n내용:\n{content}",
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


def analyze_container(source_type: str, content: str, context: str) -> dict:
    if IS_MOCK:
        return _enrich(generate_mock_audit(source_type, content, context))
    return _enrich(_real_analyze(source_type, content, context))


def generate_markdown_report(entry: dict) -> str:
    label = SOURCE_LABELS.get(entry.get("source_type", ""), entry.get("source_type", "N/A"))
    lines = [
        "# 컨테이너/Dockerfile 감사 리포트",
        "",
        f"**대상 파일:** {label}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        "> AI가 붙여넣은 Dockerfile/compose 텍스트만으로 분석한 결과입니다. 실제 반영 전 담당자 검토와 스테이징 환경 검증을 거치세요.",
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
            f"**해당 라인:** `{f.get('rule_reference', '')}`  ",
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
        "- 이미지를 빌드한 뒤 `docker scout cves` / `trivy image` 등으로 실제 알려진 취약점도 함께 스캔하세요.",
        "- 클러스터에 배포한다면 Kubernetes NetworkPolicy·PodSecurity 설정도 별도로 점검하세요.",
    ]

    return "\n".join(lines)
