"""정규식/엔트로피 기반 시크릿 스캐너. App 15(CVE 조회)/App 17(인프라 스캐너)처럼
Claude API를 쓰지 않는다 — 하드코딩된 비밀값 탐지는 결정론적 패턴 매칭이 더 정확·
빠르고, 무엇보다 원본 시크릿 값을 외부(Claude API 등)로 전송하지 않아도 된다는
이점이 있다. API 키 설정 여부와 무관하게 항상 동일하게 동작한다.

⚠️ 보안 설계: 이 앱이 다루는 입력 자체가 실제 비밀값일 수 있으므로, 매치된 값은
찾아내는 즉시 마스킹하고 그 이후로는(응답·히스토리 DB·마크다운 리포트 전부)
원본 값이나 원본 텍스트 조각을 절대 다시 노출하지 않는다 — `context` 필드도
매치 구간만 마스킹해 재구성하며, 붙여넣은 원문 전체나 truncate된 미리보기는
어디에도 저장하지 않는다.
"""

import math
import re

_PLACEHOLDER_WORDS = {
    "xxx", "yyy", "zzz", "changeme", "change_me", "your_api_key_here", "example",
    "test", "placeholder", "dummy", "sample", "todo", "fixme", "secret", "password",
}

_PATTERNS = [
    {"id": "aws_access_key", "label": "AWS 액세스 키 ID", "severity": "CRITICAL",
     "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "recommendation": "AWS 콘솔에서 즉시 이 키를 비활성화/삭제하고 새 키로 교체하세요. 장기 액세스 키 대신 IAM Role 사용을 권장합니다."},
    {"id": "aws_secret_key", "label": "AWS 시크릿 액세스 키", "severity": "CRITICAL",
     "regex": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "recommendation": "연결된 액세스 키를 즉시 폐기하고 교체하세요. 코드에는 값 대신 환경변수/Secrets Manager 참조만 남기세요."},
    {"id": "github_token", "label": "GitHub 토큰", "severity": "CRITICAL",
     "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
     "recommendation": "GitHub Settings > Developer settings에서 즉시 토큰을 폐기(revoke)하고 재발급하세요."},
    {"id": "gitlab_token", "label": "GitLab Personal Access Token", "severity": "CRITICAL",
     "regex": re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
     "recommendation": "GitLab에서 즉시 토큰을 폐기하고 재발급하세요."},
    {"id": "slack_token", "label": "Slack 토큰", "severity": "HIGH",
     "regex": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
     "recommendation": "Slack App 관리 화면에서 토큰을 즉시 재발급하세요."},
    {"id": "slack_webhook", "label": "Slack Webhook URL", "severity": "HIGH",
     "regex": re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
     "recommendation": "해당 Webhook을 즉시 삭제하고 새로 생성하세요. Webhook URL 자체가 곧 인증 수단입니다."},
    {"id": "google_api_key", "label": "Google API 키", "severity": "HIGH",
     "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "recommendation": "Google Cloud Console에서 이 키를 삭제/재발급하고, API 키 제한(HTTP 리퍼러, IP, API 범위)을 설정하세요."},
    {"id": "stripe_live_secret", "label": "Stripe 라이브 시크릿 키", "severity": "CRITICAL",
     "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
     "recommendation": "Stripe 대시보드에서 즉시 키를 롤(roll)하세요. 실거래 결제 권한을 가진 키입니다."},
    {"id": "stripe_live_publishable", "label": "Stripe 라이브 공개 키", "severity": "MEDIUM",
     "regex": re.compile(r"\bpk_live_[0-9a-zA-Z]{20,}\b"),
     "recommendation": "공개 키는 클라이언트 노출이 전제지만, 저장소에 하드코딩하기보다는 빌드 설정/환경변수로 관리하는 것을 권장합니다."},
    {"id": "private_key_block", "label": "개인키 블록", "severity": "CRITICAL",
     "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "recommendation": "이 개인키로 서명/복호화되는 모든 인증서·연결을 즉시 폐기하고 새 키 쌍으로 교체하세요."},
    {"id": "twilio_key", "label": "Twilio API 키", "severity": "HIGH",
     "regex": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "recommendation": "Twilio 콘솔에서 이 키를 즉시 삭제하고 재발급하세요."},
    {"id": "db_connection_string", "label": "DB 연결 문자열 (자격증명 포함)", "severity": "HIGH",
     "regex": re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:@/\s]+:([^@/\s]+)@[^/\s]+"),
     "recommendation": "연결 문자열에서 비밀번호를 분리해 환경변수/Secrets Manager로 옮기고, 노출된 DB 계정 비밀번호는 즉시 변경하세요."},
    {"id": "jwt_like", "label": "JWT 형태 토큰", "severity": "MEDIUM",
     "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "recommendation": "실제 발급된 세션/인증 토큰이라면 즉시 무효화하세요. 만료 시간이 짧더라도 코드/로그에 남기지 않는 것이 원칙입니다."},
]

_GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key)\b\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{12,})['\"]"
)

_ENTROPY_CANDIDATE_RE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{20,100})['\"]")

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

MAX_CONTENT_CHARS = 1_000_000


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}{'•' * max(4, len(value) - 8)}{value[-4:]}"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in _PLACEHOLDER_WORDS:
        return True
    if re.fullmatch(r"x+", lowered) or re.fullmatch(r"0+", lowered) or re.fullmatch(r"1+", lowered):
        return True
    if any(w in lowered for w in ("example", "placeholder", "changeme", "your_", "dummy", "sample_")):
        return True
    return False


def _masked_context(line: str, span: tuple[int, int], masked_value: str) -> str:
    start, end = span
    rebuilt = line[:start] + masked_value + line[end:]
    return rebuilt.strip()[:160]


def scan_text(content: str, filename: str = "") -> dict:
    lines = content.splitlines()
    findings: list[dict] = []
    flagged_lines: set[int] = set()

    for line_no, line in enumerate(lines, start=1):
        for pat in _PATTERNS:
            for m in pat["regex"].finditer(line):
                has_group = pat["regex"].groups >= 1
                value = m.group(1) if has_group else m.group(0)
                span = m.span(1) if has_group else m.span(0)
                if _is_placeholder(value):
                    continue
                masked_value = _mask(value)
                findings.append({
                    "pattern_id": pat["id"],
                    "pattern_label": pat["label"],
                    "severity": pat["severity"],
                    "line": line_no,
                    "matched_masked": masked_value,
                    "context": _masked_context(line, span, masked_value),
                    "recommendation": pat["recommendation"],
                    "confidence": "HIGH",
                })
                flagged_lines.add(line_no)

        for m in _GENERIC_ASSIGNMENT_RE.finditer(line):
            value = m.group(1)
            if _is_placeholder(value):
                continue
            masked_value = _mask(value)
            findings.append({
                "pattern_id": "generic_credential_assignment",
                "pattern_label": "일반 자격증명 할당 패턴",
                "severity": "MEDIUM",
                "line": line_no,
                "matched_masked": masked_value,
                "context": _masked_context(line, m.span(1), masked_value),
                "recommendation": "이 값이 실제 자격증명이라면 코드에서 분리해 환경변수/Secrets Manager로 옮기고, 이미 커밋된 이력이 있다면 값 자체를 교체(rotate)하세요.",
                "confidence": "MEDIUM",
            })
            flagged_lines.add(line_no)

    for line_no, line in enumerate(lines, start=1):
        if line_no in flagged_lines:
            continue
        for m in _ENTROPY_CANDIDATE_RE.finditer(line):
            value = m.group(1)
            if _is_placeholder(value):
                continue
            if _shannon_entropy(value) < 4.2:
                continue
            masked_value = _mask(value)
            findings.append({
                "pattern_id": "high_entropy_string",
                "pattern_label": "고엔트로피 문자열 (추정)",
                "severity": "LOW",
                "line": line_no,
                "matched_masked": masked_value,
                "context": _masked_context(line, m.span(1), masked_value),
                "recommendation": "무작위성이 높은 문자열이 하드코딩되어 있습니다. 실제 시크릿인지 확인이 필요합니다 (오탐 가능성이 있는 best-effort 탐지입니다).",
                "confidence": "LOW",
            })
            break  # 한 줄에서 하나만 — 소음 방지

    return _summarize(findings, filename)


def _summarize(findings: list[dict], filename: str) -> dict:
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f["severity"], 0), f["line"]), reverse=True)
    stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        stats[key] = stats.get(key, 0) + 1

    if stats["critical"] > 0:
        overall_risk = "CRITICAL"
    elif stats["high"] > 0:
        overall_risk = "HIGH"
    elif stats["medium"] > 0:
        overall_risk = "MEDIUM"
    elif stats["low"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    summary = (
        f"총 {stats['total']}건의 잠재적 시크릿을 발견했습니다."
        if findings else "알려진 패턴의 하드코딩된 시크릿을 발견하지 못했습니다."
    )

    return {
        "filename": filename,
        "overall_risk": overall_risk,
        "summary": summary,
        "findings": findings,
        "stats": stats,
    }


PATTERN_REFERENCE = [
    {"id": p["id"], "label": p["label"], "severity": p["severity"]} for p in _PATTERNS
] + [
    {"id": "generic_credential_assignment", "label": "일반 자격증명 할당 패턴 (key=value 휴리스틱)", "severity": "MEDIUM"},
    {"id": "high_entropy_string", "label": "고엔트로피 문자열 (추정, best-effort)", "severity": "LOW"},
]

DISCLAIMER = (
    "이 도구는 정규식·엔트로피 기반 결정론적 패턴 매칭으로 동작하며 Claude AI를 사용하지 않습니다 — "
    "붙여넣거나 업로드한 텍스트를 외부로 전송하지 않고 이 서버 안에서만 검사합니다. "
    "발견된 값은 찾아낸 즉시 일부만 남기고 마스킹되며, 원본 값이나 원본 텍스트는 화면에도 서버 저장소에도 남기지 않습니다. "
    "정규식 기반 탐지의 한계로 오탐(false positive)·누락이 있을 수 있어, gitleaks/trufflehog 등 "
    "전용 도구와 함께 쓰는 것을 권장합니다."
)


def generate_markdown_report(entry: dict) -> str:
    lines = [
        "# 시크릿 스캔 리포트",
        "",
        f"**대상 파일:** {entry.get('filename') or '(파일명 없음)'}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        "> 정규식·엔트로피 기반 결정론적 스캔 결과입니다 (Claude AI 미사용). "
        "아래 값들은 전부 마스킹된 형태이며 원본 시크릿은 어디에도 저장되지 않았습니다.",
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
    lines.append(f"전체 {stats.get('total', 0)}건 — CRITICAL {stats.get('critical', 0)} / HIGH {stats.get('high', 0)} / MEDIUM {stats.get('medium', 0)} / LOW {stats.get('low', 0)}")
    lines += ["", "---", "", "## 상세 발견 사항", ""]

    for f in entry.get("findings", []):
        lines += [
            f"### [{f.get('severity')}] {f.get('pattern_label')} (line {f.get('line')})",
            "",
            f"**컨텍스트(마스킹됨):** `{f.get('context', '')}`  ",
            "",
            f"**권장 조치:** {f.get('recommendation', '')}",
            "",
            "---",
            "",
        ]

    lines += [
        "## 다음 단계",
        "",
        "- 실제 시크릿으로 확인되면 즉시 해당 서비스에서 값을 폐기/재발급(rotate)하세요.",
        "- 이미 git 이력에 커밋된 시크릿은 값 교체만으로는 부족합니다 — git-filter-repo/BFG 등으로 이력에서도 제거하는 것을 검토하세요.",
        "- 코드/설정 감사를 더 하려면 [취약점 스캐너](/vuln)를, 네트워크·권한 설정 감사가 필요하면 [방화벽 정책 감사기](/firewall-audit)·[클라우드 IAM 정책 감사기](/iam-audit)를 이용해보세요.",
    ]

    return "\n".join(lines)
