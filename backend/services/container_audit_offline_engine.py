"""App 20(컨테이너/Dockerfile 감사기)의 오프라인(폐쇄망) 모드 — Dockerfile/docker-compose.yml
텍스트를 정규식으로 분석한다. 하드코딩 시크릿 탐지는 App 19 secret_scanner_service를 재사용."""
import re

from services.secret_scanner_service import scan_text as _scan_secrets


def _mk(rule_reference: str, issue_type: str, severity: str, description: str, recommendation: str) -> dict:
    return {
        "rule_reference": rule_reference.strip()[:200],
        "issue_type": issue_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.I | re.M)
_FROM_RE = re.compile(r"^\s*FROM\s+([^\s:@]+)(:(\S+))?(\s+AS\s+\S+)?\s*$", re.I | re.M)
_PRIVILEGED_RE = re.compile(r"privileged\s*:\s*true|--privileged\b", re.I)
_CAP_ADD_RE = re.compile(r"cap_add\s*:", re.I)
_HOST_NET_RE = re.compile(r"network_mode\s*:\s*[\"']?host[\"']?", re.I)
_HOST_PID_RE = re.compile(r"pid\s*:\s*[\"']?host[\"']?", re.I)
_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock", re.I)
_BROAD_MOUNT_RE = re.compile(r"-\s*[\"']?(/|~)(:|\s*:)", re.M)
_HEALTHCHECK_RE = re.compile(r"^\s*HEALTHCHECK\b", re.I | re.M)
_RESOURCE_LIMIT_RE = re.compile(r"mem_limit|cpus\s*:|deploy\s*:\s*\n\s*resources", re.I)
_DOCKERFILE_SECRET_ENV_RE = re.compile(
    r"^\s*(?:ENV|ARG)\s+(\w*(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN)\w*)[\s=]+(\S+)", re.I | re.M
)


def _secrets_as_findings(content: str) -> list[dict]:
    result = _scan_secrets(content)
    findings = []
    for f in result.get("findings", []):
        findings.append(_mk(
            f"{f['line']}번째 줄", "baked_in_secret", f["severity"],
            f"{f['pattern_label']}(으)로 추정되는 값이 이미지 레이어에 구워질 위치(ENV/ARG 등)에서 발견됐습니다 "
            f"(마스킹됨: {f['matched_masked']}).",
            f["recommendation"],
        ))
    return findings


def analyze_offline(source_type: str, content: str, context: str) -> dict:
    findings: list[dict] = []
    is_dockerfile = source_type == "dockerfile"

    if is_dockerfile:
        users = _USER_RE.findall(content)
        if not users or users[-1].lower() == "root":
            findings.append(_mk(
                "USER 지시어" if not users else f"USER {users[-1]}",
                "running_as_root", "HIGH",
                "USER 지시어가 없거나 root로 설정되어 있어 컨테이너 메인 프로세스가 root 권한으로 실행됩니다.",
                "전용 비특권 사용자를 만들어 USER 지시어로 지정하세요.",
            ))

        for m in _FROM_RE.finditer(content):
            tag = m.group(3)
            if not tag or tag.lower() == "latest":
                findings.append(_mk(
                    m.group(0), "unpinned_base_image", "MEDIUM",
                    "베이스 이미지 태그가 :latest이거나 아예 지정되지 않아 빌드가 재현 불가능하고 예기치 않은 새 버전이 섞일 수 있습니다.",
                    "구체적인 버전 태그(가능하면 다이제스트까지)로 고정하세요.",
                ))

        if not _HEALTHCHECK_RE.search(content):
            findings.append(_mk(
                "Dockerfile 전체", "missing_control", "LOW",
                "HEALTHCHECK 지시어가 없어 컨테이너 오케스트레이터가 헬스 상태를 판단할 수 없습니다.",
                "HEALTHCHECK 지시어를 추가하세요.",
            ))

        for m in _DOCKERFILE_SECRET_ENV_RE.finditer(content):
            findings.append(_mk(
                m.group(0), "baked_in_secret", "CRITICAL",
                f"ENV/ARG로 시크릿으로 보이는 값({m.group(1)})이 이미지 레이어에 그대로 구워집니다 — 나중에 제거해도 레이어 히스토리에 남습니다.",
                "빌드 시크릿은 BuildKit --mount=type=secret 또는 런타임 환경변수/Secrets Manager로 주입하세요.",
            ))
    else:
        if _PRIVILEGED_RE.search(content):
            findings.append(_mk("privileged: true", "excessive_capabilities", "CRITICAL",
                "컨테이너가 privileged 모드로 실행되어 호스트에 준하는 권한을 가집니다.",
                "privileged를 제거하고 꼭 필요한 개별 capability만 cap_add로 부여하세요."))
        if _CAP_ADD_RE.search(content):
            findings.append(_mk("cap_add", "excessive_capabilities", "MEDIUM",
                "cap_add로 추가 커널 capability가 부여되어 있습니다.",
                "정말 필요한 최소한의 capability인지 검토하세요(예: SYS_ADMIN은 특히 위험)."))
        if _HOST_NET_RE.search(content):
            findings.append(_mk("network_mode: host", "excessive_capabilities", "HIGH",
                "호스트 네트워크 네임스페이스를 공유해 컨테이너 격리가 크게 약화됩니다.",
                "필요하지 않다면 network_mode: host를 제거하고 포트 매핑을 사용하세요."))
        if _HOST_PID_RE.search(content):
            findings.append(_mk("pid: host", "excessive_capabilities", "HIGH",
                "호스트 PID 네임스페이스를 공유해 호스트의 모든 프로세스가 컨테이너에서 보입니다.",
                "필요하지 않다면 pid: host를 제거하세요."))
        if _DOCKER_SOCK_RE.search(content):
            findings.append(_mk("/var/run/docker.sock 마운트", "insecure_mount_or_network", "CRITICAL",
                "Docker 소켓을 마운트하면 컨테이너가 사실상 호스트 root 권한과 동등한 능력을 가집니다.",
                "정말 필요한 경우가 아니면 소켓 마운트를 제거하고, 필요하면 권한이 제한된 프록시(docker-socket-proxy)를 사용하세요."))
        if _BROAD_MOUNT_RE.search(content):
            findings.append(_mk("루트/홈 디렉토리 바인드 마운트", "insecure_mount_or_network", "HIGH",
                "루트(/) 또는 홈 디렉토리 전체를 바인드 마운트하는 것으로 보입니다 — 컨테이너가 호스트 파일시스템 대부분에 접근 가능합니다.",
                "필요한 하위 디렉토리만 구체적으로 마운트하세요."))
        if not _RESOURCE_LIMIT_RE.search(content):
            findings.append(_mk("compose 파일 전체", "missing_control", "LOW",
                "리소스 제한(mem_limit/cpus/deploy.resources)이 설정되어 있지 않습니다.",
                "리소스 제한을 설정해 한 컨테이너의 폭주가 호스트 전체에 영향을 주지 않게 하세요."))

    findings.extend(_secrets_as_findings(content))

    if not findings:
        summary = "규칙 기반 오프라인 분석에서 사전 정의된 위험 패턴이 발견되지 않았습니다. 이 엔진이 모르는 문제는 놓칠 수 있습니다."
        overall_risk = "INFO"
    else:
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        if crit:
            summary = f"규칙 기반 오프라인 분석에서 심각(CRITICAL) {crit}건을 포함해 총 {len(findings)}건의 문제가 발견됐습니다."
            overall_risk = "CRITICAL"
        elif high:
            summary = f"규칙 기반 오프라인 분석에서 높음(HIGH) {high}건을 포함해 총 {len(findings)}건의 문제가 발견됐습니다."
            overall_risk = "HIGH"
        else:
            summary = f"규칙 기반 오프라인 분석에서 총 {len(findings)}건의 개선 사항이 발견됐습니다."
            overall_risk = "MEDIUM"

    return {
        "summary": summary,
        "overall_risk": overall_risk,
        "findings": findings,
        "compliance_notes": [],
        "engine_note": (
            "이 결과는 네트워크 연결 없이 동작하는 규칙 기반 오프라인 분석 엔진이 생성했습니다 — "
            "AI가 아니라 사전 정의된 패턴(USER 누락, privileged/host 네트워크, docker.sock 마운트, "
            "시크릿 하드코딩 등)과의 매칭 결과이므로 AI 분석보다 탐지 범위가 좁습니다. 인터넷 또는 "
            "로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 권장합니다."
        ),
    }
