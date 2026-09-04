"""컨테이너/Dockerfile 감사기 Mock 데이터. App 16(방화벽 정책 감사기)/App 18(IAM
정책 감사기)와 같은 패턴 — 파일 유형(Dockerfile/docker-compose.yml)별로 실제
자주 나오는 컨테이너 보안 안티패턴을 큐레이션했다."""

_TEMPLATES = {
    "dockerfile": {
        "summary": "베이스 이미지 버전이 고정되지 않았고 컨테이너가 root로 실행되며, 이미지에 DB 비밀번호까지 그대로 구워져 있습니다. 이미지를 받는 누구나 레이어를 열어보면 비밀번호를 볼 수 있는 상태입니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "ENV DB_PASSWORD=SuperSecret123",
                "issue_type": "baked_in_secret",
                "severity": "CRITICAL",
                "description": "DB 비밀번호가 ENV로 이미지 레이어에 그대로 구워져 있습니다. 나중에 다른 레이어에서 값을 지우거나 덮어써도, `docker history`나 이미지 레이어를 열어보면 여전히 값이 남아있습니다.",
                "recommendation": "빌드 시점 비밀은 BuildKit의 `--secret` 마운트를 쓰고, 런타임 비밀은 ENV 대신 docker secrets/K8s Secret으로 컨테이너 실행 시 주입하세요. 이미 구워진 이미지는 즉시 재빌드하고 해당 비밀번호는 교체하세요.",
            },
            {
                "rule_reference": "FROM node:latest",
                "issue_type": "unpinned_base_image",
                "severity": "HIGH",
                "description": "베이스 이미지 태그가 `latest`로 고정돼 있지 않습니다. 언제 빌드하느냐에 따라 다른 버전이 받아져 재현 불가능한 빌드가 되고, 검증 안 된 새 버전이 예고 없이 들어올 수 있습니다.",
                "recommendation": "FROM node:20.11.1-bookworm-slim 처럼 구체적인 버전(+가능하면 다이제스트 `@sha256:...`)으로 고정하세요.",
            },
            {
                "rule_reference": "(USER 지시어 없음 — 기본값으로 root 실행됨)",
                "issue_type": "running_as_root",
                "severity": "CRITICAL",
                "description": "USER 지시어가 없어 컨테이너의 메인 프로세스가 root로 실행됩니다. 애플리케이션에 취약점이 있어 컨테이너를 탈출당하면, 공격자가 곧바로 root 권한을 갖게 됩니다.",
                "recommendation": "RUN addgroup -S app && adduser -S app -G app 로 전용 사용자를 만들고, 마지막에 USER app을 추가해 비-root로 실행하세요.",
            },
            {
                "rule_reference": "RUN apt-get update && apt-get install -y curl",
                "issue_type": "missing_control",
                "severity": "LOW",
                "description": "패키지 설치 후 apt 캐시를 정리하지 않아 이미지 크기가 불필요하게 커지고, 오래된 패키지 인덱스가 이미지에 그대로 남습니다.",
                "recommendation": "RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* 처럼 같은 RUN 레이어에서 정리까지 함께 하세요.",
            },
            {
                "rule_reference": "(HEALTHCHECK 지시어 없음)",
                "issue_type": "missing_control",
                "severity": "LOW",
                "description": "HEALTHCHECK가 없어 오케스트레이터(Docker/K8s)가 컨테이너 내부 프로세스가 실제로 정상 응답하는지 알 방법이 없습니다. 프로세스는 떠 있지만 애플리케이션이 멈춘 상태를 자동으로 감지하지 못합니다.",
                "recommendation": "HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000/health || exit 1 처럼 실제 헬스 엔드포인트를 체크하는 지시어를 추가하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.6.3(시스템 개발 보안)에서 요구하는 소스코드/이미지 내 비밀정보 관리 원칙이 지켜지지 않고 있습니다."},
        ],
    },
    "compose": {
        "summary": "한 서비스가 privileged 모드로 실행되면서 동시에 호스트의 Docker 소켓까지 마운트하고 있어, 이 컨테이너가 뚫리면 사실상 호스트 전체가 뚫리는 것과 같은 상태입니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "services.app.privileged: true",
                "issue_type": "excessive_capabilities",
                "severity": "CRITICAL",
                "description": "privileged 모드는 컨테이너에 호스트의 거의 모든 커널 기능(device 접근, 커널 모듈 로드 등)을 그대로 허용합니다. 컨테이너 격리가 사실상 무력화됩니다.",
                "recommendation": "privileged: true를 제거하고, 정말 필요한 개별 capability만 cap_add로 최소한으로 추가하세요(예: NET_ADMIN만 필요하면 그것만).",
            },
            {
                "rule_reference": "services.app.volumes: - /var/run/docker.sock:/var/run/docker.sock",
                "issue_type": "insecure_mount_or_network",
                "severity": "CRITICAL",
                "description": "Docker 소켓을 컨테이너 안에 마운트하면, 그 컨테이너 안에서 호스트의 Docker 데몬을 직접 제어할 수 있습니다 — 새 컨테이너를 root 권한으로 띄우는 것도 가능해 사실상 호스트 root 권한과 같습니다.",
                "recommendation": "정말 Docker-in-Docker가 필요하다면 소켓을 직접 마운트하는 대신 별도의 격리된 DinD 컨테이너나 소켓 프록시(docker-socket-proxy)로 필요한 API만 제한적으로 노출하세요.",
            },
            {
                "rule_reference": "services.app.network_mode: host",
                "issue_type": "excessive_capabilities",
                "severity": "HIGH",
                "description": "호스트 네트워크 네임스페이스를 그대로 공유합니다. 컨테이너의 모든 포트가 격리 없이 호스트에 직접 바인딩되고, 호스트의 다른 네트워크 트래픽도 컨테이너에서 관찰 가능해집니다.",
                "recommendation": "특별한 이유가 없다면 기본 bridge 네트워크를 쓰고, 필요한 포트만 ports로 명시적으로 게시하세요.",
            },
            {
                "rule_reference": "services.app.image: myapp:latest",
                "issue_type": "unpinned_base_image",
                "severity": "MEDIUM",
                "description": "서비스 이미지 태그가 latest로 고정되지 않았습니다. 배포할 때마다 다른 이미지가 받아질 수 있어 롤백·재현이 어렵습니다.",
                "recommendation": "CI에서 빌드한 구체적인 태그(커밋 해시 또는 semver, 예: myapp:1.4.2)로 고정하세요.",
            },
            {
                "rule_reference": "services.app: (mem_limit/cpus 등 리소스 제한 설정 없음)",
                "issue_type": "missing_control",
                "severity": "LOW",
                "description": "메모리·CPU 제한이 없어, 이 컨테이너 하나가 버그나 공격으로 리소스를 과도하게 소비하면 같은 호스트의 다른 컨테이너/프로세스까지 영향을 받을 수 있습니다.",
                "recommendation": "mem_limit, cpus(또는 Compose v3의 deploy.resources.limits)로 서비스별 리소스 상한을 설정하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "PCI-DSS", "note": "요구사항 2.2(시스템 컴포넌트별 불필요한 기능·서비스 제거)에 위배되는 과도한 권한 부여가 발견되었습니다."},
        ],
    },
}

_DEFAULT_KEY = "dockerfile"


def generate_mock_audit(source_type: str, content: str, context: str) -> dict:
    template = _TEMPLATES.get(source_type, _TEMPLATES[_DEFAULT_KEY])
    return {
        "summary": template["summary"],
        "overall_risk": template["overall_risk"],
        "findings": [dict(f) for f in template["findings"]],
        "compliance_notes": [dict(c) for c in template["compliance_notes"]],
    }
