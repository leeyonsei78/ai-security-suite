"""App 23(실시간 공격 모니터링 & 대응 센터)의 "AWS 활동 모니터링" 탭용 수집기.

⚠️ 이름과 달리 실제 AWS CloudTrail은 쓰지 않는다 — 이 프로젝트가 무료로 고정한
LocalStack 4.4.0(test-range/docker-compose.yml 참고)에서 CloudTrail API를 직접
호출해보니 `lookup-events`/`describe-trails` 등 전부 "The API for service
'cloudtrail' is either not included in your current license plan or has not yet
been emulated by LocalStack" 오류로 아예 지원되지 않음을 실제로 확인했다(2026-09-05).
대신 LocalStack 컨테이너 자체가 `LS_LOG=trace`일 때 모든 API 요청의 실제 파라미터
(IAM 정책 문서, 보안그룹 CIDR/포트 등)까지 자기 로그(`docker logs`)에 그대로 남기는
것을 발견해, 그 로그를 신호원으로 재사용한다 — App 23의 Windows 실시간 수집이
PowerShell 서브프로세스를 쓰는 것과 동일한 패턴(docker CLI 서브프로세스).

실제 AWS 계정을 쓸 때는 이 방식이 아니라 진짜 CloudTrail(`aws cloudtrail
lookup-events`)을 써야 한다 — 이 모듈은 test-range의 무료 LocalStack 샌드박스
전용이다.
"""
import re
import subprocess

CONTAINER_NAME = "test-range-localstack"

_REQUEST_LINE_RE = re.compile(r"localstack\.request\.aws\s*:\s*AWS\s+(\S+)\.(\S+)\s*=>\s*(\d+)")

ENGINE_NOTE = (
    "이 신호는 실제 AWS CloudTrail이 아니라, 이 프로젝트가 무료로 고정한 LocalStack "
    "4.4.0 컨테이너 자체의 요청 로그(LS_LOG=trace)입니다 — 이 버전은 CloudTrail API를 "
    "지원하지 않습니다. 실제 AWS 계정에서는 CloudTrail을 사용하는 것이 정식 방법입니다."
)


def check_connection() -> dict:
    """본격적인 모니터링 전에 LocalStack 컨테이너가 실제로 떠 있는지 확인한다."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return {"ok": False, "message": "이 백엔드를 실행 중인 호스트에서 'docker' 명령을 찾을 수 없습니다 — Docker Desktop이 설치·실행 중인지 확인하세요."}
    except Exception as e:
        return {"ok": False, "message": f"연결 확인 중 오류: {str(e)[:200]}"}

    if proc.returncode != 0:
        return {
            "ok": False,
            "message": f"'{CONTAINER_NAME}' 컨테이너를 찾을 수 없습니다 — "
                       "test-range를 먼저 기동하세요: cd test-range && docker compose up -d localstack aws-sandbox",
        }
    if proc.stdout.strip() != "true":
        return {"ok": False, "message": f"'{CONTAINER_NAME}' 컨테이너가 실행 중이 아닙니다(중지 상태) — docker compose start localstack으로 다시 켜세요."}
    return {"ok": True, "message": "LocalStack 컨테이너에 정상적으로 연결되었습니다."}


def collect_events(since_seconds: int = 25) -> str:
    """최근 since_seconds초 동안 LocalStack 컨테이너가 처리한 API 요청 로그를
    App 1/23이 공유하는 analyze_logs() 파이프라인에 넣을 수 있는 텍스트로 변환한다."""
    try:
        proc = subprocess.run(
            ["docker", "logs", "--since", f"{since_seconds}s", CONTAINER_NAME],
            capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        return "status: 'docker' 명령을 찾을 수 없습니다 — Docker Desktop이 실행 중인지 확인하세요."
    except Exception as e:
        return f"status: LocalStack 로그 조회 실패 — {str(e)[:200]}"

    all_lines = proc.stdout.splitlines() + proc.stderr.splitlines()
    matched = [l for l in all_lines if _REQUEST_LINE_RE.search(l)]
    if not matched:
        return "status: No suspicious signals observed (no new LocalStack API calls)"

    formatted = []
    for line in matched:
        m = _REQUEST_LINE_RE.search(line)
        service, operation = m.group(1), m.group(2)
        # 뒤에 이어지는 실제 요청/응답 파라미터(정책 문서, CIDR/포트 등)를 그대로 detail에
        # 담아야 오프라인 엔진의 와일드카드 권한/전체공개 CIDR 탐지 정규식이 매칭할 수 있다.
        formatted.append(f"aws_cloudtrail[{operation}]: service={service} {line.strip()[:1000]}")
    return "\n".join(formatted)
