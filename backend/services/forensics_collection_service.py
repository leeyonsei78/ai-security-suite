"""포렌식 실습·분석 센터(App 25) '증거 수집 도구' 탭 — App 23(attack_monitor_service.py)의
PowerShell 서브프로세스 수집 패턴을 그대로 재사용하되, 목적이 다르다: App 23은 "지금
위협이 있는가"를 판정하기 위한 신호 수집이고, 이 모듈은 실제 조사에 쓸 증거를 무결성
검증 가능한 형태로 남기는 "chain of custody"(증거 보관 연속성) 기록이 목적이다.

그래서 이 모듈은 AI를 전혀 쓰지 않는다(App 15/17/19/21과 같은 결정론적 부류) — 수집한
원본 데이터를 그대로 SHA-256 해시와 함께 보존해, 나중에 "이 증거가 수집 시점 이후
변경되지 않았음"을 확인할 수 있게 하는 것이 핵심이다. 위협 여부를 판정하지 않으므로
notify.py 알림 대상에도 포함하지 않는다(App 22 집계 대상에서도 자연히 제외).

⚠️ 이 PC 자신(Windows, PowerShell 5.1 기준) 수집은 일부 항목(프로세스 생성 감사 4688,
Prefetch)이 감사 정책 활성화 또는 관리자 권한을 요구할 수 있으며, 실패해도 빈 결과
대신 명확한 에러 메시지를 남긴다(조사 기록에는 "시도했으나 이 권한/설정으로는 수집
불가"도 그 자체로 의미 있는 사실이기 때문).

**원격 SSH 수집 + 클라우드 CLI 수집** (2026-09-06, "이 PC뿐 아니라 Linux/macOS/클라우드/
네트워크 장비도 실제로 수집하게 해달라"는 요청으로 확장): 기존에는 이 PC(Windows)만
실제로 수집 가능했고 다른 플랫폼은 `forensics_audit_guide.py`의 문서(사람이 직접 실행)로만
존재했는데, 이제 그 문서의 명령어를 실제로 실행하는 두 번째·세 번째 경로를 추가했다.
- **SSH 원격 수집**(`collect_remote`): paramiko로 Linux/macOS/네트워크 장비(Cisco/Fortinet/
  Palo Alto/Juniper)에 직접 접속해 명령을 실행한다. 자격증명은 App 23의 원격 모니터링과
  같은 원칙 — 저장하지 않고 매 요청마다 전달만 함. paramiko는 프로세스를 통해 셸을 띄우지
  않는 순수 Python 구현이라(소켓 레벨 SSH), App 23이 WinRM 비밀번호 노출을 막기 위해 임시
  파일 방식을 따로 만들어야 했던 것과 달리 애초에 그런 위험이 없다.
  ⚠️ **네트워크 장비는 명령 하나만 단발성으로 실행**한다 — SSH `exec_command`는 매번 새
  채널(사실상 새 세션)을 여는데, Cisco/Fortinet/Palo Alto/Juniper 같은 네트워크 장비는
  POSIX 셸이 아니라 벤더별 CLI라 `terminal length 0` 같은 상태 설정이 다음 채널로 이어지지
  않고, 장비·펌웨어에 따라 여러 명령 연결(`;`, `&&`) 자체를 지원하지 않을 수 있다. 그래서
  가이드가 안내하는 여러 명령 중 가장 핵심적인 조회 명령 하나만 실제 자동화 대상으로 삼고,
  실패 시 가이드의 나머지 명령을 수동으로 실행하도록 안내한다. 반대로 Linux/macOS는 sshd가
  전달받은 명령 문자열을 실제 로그인 셸로 실행하므로 여러 명령을 그대로 순차 실행해도 안전함.
- **클라우드 CLI 수집**(`collect_cloud`): AWS/Azure/GCP는 원격 접속이 아니라 이 백엔드
  호스트에 설치·인증되어 있는 CLI(aws/az/gcloud)를 서브프로세스로 그대로 실행한다 — 클라우드
  API는 애초에 "어디서 실행하는지"가 아니라 "어떤 자격증명으로 실행하는지"가 중요하므로,
  조사관 자신의 PC(또는 이 백엔드가 도는 서버)에 이미 구성된 CLI 인증을 그대로 재사용하는
  편이 자연스럽다. CLI 미설치(FileNotFoundError)와 미인증(0이 아닌 종료 코드)을 구분해 안내.
"""

import hashlib
import io
import json
import subprocess
from datetime import datetime, timedelta, timezone

import paramiko

_PRELUDE = (
    "$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "$ProgressPreference='SilentlyContinue'; "
)

COLLECTIBLE_ITEMS = [
    {
        "id": "security_logon_events",
        "label": "로그온 성공/실패 이벤트 (Security 4624/4625)",
        "description": "최근 로그온 성공(4624)·실패(4625) 이벤트 각 20건. 브루트포스·계정 탈취 조사의 기본 자료입니다.",
        "requires_admin": False,
        "command": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 40",
        "script": r"""
try {
  $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 40 -EA Stop |
    Select-Object TimeCreated,Id,@{n='Account';e={$_.Properties[5].Value}},@{n='SourceIP';e={$_.Properties[19].Value}}
  @{ ok = $true; data = $events } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
""",
    },
    {
        "id": "process_creation_events",
        "label": "프로세스 생성 이벤트 (Security 4688)",
        "description": "최근 생성된 프로세스 20건(커맨드라인 포함). 프로세스 생성 감사 정책이 켜져 있어야 값이 나옵니다.",
        "requires_admin": False,
        "command": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 20",
        "script": r"""
try {
  $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 20 -EA Stop |
    Select-Object TimeCreated,@{n='NewProcess';e={$_.Properties[5].Value}},@{n='CommandLine';e={$_.Properties[8].Value}}
  @{ ok = $true; data = $events } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; error = "프로세스 생성 감사 정책이 꺼져 있거나 조회 권한이 없습니다: $($_.Exception.Message)" } | ConvertTo-Json -Compress
}
""",
    },
    {
        "id": "run_keys",
        "label": "레지스트리 Run/RunOnce 키",
        "description": "재부팅 시 자동 실행되도록 등록된 프로그램 목록 — 지속성(persistence) 확인용.",
        "requires_admin": False,
        "command": "Get-ItemProperty HKLM:\\...\\Run, HKCU:\\...\\Run, ...\\RunOnce",
        "script": r"""
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$result = @()
foreach ($p in $paths) {
  try {
    $props = Get-ItemProperty -Path $p -EA Stop
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $result += [PSCustomObject]@{ key = $p; name = $_.Name; value = "$($_.Value)" }
    }
  } catch {}
}
@{ ok = $true; data = $result } | ConvertTo-Json -Depth 5 -Compress
""",
    },
    {
        "id": "prefetch_files",
        "label": "Prefetch 파일 목록",
        "description": "실행된 프로그램의 흔적(Prefetch)을 파일명·생성/수정 시각과 함께 수집합니다. 접근에 관리자 권한이 필요할 수 있습니다.",
        "requires_admin": True,
        "command": "Get-ChildItem C:\\Windows\\Prefetch",
        "script": r"""
try {
  $files = Get-ChildItem 'C:\Windows\Prefetch' -Filter '*.pf' -EA Stop |
    Select-Object Name,CreationTime,LastWriteTime |
    Sort-Object LastWriteTime -Descending | Select-Object -First 50
  @{ ok = $true; data = $files } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; error = "Prefetch 폴더 접근 실패(관리자 권한 필요할 수 있음): $($_.Exception.Message)" } | ConvertTo-Json -Compress
}
""",
    },
    {
        "id": "running_processes",
        "label": "현재 실행 중인 프로세스",
        "description": "현재 실행 중인 프로세스 이름·PID·실행 경로. 프로세스 마스커레이딩(위장) 확인용.",
        "requires_admin": False,
        "command": "Get-Process | Select-Object Id,ProcessName,Path,StartTime",
        "script": r"""
$procs = Get-Process -EA SilentlyContinue | Select-Object Id,ProcessName,Path,StartTime -First 60
@{ ok = $true; data = $procs } | ConvertTo-Json -Depth 5 -Compress
""",
    },
    {
        "id": "usb_history",
        "label": "USB 저장장치 연결 이력",
        "description": "과거 연결됐던 USB 저장장치 목록(USBSTOR 레지스트리) — 데이터 반출 경로 조사용.",
        "requires_admin": False,
        "command": "Get-ChildItem HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        "script": r"""
try {
  $devices = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -EA Stop | ForEach-Object {
    $sub = Get-ChildItem $_.PSPath -EA SilentlyContinue | Select-Object -First 1
    [PSCustomObject]@{ device = $_.PSChildName; serial = $(if ($sub) { $sub.PSChildName } else { '' }) }
  }
  @{ ok = $true; data = $devices } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
""",
    },
]

_ITEMS_BY_ID = {item["id"]: item for item in COLLECTIBLE_ITEMS}

# ── 원격 SSH 수집 대상 (Linux/macOS/네트워크 장비) ─────────────────────────
# Linux/macOS는 sshd가 명령 문자열을 로그인 셸로 실행하므로 여러 명령을 그대로 나열해도
# 안전하다. 네트워크 장비는 위 모듈 docstring의 이유로 명령 1개만 둔다.
SSH_COLLECTIBLE = {
    "linux": {
        "platform_label": "Linux",
        "artifact_types": [
            {
                "artifact_type": "event_log",
                "label": "인증 로그 (로그온 성공/실패)",
                "commands": [
                    "grep -E 'Failed password|Accepted password' /var/log/auth.log 2>/dev/null | tail -100; "
                    "grep -E 'Failed password|Accepted password' /var/log/secure 2>/dev/null | tail -100",
                ],
            },
            {
                "artifact_type": "persistence_artifacts",
                "label": "지속성 메커니즘 (cron/systemd)",
                "commands": [
                    "echo '=== crontab ==='; crontab -l 2>/dev/null; "
                    "echo '=== systemd enabled services ==='; systemctl list-unit-files --type=service --state=enabled 2>/dev/null",
                ],
            },
            {
                "artifact_type": "process_list",
                "label": "실행 중인 프로세스",
                "commands": ["ps aux --sort=-%cpu | head -30"],
            },
            {
                "artifact_type": "filesystem_timeline",
                "label": "최근 24시간 내 변경된 파일",
                "commands": ["find /home /tmp /var/tmp -type f -mmin -1440 2>/dev/null | head -100"],
            },
        ],
    },
    "macos": {
        "platform_label": "macOS",
        "artifact_types": [
            {"artifact_type": "event_log", "label": "로그온 이력", "commands": ["last -100"]},
            {
                "artifact_type": "persistence_artifacts",
                "label": "지속성 메커니즘 (LaunchAgents/LaunchDaemons)",
                "commands": [
                    "ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null; "
                    "launchctl list | grep -v com.apple",
                ],
            },
            {"artifact_type": "process_list", "label": "실행 중인 프로세스", "commands": ["ps aux | head -30"]},
            {
                "artifact_type": "filesystem_timeline",
                "label": "최근 24시간 내 변경된 파일",
                "commands": ["find /Users /tmp -type f -mtime -1 2>/dev/null | head -100"],
            },
        ],
    },
    "cisco_ios": {
        "platform_label": "Cisco IOS (라우터/스위치)",
        "artifact_types": [
            {"artifact_type": "network_device_log", "label": "장비 로그", "commands": ["show logging | last 200"]},
        ],
    },
    "fortinet": {
        "platform_label": "Fortinet FortiGate",
        "artifact_types": [
            {"artifact_type": "network_device_log", "label": "장비 로그", "commands": ["execute log display"]},
        ],
    },
    "palo_alto": {
        "platform_label": "Palo Alto Networks (PAN-OS)",
        "artifact_types": [
            {"artifact_type": "network_device_log", "label": "트래픽 로그", "commands": ["show log traffic direction equal backward"]},
        ],
    },
    "juniper": {
        "platform_label": "Juniper (Junos)",
        "artifact_types": [
            {"artifact_type": "network_device_log", "label": "메시지 로그", "commands": ["show log messages | last 200"]},
        ],
    },
}

NETWORK_DEVICE_PLATFORMS = {"cisco_ios", "fortinet", "palo_alto", "juniper"}

# ── 클라우드 CLI 수집 대상 (이 백엔드 호스트에 설치·인증된 CLI를 그대로 실행) ─
def _aws_commands() -> list[list[str]]:
    return [["aws", "cloudtrail", "lookup-events", "--max-results", "50"]]


def _azure_commands() -> list[list[str]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    return [[
        "az", "monitor", "activity-log", "list",
        "--start-time", start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--end-time", end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--output", "json",
    ]]


def _gcp_commands() -> list[list[str]]:
    return [["gcloud", "logging", "read", "logName:activity", "--limit", "50", "--format", "json"]]


CLOUD_CLI_TARGETS = {
    "aws": {"platform_label": "AWS (CloudTrail)", "check_command": ["aws", "sts", "get-caller-identity"], "build_commands": _aws_commands},
    "azure": {"platform_label": "Azure (Activity Log)", "check_command": ["az", "account", "show"], "build_commands": _azure_commands},
    "gcp": {"platform_label": "GCP (Cloud Audit Logs)", "check_command": ["gcloud", "config", "get-value", "project"], "build_commands": _gcp_commands},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_ps(script: str, timeout: int = 20) -> str | None:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PRELUDE + script],
            capture_output=True, timeout=timeout,
        )
        return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


def _sha256_of(obj) -> str:
    canonical = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_private_key(pem_text: str) -> paramiko.PKey:
    """PEM 텍스트(RSA/Ed25519/ECDSA 어떤 형식인지 모를 때)에서 paramiko 키 객체를 만든다
    — AWS EC2가 발급하는 .pem 키 페어(대개 RSA 또는 ED25519)를 그대로 붙여넣어 쓸 수 있게
    하기 위해 지원하는 키 타입을 순서대로 시도한다."""
    last_error: Exception | None = None
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_cls.from_private_key(io.StringIO(pem_text))
        except Exception as e:
            last_error = e
    raise ValueError(f"개인키를 파싱할 수 없습니다(RSA/Ed25519/ECDSA 모두 실패): {last_error}")


def _ssh_connect(
    host: str, port: int, username: str, password: str | None, timeout: float = 8,
    pkey: paramiko.PKey | None = None,
) -> paramiko.SSHClient:
    """편의를 위해 최초 접속 시 호스트 키를 자동 등록한다(TOFU) — 이 도구가 전제하는
    "조사관이 이미 신뢰하는 내부망/조사 대상"에는 실용적인 타협이지만, 신뢰할 수 없는
    네트워크를 넘나드는 운영 환경에는 적합하지 않다(known_hosts 사전 등록 권장).

    pkey가 주어지면 비밀번호 대신 키 기반 인증을 쓴다 — AWS EC2 등 클라우드 VM은
    기본적으로 비밀번호 인증이 꺼져 있고 키 페어만 허용하는 경우가 대부분이라 필요."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=None if pkey else password, pkey=pkey,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    return client


def check_ssh_connection(host: str, port: int, username: str, password: str | None, pkey: paramiko.PKey | None = None) -> dict:
    """본격 수집 전 연결 가능 여부만 확인 — App 23의 check_remote_connection(WinRM)과
    동일한 목적. 블로킹 호출이므로 라우터에서 run_in_executor로 위임해야 한다."""
    try:
        client = _ssh_connect(host, port, username, password, pkey=pkey)
        client.close()
        return {"ok": True, "message": f"{host}:{port} SSH 연결 및 인증에 성공했습니다."}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "인증 실패 — 사용자명/비밀번호(또는 개인키)를 확인하세요."}
    except (paramiko.SSHException, OSError, TimeoutError) as e:
        return {"ok": False, "error": f"연결 실패 — 호스트/포트가 맞는지, SSH 서비스(22번 포트 등)가 열려 있는지 확인하세요: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _run_ssh_commands(
    host: str, port: int, username: str, password: str | None, commands: list[str], timeout: float = 15,
    pkey: paramiko.PKey | None = None,
) -> dict:
    try:
        client = _ssh_connect(host, port, username, password, timeout=timeout, pkey=pkey)
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "인증 실패 — 사용자명/비밀번호(또는 개인키)를 확인하세요."}
    except (paramiko.SSHException, OSError, TimeoutError) as e:
        return {"ok": False, "error": f"연결 실패 — 호스트/포트가 맞는지, SSH 서비스가 열려 있는지 확인하세요: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

    outputs = []
    try:
        for cmd in commands:
            try:
                _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                outputs.append(f"$ {cmd}\n{out}" + (f"[stderr] {err}" if err.strip() else ""))
            except Exception as e:
                outputs.append(f"$ {cmd}\n[실행 실패: {e}]")
    finally:
        client.close()

    return {"ok": True, "output": "\n\n".join(outputs)}


def _run_subprocess(cmd: list[str], timeout: int = 30) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return {
            "ok": proc.returncode == 0,
            "stdout": proc.stdout.decode("utf-8", errors="replace"),
            "stderr": proc.stderr.decode("utf-8", errors="replace"),
        }
    except FileNotFoundError:
        return {"ok": False, "error": f"명령을 찾을 수 없습니다: {cmd[0]} — 이 백엔드 호스트에 해당 CLI가 설치되어 있는지 확인하세요."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "명령 실행 시간이 초과됐습니다."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_cloud_cli(provider: str) -> dict:
    """클라우드 CLI가 설치되어 있고 인증된 상태인지 확인 — 실제 수집 전 사전 점검용."""
    target = CLOUD_CLI_TARGETS.get(provider)
    if target is None:
        return {"ok": False, "error": f"Unknown provider: {provider}"}
    result = _run_subprocess(target["check_command"], timeout=15)
    if result.get("ok"):
        return {"ok": True, "message": f"{target['platform_label']} CLI 인증이 확인됐습니다."}
    if "error" in result:
        return {"ok": False, "error": result["error"]}
    return {"ok": False, "error": f"{target['platform_label']} CLI가 인증되지 않은 것으로 보입니다: {result.get('stderr', '')[:300] or '(오류 메시지 없음)'}"}


def collect_remote(platform: str, artifact_type: str, host: str, port: int, username: str, password: str, collected_by: str) -> dict:
    """Linux/macOS/네트워크 장비에 SSH로 접속해 실제로 명령을 실행하고 chain of custody
    레코드를 만든다. 블로킹 호출이므로 라우터에서 run_in_executor로 위임해야 한다."""
    platform_def = SSH_COLLECTIBLE.get(platform)
    if platform_def is None:
        raise ValueError(f"Unknown platform: {platform}")
    item = next((a for a in platform_def["artifact_types"] if a["artifact_type"] == artifact_type), None)
    if item is None:
        raise ValueError(f"Unknown artifact_type '{artifact_type}' for platform '{platform}'")

    result = _run_ssh_commands(host, port, username, password, item["commands"])
    collected_at = _now_iso()
    label = f"{platform_def['platform_label']} — {item['label']} ({host})"
    command_display = " ; ".join(item["commands"])

    if not result.get("ok"):
        error_suffix = " (네트워크 장비는 SSH 비인터랙티브 실행 방식에 의존해 일부 장비/펌웨어에서 동작하지 않을 수 있습니다 — 실패 시 가이드의 수동 명령을 직접 실행하세요.)" if platform in NETWORK_DEVICE_PLATFORMS else ""
        record = {
            "item_id": f"remote_{platform}_{artifact_type}", "label": label, "command": command_display,
            "collected_by": collected_by.strip() or "익명", "collected_at": collected_at,
            "ok": False, "error": result.get("error", "") + error_suffix, "data": "", "count": 0,
            "target_host": host,
        }
    else:
        text = result["output"]
        record = {
            "item_id": f"remote_{platform}_{artifact_type}", "label": label, "command": command_display,
            "collected_by": collected_by.strip() or "익명", "collected_at": collected_at,
            "ok": True, "error": None, "data": text, "count": text.count("\n") + (1 if text else 0),
            "target_host": host,
        }
    record["sha256"] = _sha256_of(record["data"])
    return record


def collect_cloud(provider: str, collected_by: str) -> dict:
    """이 백엔드 호스트에 설치·인증된 클라우드 CLI(aws/az/gcloud)를 그대로 실행해
    감사 로그를 수집한다. 블로킹 호출이므로 라우터에서 run_in_executor로 위임해야 한다."""
    target = CLOUD_CLI_TARGETS.get(provider)
    if target is None:
        raise ValueError(f"Unknown provider: {provider}")

    commands = target["build_commands"]()
    parts = []
    all_ok = True
    for cmd in commands:
        r = _run_subprocess(cmd)
        if not r.get("ok"):
            all_ok = False
        stdout = r.get("stdout", "")
        stderr = r.get("stderr", "") or r.get("error", "")
        parts.append(f"$ {' '.join(cmd)}\n{stdout}" + (f"[stderr] {stderr}" if stderr.strip() else ""))
    combined = "\n\n".join(parts)

    record = {
        "item_id": f"cloud_{provider}",
        "label": f"클라우드 감사 로그 — {target['platform_label']}",
        "command": " ; ".join(" ".join(c) for c in commands),
        "collected_by": collected_by.strip() or "익명",
        "collected_at": _now_iso(),
        "ok": all_ok,
        "error": None if all_ok else f"일부 명령이 실패했습니다 — {target['platform_label']} CLI 설치·인증 상태를 확인하세요.",
        "data": combined,
        "count": combined.count("\n") + (1 if combined else 0),
        "target_host": f"local CLI ({provider})",
    }
    record["sha256"] = _sha256_of(record["data"])
    return record


def collect_item(item_id: str, collected_by: str) -> dict:
    """실제로 이 PC에서 PowerShell을 실행해 증거를 수집하고, 무결성 해시와 함께 반환한다.
    블로킹 서브프로세스 호출이므로 라우터에서 run_in_executor로 스레드에 위임해야 한다
    (이 프로젝트 전체에서 반복된 패턴)."""
    item = _ITEMS_BY_ID.get(item_id)
    if item is None:
        raise ValueError(f"Unknown item_id: {item_id}")

    raw = _run_ps(item["script"])
    collected_at = _now_iso()

    if raw is None or not raw.strip():
        parsed = {"ok": False, "error": "PowerShell 실행 실패 또는 응답 없음(타임아웃)"}
    else:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"ok": False, "error": "PowerShell 출력 파싱 실패", "raw_output": raw[:2000]}

    data = parsed.get("data", []) if parsed.get("ok") else []
    record = {
        "item_id": item_id,
        "label": item["label"],
        "command": item["command"],
        "collected_by": collected_by.strip() or "익명",
        "collected_at": collected_at,
        "ok": bool(parsed.get("ok")),
        "error": parsed.get("error"),
        "data": data,
        "count": len(data) if isinstance(data, list) else (1 if data else 0),
    }
    record["sha256"] = _sha256_of(record["data"])
    return record


def generate_custody_report(records: list[dict]) -> str:
    lines = [
        "# 포렌식 증거 수집 — Chain of Custody 기록",
        "",
        "> 이 문서는 이 도구가 수집 시점에 실제로 조회한 데이터와 그 SHA-256 무결성 해시를 기록한 것입니다.",
        "> 법적 증거로 사용하려면 별도의 정식 포렌식 절차(쓰기방지 이미징 등)를 거쳐야 합니다.",
        "",
        "---",
        "",
    ]
    for r in records:
        status = "성공" if r.get("ok") else f"실패 — {r.get('error', '')}"
        lines += [
            f"## {r.get('label')}",
            "",
            f"- **수집 시각(UTC):** {r.get('collected_at')}",
            f"- **수집자:** {r.get('collected_by')}",
            f"- **실행 명령:** `{r.get('command')}`",
            f"- **결과:** {status} ({r.get('count', 0)}건)",
            f"- **SHA-256(데이터 무결성 해시):** `{r.get('sha256')}`",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)
