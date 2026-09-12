"""등록된 장비에서 실제로 설정/로그를 수집하는 계층 — "장비 등록 → 주기적으로 API/SSH로
직접 접속해 정보를 가져와 분석"이라는 SIEM 스타일 자동화의 핵심.

새로 구현하지 않고 이미 검증된 두 모듈의 수집기를 그대로 재사용한다:
- `forensics_collection_service`의 SSH(paramiko) 명령 실행기·클라우드 CLI 서브프로세스
  실행기 — App 25 '증거 수집 도구' 탭에서 이미 연결 실패(WinRM/SSH 미설정, CLI 미인증
  등)를 구분해 안내하는 처리까지 검증된 코드.
- `attack_monitor_service`의 Windows 로컬/WinRM 실행기 — App 23에서 이미 "here-string은
  stdin으로 넘기면 조용히 실패한다" 같은 실제 버그를 겪고 고친 코드.

이 모듈이 새로 하는 일은 "장비 유형별로 어떤 명령을 보내고, 그 결과를 어떤 분석기
(firewall_audit/iam_audit/log_analysis)의 어떤 source_type으로 넘길지"를 결정하는
매핑뿐이다 — 실제 접속·실행 로직은 위 두 모듈에 위임한다.

블로킹 호출(SSH/서브프로세스/PowerShell)로 구성되어 있으므로, 호출부(스케줄러·라우터)는
반드시 `run_in_executor`로 스레드에 위임해야 한다(이 프로젝트 전체에서 반복된 패턴).
"""

from services import attack_monitor_service as ams
from services import forensics_collection_service as fcs


def _pkey_for(device: dict):
    """auth_method가 private_key면 저장된(복호화된) PEM 텍스트를 paramiko 키 객체로 만들어
    반환한다 — AWS EC2 등 비밀번호 인증이 꺼져 있고 키 페어만 허용하는 대상 지원용.
    password 방식이면 None을 반환해 기존 비밀번호 인증 경로를 그대로 탄다."""
    if device.get("auth_method") != "private_key":
        return None
    return fcs._load_private_key(device.get("password", ""))

NETWORK_DEVICE_VENDORS = {
    "cisco_ios": {"label": "Cisco IOS (라우터/스위치)", "command": "show running-config", "firewall_source_type": "router_switch"},
    "juniper": {"label": "Juniper (Junos)", "command": "show configuration | display set", "firewall_source_type": "router_switch"},
    "fortinet": {"label": "Fortinet FortiGate", "command": "show full-configuration", "firewall_source_type": "other"},
    "palo_alto": {"label": "Palo Alto Networks (PAN-OS)", "command": "show config running", "firewall_source_type": "other"},
}

_LINUX_FIREWALL_CMD = "iptables -L -n -v --line-numbers 2>/dev/null; echo '--- nftables ---'; nft list ruleset 2>/dev/null"
_LINUX_LOG_CMD = (
    "tail -n 150 /var/log/auth.log 2>/dev/null; tail -n 150 /var/log/secure 2>/dev/null"
)

_WINDOWS_FIREWALL_PS = (
    "netsh advfirewall firewall show rule name=all dir=in | Select-String -Pattern "
    "'Rule Name|Enabled|Direction|Action|Profiles|LocalPort|RemoteIP' | Out-String"
)


def _aws_cmd(analyzer: str, profile: str) -> list[str]:
    if analyzer == "firewall_audit":
        cmd = ["aws", "ec2", "describe-security-groups", "--output", "json"]
    else:
        cmd = ["aws", "iam", "get-account-authorization-details", "--filter", "User", "Role", "LocalManagedPolicy", "--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    return cmd


def _azure_cmd(analyzer: str, subscription: str) -> list[str]:
    if analyzer == "firewall_audit":
        cmd = ["az", "network", "nsg", "list", "--output", "json"]
    else:
        cmd = ["az", "role", "assignment", "list", "--all", "--output", "json"]
    if subscription:
        cmd += ["--subscription", subscription]
    return cmd


def _gcp_cmd(analyzer: str, project: str) -> list[str]:
    if analyzer == "firewall_audit":
        return ["gcloud", "compute", "firewall-rules", "list", "--project", project, "--format=json"]
    return ["gcloud", "projects", "get-iam-policy", project, "--format=json"]


# 분석기별 source_type — firewall_audit_service.SOURCE_LABELS / iam_audit_service.SOURCE_LABELS와
# 반드시 같은 값을 써야 한다(다르면 "Invalid source_type"으로 거부됨).
_FIREWALL_SOURCE_TYPE = {
    "linux_host": "iptables", "windows_host": "windows_fw",
    "aws_account": "aws_sg", "azure_subscription": "azure_nsg", "gcp_project": "gcp_fw",
}
_IAM_SOURCE_TYPE = {
    "aws_account": "aws_iam", "azure_subscription": "azure_rbac", "gcp_project": "gcp_iam",
}


def _winrm_target(device: dict) -> dict | None:
    host = (device.get("host") or "").strip()
    if not host or host in ("localhost", "127.0.0.1"):
        return None
    return {"host": host, "username": device.get("username", ""), "password": device.get("password", "")}


def collect(device: dict) -> dict:
    """device(비밀번호가 복호화된 내부용 dict, device_store.get_device_internal 결과)에서
    실제로 데이터를 수집한다. 반환: {"ok": bool, "content": str, "source_type": str|None,
    "error": str|None} — source_type은 firewall_audit/iam_audit 분석기에 그대로 전달된다
    (log_analysis는 source_type 없이 텍스트만 analyze_logs에 넘기므로 None)."""
    device_type = device["device_type"]
    analyzer = device["analyzer"]

    try:
        if device_type == "network_device":
            return _collect_network_device(device)
        if device_type == "linux_host":
            return _collect_linux(device, analyzer)
        if device_type == "windows_host":
            return _collect_windows(device, analyzer)
        if device_type in ("aws_account", "azure_subscription", "gcp_project"):
            return _collect_cloud(device, analyzer)
        return {"ok": False, "content": "", "source_type": None, "error": f"알 수 없는 장비 유형: {device_type}"}
    except Exception as e:
        return {"ok": False, "content": "", "source_type": None, "error": f"수집 중 예외 발생: {e}"}


def _collect_network_device(device: dict) -> dict:
    vendor = device.get("vendor")
    vendor_def = NETWORK_DEVICE_VENDORS.get(vendor)
    if vendor_def is None:
        return {"ok": False, "content": "", "source_type": None, "error": f"지원하지 않는 벤더: {vendor}"}
    host = device.get("host", "")
    port = int(device.get("port") or 22)
    pkey = _pkey_for(device)
    password = None if pkey else device.get("password", "")
    result = fcs._run_ssh_commands(host, port, device.get("username", ""), password, [vendor_def["command"]], pkey=pkey)
    if not result.get("ok"):
        return {"ok": False, "content": "", "source_type": None, "error": result.get("error", "SSH 접속 실패")}
    return {"ok": True, "content": result["output"], "source_type": vendor_def["firewall_source_type"], "error": None}


def _collect_linux(device: dict, analyzer: str) -> dict:
    host = device.get("host", "")
    port = int(device.get("port") or 22)
    cmd = _LINUX_FIREWALL_CMD if analyzer == "firewall_audit" else _LINUX_LOG_CMD
    pkey = _pkey_for(device)
    password = None if pkey else device.get("password", "")
    result = fcs._run_ssh_commands(host, port, device.get("username", ""), password, [cmd], pkey=pkey)
    if not result.get("ok"):
        return {"ok": False, "content": "", "source_type": None, "error": result.get("error", "SSH 접속 실패")}
    source_type = _FIREWALL_SOURCE_TYPE["linux_host"] if analyzer == "firewall_audit" else None
    return {"ok": True, "content": result["output"], "source_type": source_type, "error": None}


def _collect_windows(device: dict, analyzer: str) -> dict:
    target = _winrm_target(device)
    if analyzer == "firewall_audit":
        raw = ams._run_remote_aware(_WINDOWS_FIREWALL_PS, target, timeout=25)
        if raw is None or not raw.strip():
            return {"ok": False, "content": "", "source_type": None, "error": "PowerShell 실행 실패 또는 응답 없음(WinRM 미설정/방화벽 규칙이 너무 많아 타임아웃했을 수 있습니다)"}
        return {"ok": True, "content": raw, "source_type": _FIREWALL_SOURCE_TYPE["windows_host"], "error": None}

    # log_analysis: App 23이 이미 만든 실시간 신호 수집(로그온 실패/Defender 탐지/새 리스너)을
    # 그대로 재사용 — baseline_listeners는 장비별 이전 상태를 들고 있지 않으므로 매번 None으로
    # 호출한다(= "새로 열린 포트" 비교 없이 이번 수집 시점의 신호만 본다는 의미).
    raw_log, _listeners = ams.collect_real_signals(None, window_minutes=device.get("interval_minutes", 60), target=target)
    if not raw_log.strip():
        raw_log = "관측된 의심 신호가 없습니다 (로그온 실패/Defender 탐지 0건)."
    return {"ok": True, "content": raw_log, "source_type": None, "error": None}


def _collect_cloud(device: dict, analyzer: str) -> dict:
    device_type = device["device_type"]
    selector = (device.get("host") or "").strip()  # aws=profile(선택)/azure=subscription(선택)/gcp=project(필수)

    if device_type == "gcp_project" and not selector:
        return {"ok": False, "content": "", "source_type": None, "error": "GCP는 프로젝트 ID를 호스트/식별자 칸에 입력해야 합니다."}

    if device_type == "aws_account":
        cmd = _aws_cmd(analyzer, selector)
    elif device_type == "azure_subscription":
        cmd = _azure_cmd(analyzer, selector)
    else:
        cmd = _gcp_cmd(analyzer, selector)

    result = fcs._run_subprocess(cmd, timeout=60)
    if not result.get("ok"):
        error = result.get("error") or result.get("stderr") or "CLI 실행 실패"
        return {"ok": False, "content": "", "source_type": None, "error": error[:1000]}

    source_map = _FIREWALL_SOURCE_TYPE if analyzer == "firewall_audit" else _IAM_SOURCE_TYPE
    return {"ok": True, "content": result["stdout"], "source_type": source_map[device_type], "error": None}


def check_connection(device: dict) -> dict:
    """저장 전 [연결 테스트] 버튼 — 실제로 접속만 확인하고 데이터는 수집하지 않는다."""
    device_type = device["device_type"]
    try:
        if device_type in ("network_device", "linux_host"):
            host, port = device.get("host", ""), int(device.get("port") or 22)
            pkey = _pkey_for(device)
            password = None if pkey else device.get("password", "")
            return fcs.check_ssh_connection(host, port, device.get("username", ""), password, pkey=pkey)
        if device_type == "windows_host":
            target = _winrm_target(device)
            if target is None:
                return {"ok": True, "message": "이 PC(로컬)를 대상으로 하므로 원격 연결 확인이 필요 없습니다."}
            return ams.check_remote_connection(target)
        if device_type in ("aws_account", "azure_subscription", "gcp_project"):
            # forensics_collection_service.check_cloud_cli()의 성공 메시지는 "AWS (CloudTrail)"처럼
            # 그 모듈(App 25 증거 수집)의 용도에 맞춘 라벨을 담고 있어 여기서는 재구성한다 —
            # 실제 인증 확인 로직(aws sts get-caller-identity 등)만 재사용하고 문구는 이 기능에 맞게 바꾼다.
            provider = {"aws_account": "aws", "azure_subscription": "azure", "gcp_project": "gcp"}[device_type]
            result = fcs.check_cloud_cli(provider)
            if result.get("ok"):
                label = {"aws_account": "AWS CLI", "azure_subscription": "Azure CLI", "gcp_project": "GCP CLI"}[device_type]
                return {"ok": True, "message": f"{label} 인증이 확인됐습니다 — 이 백엔드 호스트에 설정된 자격증명을 그대로 사용합니다."}
            return result
        return {"ok": False, "error": f"알 수 없는 장비 유형: {device_type}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
