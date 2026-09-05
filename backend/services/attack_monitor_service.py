"""App 23(실시간 공격 모니터링 & 대응 센터)의 '실제 시스템' 탭 백엔드.

이 프로젝트의 기존 실시간 모니터링(App 1의 '실시간' 탭)은 실제 로그 소스가 없는
데모 환경이라 합성 로그를 생성해 분석 파이프라인을 시연한다. 이 모듈은 그와 달리
**이 Windows PC의 실제 보안 신호**(로그온 실패 이벤트, Windows Defender 탐지,
방화벽 로그, 새로 열린 리스닝 포트)를 PowerShell로 직접 조회해, App 1과 동일한
analyze_logs() 파이프라인(Claude 또는 Mock)에 태워 위협을 분류한다.

⚠️ Windows 전용(PowerShell 5.1 기준)이며, 방화벽 연결 로깅(LogAllowed/LogBlocked)은
관리자 권한이 있어야 켤 수 있어 이 세션에서는 활성화하지 못했다 — 비활성 상태에서도
동작하도록 방화벽 로그는 best-effort로만 사용하고, 로그온 실패/Defender 탐지/신규
리스너 변화는 관리자 권한 없이도 조회 가능함을 실제로 확인해 주력 신호로 사용한다.
get_exposure_snapshot()의 notes에 로깅을 켜는 방법(관리자 권한 필요)을 안내한다.
"""

import json
import subprocess
from datetime import datetime, timezone

from services.response_playbook import get_response_action

_EXPOSURE_SCRIPT = r"""
$result = [ordered]@{}
$result.firewall_profiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled,LogAllowed,LogBlocked)
$result.rdp_deny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
try {
  $result.failed_logon_24h = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-24)} -EA Stop).Count
} catch { $result.failed_logon_24h = 0 }
$result.exposed_listeners = @(Get-NetTCPConnection -State Listen -EA SilentlyContinue | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
  [PSCustomObject]@{ address = $_.LocalAddress; port = $_.LocalPort; process = $(if ($p) { $p.ProcessName } else { 'unknown' }) }
})
try { $result.defender_realtime = [bool](Get-MpComputerStatus -EA Stop).RealTimeProtectionEnabled } catch { $result.defender_realtime = $null }
try { $result.defender_recent_threats = @(Get-MpThreatDetection -EA Stop).Count } catch { $result.defender_recent_threats = 0 }
$result | ConvertTo-Json -Depth 5 -Compress
"""

_COLLECT_SCRIPT_TPL = r"""
$since = (Get-Date).AddMinutes(-__MINUTES__)
$result = [ordered]@{}
try {
  $result.failed_logons = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -EA Stop |
    Select-Object -First 20 TimeCreated,@{n='Account';e={$_.Properties[5].Value}},@{n='SourceIP';e={$_.Properties[19].Value}})
} catch { $result.failed_logons = @() }
try {
  $result.defender_threats = @(Get-MpThreatDetection -EA Stop | Where-Object { $_.InitialDetectionTime -ge $since } |
    Select-Object -First 10 ThreatID,ProcessName,InitialDetectionTime)
} catch { $result.defender_threats = @() }
$result.current_listeners = @(Get-NetTCPConnection -State Listen -EA SilentlyContinue | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
  "$($_.LocalAddress)|$($_.LocalPort)|$(if ($p) { $p.ProcessName } else { 'unknown' })"
})
try {
  $log = "$env:systemroot\system32\LogFiles\Firewall\pfirewall.log"
  # ALLOW 항목은 이 개발 PC 자신의 정상 트래픽(로컬 5180/8000 등)이 대부분이라 노이즈가 크므로,
  # 실제 위협 신호로서 의미 있는 DROP(차단)만 골라 태운다. -Tail은 ALLOW가 훨씬 많이 쌓이는
  # 상황에서도 최근 DROP을 놓치지 않도록 넉넉히 잡는다.
  if (Test-Path $log) { $result.firewall_log_tail = @(Get-Content $log -Tail 300 -EA Stop | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} DROP ' } | Select-Object -Last 20) } else { $result.firewall_log_tail = @() }
} catch { $result.firewall_log_tail = @() }
$result | ConvertTo-Json -Depth 5 -Compress
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_ps(script: str, timeout: int = 20) -> str | None:
    prelude = (
        "$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "$ProgressPreference='SilentlyContinue'; "
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prelude + script],
            capture_output=True, timeout=timeout,
        )
        return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


def _safe_json(raw: str | None):
    if not raw or not raw.strip():
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _ensure_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def get_exposure_snapshot() -> dict:
    """지금 이 순간 이 PC의 실제 외부 노출 상태를 결정론적으로(AI 미사용) 점검한다.
    App 3/11의 recon/environment 가이드가 '정적 안내'라면, 이건 매번 실제로 조회한 라이브 결과다."""
    data = _safe_json(_run_ps(_EXPOSURE_SCRIPT)) or {}

    profiles = _ensure_list(data.get("firewall_profiles"))
    logging_enabled = bool(profiles) and all(p.get("LogAllowed") and p.get("LogBlocked") for p in profiles)
    rdp_enabled = data.get("rdp_deny") == 0
    failed_24h = data.get("failed_logon_24h") or 0
    listeners = _ensure_list(data.get("exposed_listeners"))
    defender_realtime = data.get("defender_realtime")
    defender_threats = data.get("defender_recent_threats") or 0

    notes = []
    if not profiles:
        notes.append({"level": "INFO", "text": "방화벽 상태를 조회하지 못했습니다 (PowerShell 실행 제한 가능성).", "command": None})
    elif not logging_enabled:
        notes.append({
            "level": "MEDIUM",
            "text": "Windows 방화벽 연결 로깅이 꺼져 있어 실제 인바운드 차단/허용 이력을 볼 수 없습니다. 관리자 권한 PowerShell에서 켤 수 있습니다.",
            "command": "netsh advfirewall set allprofiles logging droppedconnections enable; netsh advfirewall set allprofiles logging allowedconnections enable",
        })
    if rdp_enabled:
        notes.append({"level": "HIGH", "text": "원격 데스크톱(RDP)이 활성화되어 있습니다. 사용하지 않는다면 끄는 것을 권장합니다.", "command": None})
    if failed_24h:
        notes.append({
            "level": "HIGH" if failed_24h >= 5 else "MEDIUM",
            "text": f"최근 24시간 동안 로그온 실패(Event ID 4625)가 {failed_24h}건 있었습니다.",
            "command": None,
        })
    if defender_realtime is False:
        notes.append({"level": "HIGH", "text": "Windows Defender 실시간 보호가 꺼져 있습니다.", "command": None})
    if defender_threats:
        notes.append({"level": "CRITICAL", "text": f"Windows Defender가 최근 탐지한 위협이 {defender_threats}건 있습니다.", "command": None})
    if not notes:
        notes.append({"level": "INFO", "text": "현재 점검 항목에서 특이사항이 발견되지 않았습니다.", "command": None})

    return {
        "checked_at": _now_iso(),
        "firewall_profiles": profiles,
        "firewall_logging_enabled": logging_enabled,
        "rdp_enabled": rdp_enabled,
        "failed_logon_24h": failed_24h,
        "exposed_listeners": listeners,
        "defender_realtime_protection": defender_realtime,
        "defender_recent_threats": defender_threats,
        "notes": notes,
    }


def collect_real_signals(baseline_listeners: set | None, window_minutes: int = 5) -> tuple[str, set]:
    """실제 Windows 신호를 모아 analyze_logs()가 이해하는 로그 텍스트로 변환한다.
    baseline_listeners가 주어지면 그 이후 새로 열린 리스너만 이상 신호로 취급하고,
    (갱신된) 현재 리스너 집합을 함께 반환해 다음 호출의 baseline으로 쓰게 한다."""
    script = _COLLECT_SCRIPT_TPL.replace("__MINUTES__", str(int(window_minutes)))
    data = _safe_json(_run_ps(script)) or {}

    failed_logons = _ensure_list(data.get("failed_logons"))
    defender_threats = _ensure_list(data.get("defender_threats"))
    current_listeners_raw = _ensure_list(data.get("current_listeners"))
    firewall_log_tail = _ensure_list(data.get("firewall_log_tail"))

    current_listeners = {x for x in current_listeners_raw if x}
    new_listeners = current_listeners - baseline_listeners if baseline_listeners is not None else set()

    now = _now_iso()
    lines = []

    for f in failed_logons:
        acct = f.get("Account") or "unknown"
        ip = f.get("SourceIP") or "unknown"
        ts = f.get("TimeCreated") or now
        lines.append(f"{ts} windows_security[4625]: Failed logon attempt for account={acct} from source_ip={ip}")

    for t in defender_threats:
        proc = t.get("ProcessName") or "unknown"
        threat_id = t.get("ThreatID") or "unknown"
        ts = t.get("InitialDetectionTime") or now
        lines.append(f"{ts} windows_defender: Threat detected (id={threat_id}) related process={proc}")

    for entry in sorted(new_listeners):
        parts = entry.split("|", 2)
        addr = parts[0] if len(parts) > 0 else "?"
        port = parts[1] if len(parts) > 1 else "?"
        proc = parts[2] if len(parts) > 2 else "unknown"
        lines.append(f"{now} network: New listener opened at {addr}:{port} process={proc} (bound to all interfaces)")

    for fl in firewall_log_tail[-20:]:
        lines.append(f"{now} windows_firewall: {fl}")

    if not lines:
        lines.append(
            f"{now} status: No suspicious signals observed in the last {window_minutes} minutes "
            f"(failed_logons=0, defender_threats=0, new_listeners=0, monitored_listeners={len(current_listeners)})"
        )

    return "\n".join(lines), current_listeners


def enrich_with_response(analysis: dict) -> dict:
    """analyze_logs()의 각 이벤트에 response_playbook의 대응 제안을 부착한다."""
    for ev in analysis.get("events", []) or []:
        ev["response"] = get_response_action(ev.get("category", ""), ev.get("description", ""), ev.get("source_ip"))
    return analysis


def generate_markdown_report(entry: dict) -> str:
    mode_label = "실제 시스템 모니터링" if entry.get("mode") == "real" else "시뮬레이션(데모)"
    lines = [
        "# 실시간 공격 모니터링 & 대응 리포트",
        "",
        f"**모드:** {mode_label}  ",
        f"**종합 위협도:** {entry.get('threat_level', 'N/A')}  ",
        "",
        entry.get("summary", ""),
        "",
        "---",
        "",
        "## 탐지된 이벤트 및 대응 제안",
        "",
    ]

    events = entry.get("events") or []
    if not events:
        lines.append("탐지된 이벤트가 없습니다.")

    for ev in events:
        resp = ev.get("response") or {}
        lines += [
            f"### [{ev.get('severity')}] {ev.get('category')}",
            "",
            ev.get("description", ""),
            "",
            f"- 소스 IP: `{ev.get('source_ip') or '-'}`",
            f"- AI 권장 조치: {ev.get('remediation', '')}",
            f"- 플레이북 제안: **{resp.get('action_label', '')}** — {resp.get('rationale', '')}",
        ]
        if resp.get("suggested_command"):
            lines += ["", "```powershell", resp["suggested_command"], "```", "", f"> {resp.get('note', '')}"]
        lines += ["", "---", ""]

    lines += [
        "## 다음 단계",
        "",
        "- 더 깊은 사고 대응 절차가 필요하면 [인시던트 리스폰스 어시스턴트](/incident)를 이용하세요.",
        "- 네트워크 노출 자체를 줄이려면 [방화벽 정책 감사기](/firewall-audit)로 실제 규칙을 점검하세요.",
        "",
        "> 이 리포트의 대응 명령은 참고용 제안이며 자동 실행되지 않습니다. 반드시 확인 후 수동으로 실행하세요.",
    ]
    return "\n".join(lines)
