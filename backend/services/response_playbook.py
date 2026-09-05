"""탐지된 이벤트 카테고리 → 구체적인 '대응 제안'으로 매핑하는 결정론적(비-AI) 모듈.
App 23(실시간 공격 모니터링 & 대응 센터)가 analyze_logs()의 각 이벤트에 부착한다.

⚠️ 안전 설계: 이 모듈은 절대 명령을 실행하지 않는다. suggested_command는 항상
'참고용 텍스트'이며, 사용자가 직접 확인 후 수동으로 실행해야 한다 — 이 프로젝트
전반의 원칙(App 9의 시뮬레이션 명령, App 6/17의 승인 체크박스 등)과 동일하게,
자동으로 방화벽 규칙을 추가하거나 프로세스를 종료하는 등 되돌리기 어려운 동작은
절대 자동 수행하지 않는다.
"""

import ipaddress
import time

_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7")
]


def _is_blockable_external_ip(ip: str | None) -> bool:
    """차단 명령을 제안해도 되는 '외부' IP인지 판단. 사설/루프백/미상 값은 제외
    (내부망 IP를 실수로 차단하라고 제안하지 않기 위한 안전장치)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in _PRIVATE_NETS)


_KEYWORD_RULES = [
    (("brute", "무차별", "logon", "credential", "password spray"), "brute_force"),
    (("scan", "스캔", "recon", "정찰", "reconnaissance"), "scan"),
    (("malware", "trojan", "ransomware", "랜섬", "바이러스", "backdoor", "백도어", "worm"), "malware"),
    (("injection", "sql", "인젝션", "xss", "ssti"), "injection"),
    (("exfil", "유출", "outbound", "전송량", "data transfer"), "exfil"),
    (("privilege", "권한 상승", "escalation", "privesc"), "privilege"),
]

_PLAYBOOK = {
    "brute_force": {
        "action_label": "출발지 IP 인바운드 차단",
        "rationale": "짧은 시간에 로그인 실패가 반복되면 무차별 대입 공격일 가능성이 높습니다. "
                     "출발지 IP를 인바운드에서 차단하고, 계정 잠금 정책/MFA 적용 여부를 함께 점검하세요.",
        "related_link": "/incident",
        "related_label": "인시던트 리스폰스 어시스턴트",
        "command_kind": "block_in",
    },
    "scan": {
        "action_label": "출발지 IP 차단 + 노출 포트 재점검",
        "rationale": "포트 스캔/정찰은 후속 공격의 전조일 수 있습니다. 출발지를 차단하고, "
                     "실제로 열려 있어야 하는 포트인지 방화벽 정책 감사기로 재확인하세요.",
        "related_link": "/firewall-audit",
        "related_label": "방화벽 정책 감사기",
        "command_kind": "block_in",
    },
    "malware": {
        "action_label": "네트워크 격리 후 정밀 검사",
        "rationale": "악성코드가 의심되면 네트워크에서 즉시 격리(랜선 분리/Wi-Fi 끄기)하고 "
                     "Windows Defender 전체 검사를 실행하세요. 증거 보존이 필요하면 삭제 전 이미지를 먼저 확보하세요.",
        "related_link": "/incident",
        "related_label": "인시던트 리스폰스 어시스턴트",
        "command_kind": None,
    },
    "injection": {
        "action_label": "애플리케이션 계층 점검",
        "rationale": "이 유형은 OS 방화벽 차단만으로는 근본 해결이 안 됩니다. "
                     "웹 취약점 스캐너·취약점 스캐너로 해당 엔드포인트를 점검하고 입력 검증/파라미터화 쿼리를 적용하세요.",
        "related_link": "/webscan",
        "related_label": "웹 취약점 스캐너",
        "command_kind": None,
    },
    "exfil": {
        "action_label": "의심 목적지로의 아웃바운드 차단",
        "rationale": "비정상적인 대량 아웃바운드 전송은 데이터 유출 정황일 수 있습니다. "
                     "목적지를 아웃바운드에서 차단하고 어떤 프로세스가 전송했는지 확인하세요.",
        "related_link": "/incident",
        "related_label": "인시던트 리스폰스 어시스턴트",
        "command_kind": "block_out",
    },
    "privilege": {
        "action_label": "권한/계정 감사",
        "rationale": "권한 상승 시도 흔적이 보이면 로컬 관리자 그룹 구성원과 해당 계정의 최근 활동을 확인하세요.",
        "related_link": "/iam-audit",
        "related_label": "클라우드 IAM 정책 감사기",
        "command_kind": "audit_admins",
    },
}

_DEFAULT = {
    "action_label": "인시던트 대응 절차 개시",
    "rationale": "구체적인 OS 명령으로 바로 대응하기 어려운 유형입니다. "
                 "인시던트 리스폰스 어시스턴트에서 이 사고 유형에 맞는 단계별 대응 계획을 세우는 것을 권장합니다.",
    "related_link": "/incident",
    "related_label": "인시던트 리스폰스 어시스턴트",
    "command_kind": None,
}


def get_response_action(category: str, description: str, source_ip: str | None) -> dict:
    text = f"{category or ''} {description or ''}".lower()
    key = next((k for kws, k in _KEYWORD_RULES if any(kw in text for kw in kws)), None)
    rule = _PLAYBOOK.get(key, _DEFAULT)

    command = None
    if rule["command_kind"] == "block_in" and _is_blockable_external_ip(source_ip):
        command = (
            f'New-NetFirewallRule -DisplayName "Block-{source_ip}-{int(time.time())}" '
            f'-Direction Inbound -Action Block -RemoteAddress {source_ip}'
        )
    elif rule["command_kind"] == "block_out" and _is_blockable_external_ip(source_ip):
        command = (
            f'New-NetFirewallRule -DisplayName "Block-Out-{source_ip}-{int(time.time())}" '
            f'-Direction Outbound -Action Block -RemoteAddress {source_ip}'
        )
    elif rule["command_kind"] == "audit_admins":
        command = "Get-LocalGroupMember -Group Administrators"

    return {
        "action_label": rule["action_label"],
        "suggested_command": command,
        "rationale": rule["rationale"],
        "related_link": rule["related_link"],
        "related_label": rule["related_label"],
        "note": "참고용 제안입니다 — 자동 실행되지 않습니다. 대상을 직접 확인한 뒤 관리자 권한 PowerShell에서 수동으로 실행하세요.",
    }
