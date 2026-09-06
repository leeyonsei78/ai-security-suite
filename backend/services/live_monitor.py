import random
from datetime import datetime, timezone

_USERS = ["jsmith", "admin", "guest", "svc_backup", "mkim", "root"]
_INTERNAL_IPS = [f"10.0.0.{n}" for n in (12, 23, 41, 54, 77, 88)]
_EXTERNAL_IPS = [f"203.0.113.{n}" for n in (10, 42, 77)] + ["45.33.32.156", "198.51.100.23", "185.220.101.7"]

# ⚠️ 실제 로그 소스가 없는 데모 환경 — 아래 세 "가상 시스템 유형" 모두 진짜 서버를 관찰하는
# 것이 아니라, 서버가 그때그때 텍스트를 만들어내는 시뮬레이션이다. 프로필을 바꾸면 실제로
# 다른 대상을 감시하게 되는 게 아니라, "생성되는 합성 로그의 성격(어떤 시스템의 로그처럼
# 보이는 텍스트인지)"만 바뀐다 — 이 앱이 사용자에게 "실시간 탭은 실제 시스템을 모니터링하지
# 않는다"는 점을 계속 고지하는 것과 같은 맥락. 실제 시스템(이 PC 또는 원격 PC)을 진짜로
# 모니터링하려면 App 23(실시간 공격 모니터링 & 대응)을 사용해야 한다.
PROFILES = {
    "generic": {
        "label": "일반 서버 (SSH·웹·애플리케이션 혼합, 기본값)",
        "benign": [
            "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
            'nginx: {ip} - - "GET /api/health HTTP/1.1" 200 12',
            'nginx: {ip} - - "GET /dashboard HTTP/1.1" 200 4521',
            "systemd: Started Session {n} of user {user}.",
            "app: user={user} action=login result=success ip={ip}",
            "cron[{pid}]: (root) CMD (/usr/local/bin/backup.sh)",
        ],
        "suspicious": [
            ("sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2", "brute_force"),
            ("sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2", "brute_force"),
            ('nginx: {ip} - - "GET /wp-login.php HTTP/1.1" 404 162', "scan"),
            ('nginx: {ip} - - "POST /api/login HTTP/1.1" 200 55 payload="\' OR 1=1--"', "sqli"),
            ('nginx: {ip} - - "GET /.env HTTP/1.1" 404 162', "recon"),
            ("kernel: nmap SYN scan detected from {ip}, 342 ports in 8s", "portscan"),
            ('app: user={user} action=sudo command="cat /etc/shadow" result=denied ip={ip}', "privesc"),
            ("app: outbound_transfer bytes=4823001233 dest={ip} duration=90s", "exfil"),
        ],
    },
    "web_server": {
        "label": "웹 서버 (nginx 접근 로그 중심)",
        "benign": [
            'nginx: {ip} - - "GET / HTTP/1.1" 200 3021',
            'nginx: {ip} - - "GET /products?id={n} HTTP/1.1" 200 5210',
            'nginx: {ip} - - "GET /static/app.js HTTP/1.1" 200 18422',
            'nginx: {ip} - - "POST /api/cart HTTP/1.1" 200 88',
            'nginx: {ip} - - "GET /api/health HTTP/1.1" 200 12',
            'nginx: {ip} - - "GET /favicon.ico HTTP/1.1" 200 198',
        ],
        "suspicious": [
            ('nginx: {ip} - - "GET /wp-login.php HTTP/1.1" 404 162', "scan"),
            ('nginx: {ip} - - "POST /api/login HTTP/1.1" 200 55 payload="\' OR 1=1--"', "sqli"),
            ('nginx: {ip} - - "GET /.env HTTP/1.1" 404 162', "recon"),
            ('nginx: {ip} - - "GET /../../../../etc/passwd HTTP/1.1" 400 88', "path_traversal"),
            ('nginx: {ip} - - "GET /admin/config.php HTTP/1.1" 404 162', "scan"),
            ("kernel: nmap SYN scan detected from {ip}, 342 ports in 8s", "portscan"),
        ],
    },
    "internal_network": {
        "label": "사내망 업무 시스템 (파일서버·VPN·AD)",
        "benign": [
            "app: user={user} action=vpn_connect result=success ip={ip}",
            "app: user={user} action=file_access path=/shared/reports/{n}.docx result=success",
            "adauth: user={user} action=logon workstation=WS-{n} result=success",
            "systemd: Started Session {n} of user {user}.",
            "app: user={user} action=print_job printer=HQ-PR-{n} result=success",
        ],
        "suspicious": [
            ('app: user={user} action=file_access path=/shared/hr/salaries.xlsx result=denied ip={ip}', "unauthorized_access"),
            ("adauth: user={user} action=logon workstation=WS-{n} result=failure reason=bad_password", "brute_force"),
            ('app: user={user} action=sudo command="net user hacker /add" result=denied ip={ip}', "privesc"),
            ("app: lateral_movement src={ip} dst=10.0.0.{n} protocol=smb result=success", "lateral_movement"),
            ("app: outbound_transfer bytes=4823001233 dest={ip} duration=90s", "exfil"),
        ],
    },
}

DEFAULT_PROFILE = "generic"


def list_profiles() -> list[dict]:
    return [{"id": pid, "label": p["label"]} for pid, p in PROFILES.items()]


def _pick_ip(external=False):
    return random.choice(_EXTERNAL_IPS if external else _INTERNAL_IPS)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fill(template: str, external_ip: bool = False) -> str:
    return template.format(
        pid=random.randint(1000, 9999),
        user=random.choice(_USERS),
        ip=_pick_ip(external=external_ip),
        port=random.randint(30000, 60000),
        n=random.randint(1, 999),
    )


def generate_batch(injected_lines: list[str] | None = None, size: int = 6, profile: str = DEFAULT_PROFILE) -> str:
    """실제 라이브 로그 소스가 없는 데모 환경을 위한 합성 로그 배치 생성기.
    대부분은 정상 트래픽이고, ~35% 확률로 1~2줄의 의심스러운 이벤트를 섞어 넣는다.
    `profile`로 어떤 가상 시스템 유형의 로그처럼 보이게 할지 고를 수 있다(PROFILES 참고)."""
    pool = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])
    lines = [f"{_now()} {_fill(random.choice(pool['benign']))}" for _ in range(size)]

    if random.random() < 0.35:
        for _ in range(random.randint(1, 2)):
            template, _category = random.choice(pool["suspicious"])
            lines.append(f"{_now()} {_fill(template, external_ip=True)}")

    for injected in (injected_lines or []):
        lines.append(f"{_now()} [injected] {injected}")

    random.shuffle(lines)
    return "\n".join(lines)
