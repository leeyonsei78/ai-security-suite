import random
from datetime import datetime, timezone

_USERS = ["jsmith", "admin", "guest", "svc_backup", "mkim", "root"]
_INTERNAL_IPS = [f"10.0.0.{n}" for n in (12, 23, 41, 54, 77, 88)]
_EXTERNAL_IPS = [f"203.0.113.{n}" for n in (10, 42, 77)] + ["45.33.32.156", "198.51.100.23", "185.220.101.7"]

_BENIGN_TEMPLATES = [
    "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
    'nginx: {ip} - - "GET /api/health HTTP/1.1" 200 12',
    'nginx: {ip} - - "GET /dashboard HTTP/1.1" 200 4521',
    "systemd: Started Session {n} of user {user}.",
    "app: user={user} action=login result=success ip={ip}",
    "cron[{pid}]: (root) CMD (/usr/local/bin/backup.sh)",
]

# (template, category) — category is only used for readability while editing, not sent to the client
_SUSPICIOUS_TEMPLATES = [
    ("sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2", "brute_force"),
    ("sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2", "brute_force"),
    ('nginx: {ip} - - "GET /wp-login.php HTTP/1.1" 404 162', "scan"),
    ('nginx: {ip} - - "POST /api/login HTTP/1.1" 200 55 payload="\' OR 1=1--"', "sqli"),
    ('nginx: {ip} - - "GET /.env HTTP/1.1" 404 162', "recon"),
    ("kernel: nmap SYN scan detected from {ip}, 342 ports in 8s", "portscan"),
    ('app: user={user} action=sudo command="cat /etc/shadow" result=denied ip={ip}', "privesc"),
    ("app: outbound_transfer bytes=4823001233 dest={ip} duration=90s", "exfil"),
]


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


def generate_batch(injected_lines: list[str] | None = None, size: int = 6) -> str:
    """실제 라이브 로그 소스가 없는 데모 환경을 위한 합성 로그 배치 생성기.
    대부분은 정상 트래픽이고, ~35% 확률로 1~2줄의 의심스러운 이벤트를 섞어 넣는다."""
    lines = [f"{_now()} {_fill(random.choice(_BENIGN_TEMPLATES))}" for _ in range(size)]

    if random.random() < 0.35:
        for _ in range(random.randint(1, 2)):
            template, _category = random.choice(_SUSPICIOUS_TEMPLATES)
            lines.append(f"{_now()} {_fill(template, external_ip=True)}")

    for injected in (injected_lines or []):
        lines.append(f"{_now()} [injected] {injected}")

    random.shuffle(lines)
    return "\n".join(lines)
