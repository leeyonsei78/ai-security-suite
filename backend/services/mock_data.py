import random
import time

_MOCK_EVENTS_POOL = [
    {
        "id": "EVT-001",
        "timestamp": "2026-08-04T10:23:11Z",
        "severity": "CRITICAL",
        "category": "Brute Force",
        "description": "SSH brute-force detected: 847 failed login attempts from 192.168.1.105 in 60 seconds.",
        "source_ip": "192.168.1.105",
        "affected_resource": "ssh:22 (server-prod-01)",
        "remediation": "Block IP immediately via firewall. Enable fail2ban. Rotate SSH keys.",
    },
    {
        "id": "EVT-002",
        "timestamp": "2026-08-04T10:24:05Z",
        "severity": "CRITICAL",
        "category": "SQL Injection",
        "description": "SQL injection payload detected in POST /api/login: ' OR 1=1 -- from 203.0.113.42.",
        "source_ip": "203.0.113.42",
        "affected_resource": "web-app /api/login",
        "remediation": "Block IP. Review and patch input validation. Use parameterized queries.",
    },
    {
        "id": "EVT-003",
        "timestamp": "2026-08-04T10:31:44Z",
        "severity": "HIGH",
        "category": "Privilege Escalation",
        "description": "User 'guest' executed sudo commands without prior authorization. Unusual root access pattern detected.",
        "source_ip": None,
        "affected_resource": "Linux host: web-server-02",
        "remediation": "Revoke sudo privileges for guest account. Audit sudoers file. Investigate lateral movement.",
    },
    {
        "id": "EVT-004",
        "timestamp": "2026-08-04T10:35:02Z",
        "severity": "HIGH",
        "category": "Data Exfiltration",
        "description": "Abnormal outbound traffic spike: 4.7 GB transferred to 198.51.100.0/24 in 5 minutes.",
        "source_ip": "10.0.0.54",
        "affected_resource": "Network egress (DMZ segment)",
        "remediation": "Block outbound connection. Isolate affected host. Capture and analyze traffic dump.",
    },
    {
        "id": "EVT-005",
        "timestamp": "2026-08-04T10:38:19Z",
        "severity": "MEDIUM",
        "category": "Malware",
        "description": "Suspicious process 'svchost32.exe' spawned from user temp directory. Hash matches known ransomware dropper.",
        "source_ip": None,
        "affected_resource": "Workstation: WS-014 (user: jsmith)",
        "remediation": "Quarantine host immediately. Run full AV scan. Preserve disk image for forensics.",
    },
    {
        "id": "EVT-006",
        "timestamp": "2026-08-04T10:44:55Z",
        "severity": "MEDIUM",
        "category": "Port Scan",
        "description": "Nmap-style port scan detected from 45.33.32.156 targeting 1024 ports in 30 seconds.",
        "source_ip": "45.33.32.156",
        "affected_resource": "Public-facing subnet 10.0.1.0/24",
        "remediation": "Add IP to blocklist. Review exposed services. Enable IDS signature rules for scanners.",
    },
    {
        "id": "EVT-007",
        "timestamp": "2026-08-04T10:51:30Z",
        "severity": "LOW",
        "category": "Policy Violation",
        "description": "User accessed restricted /admin panel outside business hours (02:14 KST). Credentials valid.",
        "source_ip": "172.16.0.23",
        "affected_resource": "Admin portal (admin.internal)",
        "remediation": "Verify with user. Enforce time-based access policies. Enable MFA for admin panel.",
    },
    {
        "id": "EVT-008",
        "timestamp": "2026-08-04T10:58:07Z",
        "severity": "INFO",
        "category": "Authentication",
        "description": "Successful login from new device/location for admin@example.com (Seoul, KR).",
        "source_ip": "58.234.100.12",
        "affected_resource": "SSO portal",
        "remediation": "Monitor for further unusual activity. Consider device trust policy.",
    },
]

_SUMMARIES = [
    "Multiple high-severity threats detected. Immediate incident response recommended.",
    "Suspicious network activity and unauthorized access attempts identified across several systems.",
    "Critical brute-force and injection attacks in progress. Automated defenses may be insufficient.",
    "Several policy violations and reconnaissance activities detected in the past hour.",
]


def generate_mock_analysis(content: str) -> dict:
    # Pick a deterministic-ish subset based on content length
    n = min(len(_MOCK_EVENTS_POOL), max(2, len(content) % 6 + 2))
    events = random.sample(_MOCK_EVENTS_POOL, n)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for ev in events:
        counts[ev["severity"]] += 1

    worst = next(
        (s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if counts[s] > 0),
        "INFO",
    )

    return {
        "summary": random.choice(_SUMMARIES),
        "threat_level": worst,
        "events": events,
        "statistics": {
            "total_events": len(events),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
        },
        "_mock": True,
    }
