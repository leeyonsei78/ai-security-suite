"""취약점 분석 전 정보 수집(Reconnaissance) 가이드 콘텐츠.

취약점을 "분석"하려면 먼저 분석할 대상 정보(포트, DNS, HTTP 헤더 등)를
수집해야 한다. RECON_GUIDE는 무엇을·어떻게 수집하는지 카테고리별 가이드이고,
RECON_SCRIPT는 실제로 실행해 수집할 수 있는 Python 표준 라이브러리 기반
스크립트다 (외부 패키지 설치 불필요). --format vuln-scanner 옵션으로 출력하면
이 앱의 /vuln '포트 스캔' 입력창에 바로 붙여넣기 좋은 형식이 된다.
"""

RECON_GUIDE = {
    "title": "분석하기 전에: 정보 수집(Recon)부터 시작하세요",
    "intro": (
        "취약점 스캐너에 붙여넣을 '포트 스캔 결과'나 '설정 파일'은 저절로 생기지 않습니다. "
        "먼저 대상에 대한 정보를 수집(Reconnaissance)해야 합니다. 아래는 무엇을, 어떤 도구로 "
        "수집하는지에 대한 정리이고, 하단에서 직접 실행 가능한 recon.py 스크립트도 받을 수 있습니다."
    ),
    "legal_note": (
        "능동적 스캔(포트 스캔, 디렉토리 브루트포스, DNS 존 트랜스퍼 시도 등)은 반드시 본인 소유이거나 "
        "서면으로 명시적 승인을 받은 대상에서만 수행하세요. 무단 스캔은 국가/지역에 따라 형사처벌 "
        "대상이 될 수 있습니다. 수동적 정찰(WHOIS, 공개 DNS 조회)도 대상에 과도한 부하를 주지 않는 "
        "선에서 진행하세요."
    ),
    "categories": [
        {
            "name": "네트워크 / 포트",
            "collect": ["열려있는 TCP/UDP 포트", "포트별 서비스와 버전", "운영체제 추정"],
            "how": [
                {"tool": "nmap", "command": "nmap -sV -sC -p- <target>", "note": "전체 포트 스캔 + 서비스/버전 탐지 + 기본 스크립트. 오래 걸리면 -p- 대신 --top-ports 1000"},
                {"tool": "recon.py (아래 다운로드)", "command": "python recon.py <target> --format vuln-scanner", "note": "nmap 없이도 기본적인 포트 상태를 빠르게 확인, 결과를 바로 이 앱에 붙여넣기 좋은 형식으로 출력"},
            ],
        },
        {
            "name": "DNS",
            "collect": ["A/AAAA/MX/NS/TXT 레코드", "서브도메인 목록", "존 트랜스퍼 가능 여부"],
            "how": [
                {"tool": "dig", "command": "dig ANY <domain> +noall +answer", "note": "레코드 전체 조회"},
                {"tool": "subfinder", "command": "subfinder -d <domain>", "note": "여러 데이터 소스를 활용한 서브도메인 열거"},
                {"tool": "dig (zone transfer 시도)", "command": "dig axfr @<nameserver> <domain>", "note": "성공하면 심각한 설정 실수 — 대부분 실패하는 게 정상"},
            ],
        },
        {
            "name": "웹 애플리케이션",
            "collect": ["서버/프레임워크(기술 스택)", "HTTP 보안 헤더", "노출된 민감 경로(.git, .env, /admin)", "robots.txt / sitemap.xml"],
            "how": [
                {"tool": "curl", "command": "curl -I <url>", "note": "응답 헤더로 서버 종류·버전 확인"},
                {"tool": "whatweb", "command": "whatweb <url>", "note": "기술 스택 자동 탐지"},
                {"tool": "gobuster", "command": "gobuster dir -u <url> -w wordlist.txt -x php,bak,env", "note": "숨겨진 디렉토리/파일 탐색"},
                {"tool": "이 앱의 웹 스캐너 (App 6, /webscan)", "command": "URL만 입력", "note": "보안 헤더 7종·민감 경로 12개를 자동으로 점검"},
            ],
        },
        {
            "name": "WHOIS / 조직 정보",
            "collect": ["도메인 등록자", "네임서버", "등록/만료일"],
            "how": [
                {"tool": "whois", "command": "whois <domain>", "note": "Windows에는 기본 내장되어 있지 않음 — WSL/Docker 환경에서 실행 권장"},
            ],
        },
        {
            "name": "SSL/TLS",
            "collect": ["인증서 유효기간", "SAN(포함된 서브도메인 목록)", "지원 프로토콜 버전"],
            "how": [
                {"tool": "openssl", "command": "openssl s_client -connect <host>:443 -servername <host> </dev/null", "note": "인증서 상세 정보 확인"},
                {"tool": "testssl.sh", "command": "testssl.sh <host>", "note": "지원 프로토콜/암호 스위트까지 종합 점검"},
            ],
        },
        {
            "name": "OSINT / 사람",
            "collect": ["임직원 이메일 패턴", "공개 문서의 메타데이터(작성자, 소프트웨어)", "유출된 자격증명 여부"],
            "how": [
                {"tool": "theHarvester", "command": "theHarvester -d <domain> -b all", "note": "공개된 이메일·서브도메인 수집"},
                {"tool": "exiftool", "command": "exiftool document.pdf", "note": "공개된 문서 파일의 작성자/내부 경로 등 메타데이터 확인"},
            ],
        },
    ],
    "workflow": [
        "수동적 정찰(Passive) 먼저: WHOIS, DNS, 공개 검색 — 대상 시스템에 직접 요청을 보내지 않아 흔적이 남지 않습니다.",
        "능동적 정찰(Active): 포트 스캔, 배너 그래빙 — 대상 시스템에 직접 연결하므로 반드시 승인된 대상에서만 진행합니다.",
        "웹 서비스가 있다면 기술 스택과 민감 경로를 확인합니다 (이 앱의 웹 스캐너로도 가능).",
        "수집한 결과를 정리해 이 취약점 스캐너의 입력창(포트 스캔/설정 파일/코드/메모리 덤프)에 붙여넣어 분석합니다.",
    ],
    "script_filename": "recon.py",
    "input_type_sources": {
        "title": "이 스캐너의 4가지 입력 유형, 실제로 어떻게 얻나요?",
        "intro": "위 카테고리는 '포트 스캔' 위주였습니다. 나머지 입력 유형(설정 파일/코드/메모리 덤프)은 수집 방법이 완전히 다르므로 따로 정리했습니다.",
        "items": [
            {
                "input_type": "portscan",
                "label": "포트 스캔 결과",
                "how": [
                    "nmap -sV -sC -p- <target> 실행 결과를 그대로 복사합니다.",
                    "또는 위 recon.py를 --format vuln-scanner 옵션으로 실행한 출력을 그대로 붙여넣습니다.",
                ],
            },
            {
                "input_type": "config",
                "label": "설정 파일",
                "how": [
                    "본인 서버라면 SSH로 접속해 직접 확인: cat /etc/nginx/nginx.conf, cat /etc/ssh/sshd_config",
                    "클라우드 리소스라면 콘솔/CLI의 설정 export 기능 사용: aws s3api get-bucket-policy --bucket <name>, gcloud/az 콘솔의 구성 내보내기",
                    "외부에서 원격으로 설정 실수를 간접 확인하려면 위 '웹 애플리케이션' 항목(curl, whatweb, gobuster)을 참고하세요 — 실제 설정 파일을 읽는 것이 아니라 그 결과로 드러나는 증상을 확인하는 방식입니다.",
                ],
            },
            {
                "input_type": "code",
                "label": "코드 스니펫",
                "how": [
                    "본인 리포지토리라면 리뷰하고 싶은 함수/파일을 그대로 복사합니다.",
                    "노출된 .git 디렉토리가 있다면 (승인된 대상에서만): git-dumper <url>/.git ./dump 로 소스 전체를 복구할 수 있습니다.",
                    "프로덕션 JS 번들은 브라우저 개발자도구 → Sources 탭에서 .map 소스맵 파일이 노출되어 있는지 확인하면 원본에 가까운 코드를 복원할 수 있습니다.",
                ],
            },
            {
                "input_type": "memory",
                "label": "메모리 덤프",
                "how": [
                    "Windows: Magnet RAM Capture, FTK Imager, winpmem 등으로 실행 중인 PC의 메모리를 .mem/.raw 파일로 추출합니다 (관리자 권한 필요).",
                    "Linux: LiME(Linux Memory Extractor) 커널 모듈로 메모리 덤프를 추출합니다.",
                    "가상머신 환경이라면 스냅샷 시 생성되는 파일을 활용할 수 있습니다: VMware의 .vmem, VirtualBox의 .sav",
                    "추출한 덤프는 Volatility 3로 분석합니다: vol -f dump.mem windows.pstree / windows.netscan / windows.cmdline (자세한 절차는 Pwn/Reverse 실습실과 '메모리 덤프 분석' 시나리오 참고)",
                ],
            },
        ],
        "note": "메모리 덤프 추출과 .git 복구는 대상 시스템에 직접 접근하는 행위이므로, 본인 소유이거나 서면 승인을 받은 시스템에서만 수행하세요.",
    },
}

RECON_SCRIPT = '''#!/usr/bin/env python3
"""
recon.py — 취약점 분석 전 정보 수집(Reconnaissance) 스크립트

이 스크립트는 본인이 소유하거나 서면으로 명시적 승인을 받은 대상에 대해서만
사용하세요. 승인되지 않은 시스템에 대한 포트 스캔·디렉토리 탐색 등은
국가/지역에 따라 형사처벌 대상이 될 수 있습니다.

Python 표준 라이브러리만으로 동작하며(추가 설치 불필요), whois/nmap 등
외부 도구가 설치되어 있으면 더 상세한 정보를 함께 보여줍니다.

사용법:
    python recon.py example.com
    python recon.py example.com --ports common
    python recon.py 203.0.113.10 --ports 1-1000
    python recon.py example.com --format vuln-scanner    # AI Security Suite /vuln 입력창에 바로 붙여넣기 좋은 형식
    python recon.py example.com --skip-confirm           # 승인 확인 프롬프트 생략 (본인 책임 하에 자동화 시 사용)
"""

import argparse
import concurrent.futures
import json
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# Windows 콘솔의 기본 코드페이지(cp949 등)가 이모지/특수문자를 못 그려 죽는 것을 방지
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

BANNER = """\\
==============================================================
 recon.py - AI Security Suite 정보 수집 스크립트
 본인 소유이거나 서면으로 승인받은 대상에만 사용하세요.
==============================================================\\
"""


def confirm_authorization(target: str) -> None:
    print(BANNER)
    print(f"대상: {target}\\n")
    resp = input("이 대상에 대해 테스트할 권한이 있습니까? (y/N): ").strip().lower()
    if resp != "y":
        print("승인이 확인되지 않아 종료합니다.")
        sys.exit(1)


def parse_ports(spec: str) -> list[int]:
    if spec == "common":
        return COMMON_PORTS
    if "-" in spec:
        start, end = spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(p) for p in spec.split(",")]


def resolve_host(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def dns_records(domain: str) -> dict:
    records = {}
    try:
        records["A"] = sorted({info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        records["A"] = []
    try:
        records["AAAA"] = sorted({info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except socket.gaierror:
        records["AAAA"] = []

    for tool, args in (("dig", ["dig", "+short"]), ("nslookup", ["nslookup", "-type="])):
        if shutil.which(tool):
            records["_dns_tool"] = tool
            break
    else:
        records["_dns_tool"] = None

    if records["_dns_tool"] == "dig":
        for rtype in ("MX", "NS", "TXT", "CNAME"):
            try:
                out = subprocess.run(
                    ["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=5
                ).stdout.strip()
                records[rtype] = [l for l in out.splitlines() if l]
            except Exception:
                records[rtype] = []
    return records


def whois_lookup(domain: str) -> str:
    if not shutil.which("whois"):
        return "(whois 명령을 찾을 수 없습니다 — Linux/WSL: sudo apt install whois)"
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        return out.stdout.strip()[:3000]
    except Exception as e:
        return f"(whois 조회 실패: {e})"


def scan_ports(host: str, ports: list[int], timeout: float = 0.75, max_workers: int = 100) -> list[tuple[int, str]]:
    open_ports = []

    def check(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "?"
                    return port, service
        except OSError:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for result in ex.map(check, ports):
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def http_probe(host: str, use_https: bool, timeout: float = 5) -> dict:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    req = urllib.request.Request(url, headers={"User-Agent": "recon.py (authorized-security-review)"})
    try:
        ctx = ssl.create_default_context() if use_https else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"url": url, "status": resp.status, "headers": dict(resp.headers)}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "headers": dict(e.headers)}
    except Exception as e:
        return {"url": url, "status": None, "error": str(e)}


def fetch_text(url: str, timeout: float = 5, max_bytes: int = 2000) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon.py"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes).decode(errors="replace")
    except Exception:
        return None


def ssl_cert_info(host: str, port: int = 443, timeout: float = 5) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return cert or {}
    except Exception as e:
        return {"error": str(e)}


def build_report(target: str, ports_spec: str) -> dict:
    ip = resolve_host(target)
    report = {
        "target": target,
        "resolved_ip": ip,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dns": dns_records(target),
        "whois": whois_lookup(target),
    }

    scan_host = ip or target
    ports = parse_ports(ports_spec)
    print(f"[*] {len(ports)}개 포트 스캔 중... (대상: {scan_host})", file=sys.stderr)
    report["open_ports"] = scan_ports(scan_host, ports)

    http_result = http_probe(target, use_https=False)
    https_result = http_probe(target, use_https=True)
    report["http"] = http_result
    report["https"] = https_result

    headers = (https_result.get("headers") or http_result.get("headers") or {})
    report["security_headers"] = {h: headers.get(h, "없음") for h in SECURITY_HEADERS}

    report["robots_txt"] = fetch_text(f"http://{target}/robots.txt")
    report["ssl_cert"] = ssl_cert_info(target) if https_result.get("status") is not None else None

    return report


def format_text(report: dict) -> str:
    lines = [
        f"=== recon.py 결과: {report['target']} ({report['resolved_ip'] or 'DNS 확인 불가'}) ===",
        f"생성 시각: {report['generated_at']}",
        "",
        "-- DNS --",
    ]
    for k, v in report["dns"].items():
        if k.startswith("_"):
            continue
        lines.append(f"{k}: {', '.join(v) if v else '(없음/조회 불가)'}")

    lines += ["", "-- WHOIS --", report["whois"], "", "-- 열린 포트 --"]
    if report["open_ports"]:
        for port, service in report["open_ports"]:
            lines.append(f"{port}/tcp\\topen\\t{service}")
    else:
        lines.append("(열린 포트가 발견되지 않았습니다)")

    lines += ["", "-- HTTP 응답 헤더 --"]
    for proto, result in (("http", report["http"]), ("https", report["https"])):
        if result.get("status") is not None:
            lines.append(f"[{proto}] {result['url']} -> {result['status']}")
            for k, v in result["headers"].items():
                lines.append(f"  {k}: {v}")
        else:
            lines.append(f"[{proto}] 연결 실패: {result.get('error')}")

    lines += ["", "-- 보안 헤더 점검 --"]
    for h, v in report["security_headers"].items():
        mark = "✅" if v != "없음" else "❌"
        lines.append(f"{mark} {h}: {v}")

    lines += ["", "-- robots.txt --", report["robots_txt"] or "(가져오지 못함)"]

    if report.get("ssl_cert"):
        lines += ["", "-- SSL 인증서 --", json.dumps(report["ssl_cert"], indent=2, ensure_ascii=False, default=str)]

    return "\\n".join(lines)


def format_vuln_scanner(report: dict) -> str:
    """AI Security Suite의 /vuln '포트 스캔' 입력창에 그대로 붙여넣기 좋은 nmap 스타일 출력."""
    lines = [
        f"Nmap-like recon report for {report['target']} ({report['resolved_ip'] or 'unresolved'})",
        f"Generated by recon.py at {report['generated_at']}",
        "",
        "PORT     STATE  SERVICE",
    ]
    for port, service in report["open_ports"]:
        lines.append(f"{port}/tcp".ljust(9) + "open".ljust(7) + service)
    if not report["open_ports"]:
        lines.append("(no open ports found in scanned range)")

    lines += ["", "HTTP security headers:"]
    for h, v in report["security_headers"].items():
        lines.append(f"{h}: {v}")

    return "\\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="취약점 분석 전 정보 수집(Recon) 스크립트")
    parser.add_argument("target", help="도메인 또는 IP 주소")
    parser.add_argument("--ports", default="common", help="'common' | '1-1000' | '22,80,443' (기본: common)")
    parser.add_argument("--format", choices=["text", "json", "vuln-scanner"], default="text")
    parser.add_argument("--skip-confirm", action="store_true", help="승인 확인 프롬프트 생략 (본인 책임 하에 자동화 시 사용)")
    args = parser.parse_args()

    if not args.skip_confirm:
        confirm_authorization(args.target)

    report = build_report(args.target, args.ports)

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    elif args.format == "vuln-scanner":
        print(format_vuln_scanner(report))
    else:
        print(format_text(report))


if __name__ == "__main__":
    main()
'''
