"""네트워크/호스트 라이브 취약점 스캐너 — 실제 TCP connect 스캔 + 배너 그랩 후,
배너에서 얻은 서비스/버전 문자열로 App 15의 NVD 연동을 통해 알려진 CVE를 찾는다.

⚠️ 안전 설계: 이 도구는 사설 IP 대역(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)과
로컬호스트만 스캔을 허용한다 — 공인 IP는 소유권을 확인할 방법이 없어 원천 차단한다
(App 10 SSRF 챌린지에서 클라우드 메타데이터 IP를 방어적으로 차단한 것과 같은 이유).
승인 체크박스(authorized)도 서버 측에서 함께 강제한다. 포트 목록은 흔한 서비스
~24개로 제한하고(전체 포트 스윕 아님), 포트당 타임아웃도 짧게 잡아 실제 스캐너처럼
공격적으로 동작하지 않도록 한다.

블로킹 소켓 호출은 run_in_executor로 스레드에 위임한다 — 이 프로젝트에서 여러 번
반복된 "블로킹 호출을 async 라우트에서 그대로 기다리면 이벤트 루프가 막힌다" 교훈과 동일 패턴.
"""

import asyncio
import ipaddress
import re
import socket
import time
from services import cve_lookup_service

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
}

_BLOCKED_IPS = {"169.254.169.254"}  # 클라우드 메타데이터 등, private 대역이어도 방어적으로 차단
_MAX_CVE_LOOKUPS = 5


def _resolve(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _is_scannable(ip_str: str) -> bool:
    if ip_str in _BLOCKED_IPS:
        return False
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private or ip.is_loopback


_HTTP_PORTS = (80, 8080, 8443, 443)


def _tcp_scan(ip: str, ports: list[int]) -> list[dict]:
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        state = "closed"
        banner = None
        try:
            sock.connect((ip, port))
            state = "open"
            try:
                if port in _HTTP_PORTS:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n")
                elif port == 6379:
                    sock.sendall(b"INFO\r\n")  # 구버전 Redis 인라인 커맨드 — redis_version 포함된 응답 유도
                raw = sock.recv(1024)
                banner = _extract_banner(raw, port)
            except OSError:
                banner = None
        except OSError:
            state = "closed"
        finally:
            sock.close()
        if state == "open":
            results.append({"port": port, "service": COMMON_PORTS.get(port, "unknown"), "state": state, "banner": banner})
    return results


_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_banner(raw: bytes, port: int) -> str | None:
    """HTTP는 상태줄이 아니라 Server 헤더(없으면 <title>, 실제로 버전이 body에만 노출되는
    서버가 있음을 확인)에, Redis는 INFO 응답 중 redis_version 줄에 버전 정보가 있다 —
    무조건 첫 줄만 쓰면 정작 필요한 버전 정보를 놓친다(실제 구현 중 발견)."""
    if not raw:
        return None
    text = raw.decode(errors="ignore")
    lines = text.splitlines()
    if not lines:
        return None
    if port in _HTTP_PORTS:
        for line in lines:
            if line.lower().startswith("server:"):
                return line.strip()[:200]
        m = _TITLE_RE.search(text)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            if title:
                return title[:200]
        return lines[0].strip()[:200]
    if port == 6379:
        for line in lines:
            if line.startswith("redis_version:"):
                return line.strip()[:200]
        return lines[0].strip()[:200] if lines[0].strip() else None
    return lines[0].strip()[:200]


def _clean_banner(banner: str) -> str:
    cleaned = re.sub(r"[^\x20-\x7e]", " ", banner)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _search_query(port: int, service: str, banner: str) -> str:
    """NVD 키워드 검색은 CVE 설명에 등장하는 문구와 부분일치해야 걸린다 — 배너 원문을
    그대로 넣으면(예: 'redis_version:4.0.14') 실제 CVE 설명 문구('Redis 4.0.14')와
    형식이 달라 매칭이 전혀 안 되는 것을 실제 테스트로 확인했다. 알고 있는 서비스는
    'Redis 4.0.14'처럼 자연스러운 형태로 재구성하고, 그 외에는 구분자만 공백으로
    정규화한다(예: 'Apache Tomcat/8.5.19' -> 'Apache Tomcat 8.5.19')."""
    if port == 6379 and banner.startswith("redis_version:"):
        return f"Redis {banner.split(':', 1)[1].strip()}"
    cleaned = _clean_banner(banner)
    return re.sub(r"[/:_]+", " ", cleaned).strip()


async def scan_target(target: str, authorized: bool) -> dict:
    if not authorized:
        return {"error": "not_authorized", "message": "authorized=true로 이 대상에 대한 소유권/테스트 권한을 확인해야 스캔이 실행됩니다."}

    ip = _resolve(target)
    if ip is None:
        return {"error": "resolve_failed", "message": f"'{target}'을(를) 확인(resolve)할 수 없습니다."}
    if not _is_scannable(ip):
        return {
            "error": "public_target_blocked",
            "message": f"공인 IP({ip})는 스캔할 수 없습니다. 이 도구는 사설망(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)과 로컬호스트만 지원합니다. 외부 대상은 명시적 승인 하에 nmap 등 전용 도구를 직접 사용하세요.",
        }

    loop = asyncio.get_event_loop()
    start = time.monotonic()
    open_ports = await loop.run_in_executor(None, _tcp_scan, ip, list(COMMON_PORTS.keys()))
    duration_ms = int((time.monotonic() - start) * 1000)

    delay = 0.7 if cve_lookup_service.HAS_API_KEY else 6.5
    lookups_done = 0
    for r in open_ports:
        r["matched_cves"] = []
        r["note"] = None
        if not r.get("banner"):
            r["note"] = "배너를 얻지 못해 CVE 검색을 건너뛰었습니다."
            continue
        if lookups_done >= _MAX_CVE_LOOKUPS:
            r["note"] = "CVE 조회 한도(5개 포트)를 넘어 건너뛰었습니다."
            continue
        query = _search_query(r["port"], r["service"], r["banner"])
        if len(query) < 3:
            r["note"] = "배너가 너무 짧아 CVE 검색을 건너뛰었습니다."
            continue
        res = await cve_lookup_service.search_cves(query)
        if "error" in res:
            r["note"] = res.get("message")
        else:
            raw = res.get("results", [])
            service_lower = r["service"].lower()
            filtered = [c for c in raw if service_lower in (c.get("description") or "").lower()]
            r["matched_cves"] = filtered
            if raw and not filtered:
                r["note"] = f"NVD 키워드 검색 결과가 있었지만 설명에 '{r['service']}'가 포함되지 않아 무관한 매칭으로 판단해 제외했습니다."
        lookups_done += 1
        if lookups_done < _MAX_CVE_LOOKUPS:
            await asyncio.sleep(delay)

    return {
        "target": target,
        "resolved_ip": ip,
        "ports_scanned": len(COMMON_PORTS),
        "open_ports": open_ports,
        "duration_ms": duration_ms,
        "highest_severity": _highest_severity(open_ports),
    }


def _highest_severity(open_ports: list[dict]) -> str | None:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = None
    for r in open_ports:
        for cve in r.get("matched_cves", []):
            sev = (cve.get("cvss") or {}).get("base_severity")
            if sev and (best is None or order.get(sev, 0) > order.get(best, 0)):
                best = sev
    return best


def generate_markdown_report(entry: dict) -> str:
    lines = [
        "# 네트워크 라이브 취약점 스캔 리포트",
        "",
        f"**대상:** {entry.get('target')} ({entry.get('resolved_ip')})  ",
        f"**스캔한 포트 수:** {entry.get('ports_scanned', 0)} (열린 포트 {len(entry.get('open_ports', []))}개)  ",
        f"**소요 시간:** {entry.get('duration_ms', 0)}ms  ",
        "",
        "> 사설망/로컬호스트 대상 TCP connect 스캔 + 배너 기반 NVD 키워드 검색 결과입니다. 정밀 검증은 nmap -sV 등 전용 도구를 권장합니다.",
        "",
        "---",
        "",
    ]
    for r in entry.get("open_ports", []):
        lines.append(f"## {r['port']}/tcp — {r['service']}")
        lines.append("")
        if r.get("banner"):
            lines.append(f"배너: `{r['banner']}`")
            lines.append("")
        if r.get("note"):
            lines.append(f"> {r['note']}")
            lines.append("")
        for cve in r.get("matched_cves", []):
            cvss = cve.get("cvss") or {}
            lines.append(f"- **{cve.get('id')}** [{cvss.get('base_severity', 'N/A')} {cvss.get('base_score', '')}] {cve.get('description', '')[:150]}")
        lines.append("")
    return "\n".join(lines)
