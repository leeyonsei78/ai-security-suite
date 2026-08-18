import os
import ssl
import json
import socket
import datetime
from dotenv import load_dotenv
from services.mock_webscan import generate_mock_webscan

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

# Security headers to check
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config",
    "/admin", "/admin/", "/administrator",
    "/backup", "/backup.zip", "/backup.sql",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/web.config",
    "/phpinfo.php", "/info.php",
    "/wp-admin/", "/wp-login.php",
    "/config.php", "/configuration.php",
    "/server-status", "/server-info",
]

CLAUDE_PROMPT = """You are a web security expert. Analyze the following web security scan results and generate findings in Korean.

Respond ONLY with valid JSON:
{
  "risk_score": 0-100,
  "summary": "한 문단 종합 평가",
  "findings": [
    {
      "id": "WEB-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "보안 헤더|SSL/TLS|경로 노출|서버 정보|기타",
      "title": "취약점 제목",
      "description": "왜 위험한지 구체적 설명",
      "recommendation": "구체적인 조치 방법"
    }
  ],
  "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
}"""


def _get_ssl_info(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            expire_str = cert.get("notAfter", "")
            expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z") if expire_str else None
            days_left = (expire_dt - datetime.datetime.utcnow()).days if expire_dt else None
            issuer = dict(x[0] for x in cert.get("issuer", []))
            return {
                "valid": True,
                "issuer": issuer.get("organizationName", "Unknown"),
                "expires_in_days": days_left,
                "protocol": s.version(),
            }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "issuer": "Invalid/Self-signed", "expires_in_days": None, "protocol": None}
    except Exception:
        return {"valid": None, "issuer": None, "expires_in_days": None, "protocol": None}


async def _do_scan(url: str) -> dict:
    import httpx
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    base = f"{parsed.scheme}://{parsed.netloc}"

    headers_found = {}
    server_info = {"server": None, "x_powered_by": None}
    exposed_paths = []
    status_code = None

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                  timeout=10,
                                  headers={"User-Agent": "Mozilla/5.0 SecurityScanner/1.0"}) as client:
        # Main request
        try:
            resp = await client.get(url)
            status_code = resp.status_code
            h = {k.lower(): v for k, v in resp.headers.items()}
            headers_found = {hdr: h.get(hdr) for hdr in SECURITY_HEADERS}
            server_info["server"] = h.get("server")
            server_info["x_powered_by"] = h.get("x-powered-by")
            cookie_header = h.get("set-cookie", "")
        except Exception as e:
            return {"error": str(e)}

        # Probe sensitive paths (limit to avoid abuse)
        for path in SENSITIVE_PATHS[:12]:
            try:
                r = await client.get(base + path, timeout=4)
                if r.status_code in (200, 301, 302, 403):
                    exposed_paths.append({"path": path, "status": r.status_code})
            except Exception:
                pass

    # SSL
    ssl_info = {}
    if parsed.scheme == "https":
        ssl_info = _get_ssl_info(hostname)

    return {
        "status_code": status_code,
        "headers_found": headers_found,
        "server_info": server_info,
        "exposed_paths": exposed_paths,
        "ssl_info": ssl_info,
    }


def _build_findings_from_raw(raw: dict) -> list[dict]:
    findings = []
    idx = 1

    def add(sev, cat, title, desc, rec):
        nonlocal idx
        findings.append({
            "id": f"WEB-{idx:03d}", "severity": sev, "category": cat,
            "title": title, "description": desc, "recommendation": rec,
        })
        idx += 1

    hf = raw.get("headers_found", {})
    si = raw.get("server_info", {})
    ssl = raw.get("ssl_info", {})
    paths = raw.get("exposed_paths", [])

    # HSTS
    if not hf.get("strict-transport-security"):
        add("HIGH", "보안 헤더", "HSTS 헤더 누락",
            "HTTPS를 강제하지 않아 SSL 다운그레이드 공격에 취약합니다.",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains 추가")

    # CSP
    if not hf.get("content-security-policy"):
        add("HIGH", "보안 헤더", "Content-Security-Policy 누락",
            "CSP 헤더가 없어 XSS 및 데이터 인젝션 공격에 노출될 수 있습니다.",
            "Content-Security-Policy 헤더를 설정해 허용 리소스를 제한하세요.")

    # X-Frame-Options
    if not hf.get("x-frame-options"):
        add("MEDIUM", "보안 헤더", "X-Frame-Options 누락",
            "iframe에 포함 가능해 클릭재킹(Clickjacking) 공격에 취약합니다.",
            "X-Frame-Options: SAMEORIGIN 추가")

    # X-Content-Type-Options
    if not hf.get("x-content-type-options"):
        add("MEDIUM", "보안 헤더", "X-Content-Type-Options 누락",
            "MIME 타입 스니핑으로 인한 XSS 공격에 취약합니다.",
            "X-Content-Type-Options: nosniff 추가")

    # Referrer-Policy
    if not hf.get("referrer-policy"):
        add("LOW", "보안 헤더", "Referrer-Policy 미설정",
            "페이지 이동 시 내부 URL 정보가 외부로 유출될 수 있습니다.",
            "Referrer-Policy: strict-origin-when-cross-origin 추가")

    # Permissions-Policy
    if not hf.get("permissions-policy"):
        add("LOW", "보안 헤더", "Permissions-Policy 미설정",
            "카메라·마이크 등 브라우저 기능에 대한 접근 제한이 없습니다.",
            "Permissions-Policy 헤더로 불필요한 브라우저 기능을 비활성화하세요.")

    # Server info exposure
    if si.get("server") and any(c.isdigit() for c in si["server"]):
        add("MEDIUM", "서버 정보", f"서버 버전 정보 노출 ({si['server']})",
            "서버 소프트웨어 버전이 노출되어 알려진 취약점 공격에 악용될 수 있습니다.",
            "서버 버전 정보를 응답 헤더에서 제거하세요.")

    if si.get("x_powered_by"):
        add("MEDIUM", "서버 정보", f"X-Powered-By 헤더 노출 ({si['x_powered_by']})",
            "백엔드 기술 스택이 노출되어 타깃 공격에 활용될 수 있습니다.",
            "X-Powered-By 헤더를 응답에서 제거하세요.")

    # SSL
    if ssl.get("valid") is False:
        add("CRITICAL", "SSL/TLS", "SSL 인증서 오류 (자체 서명 또는 유효하지 않음)",
            "인증서를 신뢰할 수 없어 중간자(MITM) 공격에 취약합니다.",
            "공인 CA에서 발급한 유효한 SSL 인증서를 사용하세요.")
    elif ssl.get("expires_in_days") is not None and ssl["expires_in_days"] < 30:
        add("HIGH", "SSL/TLS", f"SSL 인증서 만료 임박 ({ssl['expires_in_days']}일 후 만료)",
            "인증서가 곧 만료됩니다. 갱신하지 않으면 브라우저에서 차단됩니다.",
            "즉시 SSL 인증서를 갱신하세요.")

    if ssl.get("protocol") in ("TLSv1", "TLSv1.1"):
        add("HIGH", "SSL/TLS", f"구형 TLS 버전 사용 ({ssl['protocol']})",
            "오래된 TLS 버전은 알려진 취약점이 있습니다.",
            "TLSv1.2 및 TLSv1.3만 허용하도록 서버를 설정하세요.")

    # Exposed paths
    critical_paths = ["/.env", "/.git/HEAD", "/.git/config", "/phpinfo.php",
                      "/backup.zip", "/backup.sql", "/config.php"]
    for ep in paths:
        path = ep["path"]
        status = ep["status"]
        if status == 200:
            sev = "CRITICAL" if path in critical_paths else "MEDIUM"
            add(sev, "경로 노출", f"{path} 외부 접근 가능 (HTTP {status})",
                f"{path} 파일이 외부에서 접근 가능합니다. 민감한 정보가 포함될 수 있습니다.",
                f"웹 서버 설정에서 {path} 접근을 차단하세요.")
        elif status == 403:
            add("LOW", "경로 노출", f"{path} 경로 존재 확인됨 (HTTP 403)",
                f"접근은 차단됐지만 경로가 존재함이 노출됩니다.",
                f"{path} 경로를 제거하거나 404를 반환하도록 설정하세요.")

    return findings


async def scan_url(url: str) -> dict:
    if IS_MOCK:
        return generate_mock_webscan(url)

    raw = await _do_scan(url)
    if "error" in raw:
        return {"url": url, "error": raw["error"], "risk_score": 0,
                "summary": "스캔 실패: " + raw["error"], "findings": [],
                "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}}

    findings = _build_findings_from_raw(raw)

    # Calculate risk score
    weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = min(100, sum(weights.get(f["severity"], 0) for f in findings))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    # Claude summary
    summary = f"총 {len(findings)}개의 보안 이슈가 발견됐습니다."
    if _api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=_api_key)
            scan_summary = {
                "url": url,
                "missing_headers": [h for h, v in raw["headers_found"].items() if not v],
                "server_info": raw["server_info"],
                "ssl_info": raw["ssl_info"],
                "exposed_paths": [e["path"] for e in raw["exposed_paths"] if e["status"] == 200],
                "finding_count": counts,
            }
            msg = client.messages.create(
                model="claude-sonnet-4-6", max_tokens=300,
                messages=[{"role": "user", "content":
                    f"웹 보안 스캔 결과를 한 문단(2~3문장)으로 요약해주세요:\n{json.dumps(scan_summary, ensure_ascii=False)}"}])
            summary = msg.content[0].text
        except Exception:
            pass

    return {
        "url": url,
        "risk_score": score,
        "summary": summary,
        "ssl": raw.get("ssl_info", {}),
        "server_info": raw.get("server_info", {}),
        "exposed_paths": [e["path"] for e in raw.get("exposed_paths", []) if e["status"] == 200],
        "findings": findings,
        "counts": counts,
    }
