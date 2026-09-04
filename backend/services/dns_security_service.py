"""도메인의 이메일/DNS 보안 설정(SPF/DMARC/DKIM/DNSSEC)을 실시간으로 점검한다.
App 15(CVE 조회)/App 17(인프라 스캐너)처럼 Claude API를 쓰지 않는다 — Google Public DNS의
DNS-over-HTTPS(DoH) JSON API(https://dns.google/resolve)를 이 프로젝트에서 이미 쓰는
httpx로 직접 조회한다(dnspython 같은 새 의존성 추가 없음).
"""
import re
import httpx

_DOH_URL = "https://dns.google/resolve"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

_COMMON_DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "dkim", "mail", "smtp"]

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain.strip()))


async def _doh_raw(client: httpx.AsyncClient, name: str, record_type: str) -> dict:
    try:
        resp = await client.get(_DOH_URL, params={"name": name, "type": record_type})
    except httpx.HTTPError:
        return {}
    if resp.status_code != 200:
        return {}
    return resp.json()


def _answers(data: dict) -> list[str]:
    # TXT 레코드는 data가 큰따옴표로 감싸져 옴 (예: '"v=spf1 ..."') — 벗겨낸다
    return [a.get("data", "").strip('"') for a in data.get("Answer", []) if a.get("data")]


def _spf_finding(records: list[str]) -> dict:
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_records:
        return {
            "check": "SPF", "status": "MISSING", "severity": "HIGH",
            "value": None,
            "description": "SPF 레코드가 없습니다. 공격자가 이 도메인 이름으로 이메일을 위조해 보내도 수신 서버가 발신 서버를 검증할 방법이 없습니다.",
            "recommendation": '도메인 apex(예: example.com)에 TXT 레코드로 "v=spf1 include:<실제 발신 서버> -all" 형태를 추가하세요.',
        }
    if len(spf_records) > 1:
        return {
            "check": "SPF", "status": "MISCONFIGURED", "severity": "MEDIUM",
            "value": " | ".join(spf_records),
            "description": f"SPF 레코드가 {len(spf_records)}개 존재합니다. RFC 7208은 도메인당 SPF 레코드를 하나만 두도록 요구하며, 여러 개가 있으면 일부 수신 서버가 검증 자체를 실패(permerror) 처리할 수 있습니다.",
            "recommendation": "여러 SPF 레코드를 하나로 병합해 TXT 레코드 1개로 유지하세요.",
        }

    record = spf_records[0]
    all_match = re.search(r"([+\-~?]?)all\b", record, re.IGNORECASE)
    qualifier = (all_match.group(1) or "+") if all_match else None

    if qualifier is None:
        return {
            "check": "SPF", "status": "INCOMPLETE", "severity": "MEDIUM",
            "value": record,
            "description": "SPF 레코드에 종료 메커니즘(all)이 없습니다. 명시되지 않은 발신자를 어떻게 처리할지 방침이 불명확합니다.",
            "recommendation": "레코드 끝에 -all(권장) 또는 최소 ~all을 추가해 명시하세요.",
        }
    if qualifier == "+":
        return {
            "check": "SPF", "status": "WEAK", "severity": "CRITICAL",
            "value": record,
            "description": "SPF 정책이 사실상 모든 발신자를 허용(+all)하고 있습니다. SPF를 두는 의미가 없어집니다.",
            "recommendation": "허용할 발신 서버를 명시하고 마지막을 -all(hardfail)로 마무리하세요.",
        }
    if qualifier == "?":
        return {
            "check": "SPF", "status": "WEAK", "severity": "MEDIUM",
            "value": record,
            "description": "SPF가 neutral(?all)로 설정되어 있어 검증 실패에 대해 사실상 아무 판단도 내리지 않습니다.",
            "recommendation": "발신 서버 목록을 확정한 뒤 -all(hardfail)로 강화하세요.",
        }
    if qualifier == "~":
        return {
            "check": "SPF", "status": "WEAK", "severity": "LOW",
            "value": record,
            "description": "SPF가 softfail(~all)로 설정되어 있습니다. 위조 메일을 표시는 하지만 명시적으로 거부하지는 않습니다.",
            "recommendation": "발신 서버 목록이 충분히 검증됐다면 -all(hardfail)로 강화하는 것을 검토하세요.",
        }
    return {
        "check": "SPF", "status": "OK", "severity": "INFO",
        "value": record,
        "description": "SPF 레코드가 존재하고 hardfail(-all)로 적절히 설정되어 있습니다.",
        "recommendation": "",
    }


def _dmarc_finding(records: list[str]) -> dict:
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {
            "check": "DMARC", "status": "MISSING", "severity": "HIGH",
            "value": None,
            "description": "DMARC 레코드가 없습니다. SPF/DKIM이 있어도 DMARC가 없으면 검증 실패 시 어떻게 처리할지(격리/거부/무시) 정책이 없어 수신 서버마다 제각각 처리합니다.",
            "recommendation": '_dmarc.<도메인>에 TXT 레코드로 "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@<도메인>" 형태로 시작해 점진적으로 강화하세요.',
        }
    record = dmarc_records[0]
    policy_match = re.search(r"p=(\w+)", record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else None

    if policy == "none":
        return {
            "check": "DMARC", "status": "MONITOR_ONLY", "severity": "MEDIUM",
            "value": record,
            "description": "DMARC 정책이 p=none(모니터링 전용)입니다. 위조 메일에 대한 리포트는 받지만 실제로 격리/거부하지는 않습니다.",
            "recommendation": "리포트로 정상 발신원을 충분히 파악한 뒤 p=quarantine을 거쳐 최종적으로 p=reject로 강화하는 것을 권장합니다.",
        }
    if policy in ("quarantine", "reject"):
        return {
            "check": "DMARC", "status": "OK", "severity": "INFO",
            "value": record,
            "description": f"DMARC 정책이 p={policy}로 설정되어 실제로 위조 의심 메일을 처리하고 있습니다.",
            "recommendation": "",
        }
    return {
        "check": "DMARC", "status": "MISCONFIGURED", "severity": "MEDIUM",
        "value": record,
        "description": "DMARC 레코드는 있지만 p= 정책 값을 명확히 확인할 수 없습니다.",
        "recommendation": "레코드 형식이 올바른지(v=DMARC1; p=...) 확인하세요.",
    }


def _has_active_dkim_key(record: str) -> bool:
    """v=DKIM1 태그가 있고 p=(공개키)에 실제 값이 있는 경우만 '유효한 키'로 인정한다.
    p=가 비어있으면(예: "v=DKIM1; p=") RFC 6376상 명시적으로 폐기(revoked)된 키를
    뜻하므로 '발견'으로 잘못 집계하지 않는다 — 일부 도메인(예: example.com)은
    모든 셀렉터에 와일드카드로 이런 폐기 레코드를 반환해 그대로 두면 오탐이 난다."""
    lowered = record.lower()
    if "v=dkim1" not in lowered:
        return False
    p_match = re.search(r"p=([^;]*)", record, re.IGNORECASE)
    return bool(p_match and p_match.group(1).strip())


async def _dkim_finding(client: httpx.AsyncClient, domain: str) -> dict:
    found_selectors = []
    for selector in _COMMON_DKIM_SELECTORS:
        data = await _doh_raw(client, f"{selector}._domainkey.{domain}", "TXT")
        records = _answers(data)
        if any(_has_active_dkim_key(r) for r in records):
            found_selectors.append(selector)

    if found_selectors:
        return {
            "check": "DKIM", "status": "FOUND", "severity": "INFO",
            "value": ", ".join(found_selectors),
            "description": f"일반적인 셀렉터({', '.join(found_selectors)})에서 DKIM 레코드를 확인했습니다.",
            "recommendation": "",
        }
    return {
        "check": "DKIM", "status": "NOT_FOUND_COMMON", "severity": "LOW",
        "value": None,
        "description": "흔히 쓰이는 셀렉터 목록에서는 DKIM 레코드를 찾지 못했습니다. 실제 셀렉터 이름이 다를 수 있어 DKIM이 없다고 단정할 수는 없습니다 (best-effort 점검).",
        "recommendation": "실제 발신 시스템(Google Workspace/SES/SendGrid 등)의 관리 콘솔에서 실제 사용 중인 DKIM 셀렉터를 확인하고 별도로 검증하세요.",
    }


async def _dnssec_finding(client: httpx.AsyncClient, domain: str) -> dict:
    data = await _doh_raw(client, domain, "DNSKEY")
    records = _answers(data)
    if records:
        return {
            "check": "DNSSEC", "status": "LIKELY_ENABLED", "severity": "INFO",
            "value": f"{len(records)}개 DNSKEY 발견",
            "description": "도메인에 DNSKEY 레코드가 존재해 DNSSEC이 적용되어 있을 가능성이 높습니다.",
            "recommendation": "",
        }
    return {
        "check": "DNSSEC", "status": "NOT_DETECTED", "severity": "LOW",
        "value": None,
        "description": "DNSKEY 레코드를 찾지 못했습니다 — DNSSEC이 적용되어 있지 않을 가능성이 높습니다. DNS 스푸핑/캐시 포이즈닝에 대한 추가 방어층이 없는 상태입니다.",
        "recommendation": "DNS 등록기관/네임서버 제공자에서 DNSSEC 서명을 활성화하는 것을 검토하세요.",
    }


async def check_domain(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not is_valid_domain(domain):
        return {"error": "invalid_format", "message": f"올바른 도메인 형식이 아닙니다: {domain}"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        spf_data = await _doh_raw(client, domain, "TXT")
        if spf_data.get("Status") == 3:  # NXDOMAIN
            return {"error": "not_found", "message": f"{domain}을(를) DNS에서 찾을 수 없습니다."}

        dmarc_data = await _doh_raw(client, f"_dmarc.{domain}", "TXT")
        dkim = await _dkim_finding(client, domain)
        dnssec = await _dnssec_finding(client, domain)

    checks = [_spf_finding(_answers(spf_data)), _dmarc_finding(_answers(dmarc_data)), dkim, dnssec]
    checks.sort(key=lambda c: _SEVERITY_RANK.get(c["severity"], 0), reverse=True)

    stats = {"total": len(checks), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for c in checks:
        key = c["severity"].lower()
        stats[key] = stats.get(key, 0) + 1

    if stats["critical"] > 0:
        overall_risk = "CRITICAL"
    elif stats["high"] > 0:
        overall_risk = "HIGH"
    elif stats["medium"] > 0:
        overall_risk = "MEDIUM"
    elif stats["low"] > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFO"

    weak_or_missing = [c["check"] for c in checks if c["severity"] in ("CRITICAL", "HIGH")]
    if weak_or_missing:
        summary = f"{domain}: {', '.join(weak_or_missing)}에서 이메일 위조 방지에 중요한 설정이 없거나 약합니다."
    else:
        summary = f"{domain}: 확인한 이메일/DNS 보안 설정에 심각한 문제가 발견되지 않았습니다."

    return {
        "domain": domain,
        "overall_risk": overall_risk,
        "summary": summary,
        "checks": checks,
        "stats": stats,
    }


DISCLAIMER = (
    "이 도구는 Claude AI를 쓰지 않고 Google Public DNS(dns.google)의 DNS-over-HTTPS API로 실시간 조회한 "
    "결과를 결정론적 규칙으로 판정합니다. DKIM은 흔히 쓰이는 셀렉터 목록만 확인하는 best-effort 점검이라 "
    "실제 셀렉터가 다르면 '못 찾음'으로 나올 수 있습니다 — 못 찾음을 곧바로 미적용으로 단정하지 마세요."
)


def generate_markdown_report(entry: dict) -> str:
    lines = [
        "# DNS/이메일 보안 점검 리포트",
        "",
        f"**대상 도메인:** {entry.get('domain', 'N/A')}  ",
        f"**종합 위험도:** {entry.get('overall_risk', 'N/A')}  ",
        "",
        "> Google Public DNS(dns.google)로 실시간 조회한 결과입니다 (Claude AI 미사용).",
        "",
        "---",
        "",
        "## 종합 평가",
        "",
        entry.get("summary", ""),
        "",
        "## 상세 결과",
        "",
    ]
    for c in entry.get("checks", []):
        lines += [
            f"### [{c.get('severity')}] {c.get('check')} — {c.get('status')}",
            "",
            f"**레코드 값:** `{c.get('value') or '(없음)'}`  ",
            "",
            f"{c.get('description', '')}",
            "",
        ]
        if c.get("recommendation"):
            lines += [f"**권장 조치:** {c['recommendation']}", ""]
        lines += ["---", ""]

    lines += [
        "## 다음 단계",
        "",
        "- 피싱 시뮬레이션/탐지도 함께 점검하려면 [피싱 탐지기](/phishing)·[피싱 모의훈련 생성기](/phishing-sim)를 이용해보세요.",
    ]
    return "\n".join(lines)
