"""NVD(미국 국가 취약점 데이터베이스) 공식 REST API 연동.

이 프로젝트의 다른 앱들과 달리 Claude API를 쓰지 않는다 — Anthropic API 키 유무와 무관하게
항상 실제 외부 API(NVD)를 실시간으로 조회한다. NVD_API_KEY는 선택 사항이며, 없으면
공개 레이트리밋(30초당 5건)이 적용되고 있으면(30초당 50건) 더 여유롭게 조회할 수 있다.
"""
import os
import re
import httpx
from dotenv import load_dotenv

load_dotenv()

_NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

HAS_API_KEY = bool(_NVD_API_KEY)


def is_valid_cve_id(cve_id: str) -> bool:
    return bool(_CVE_ID_RE.match(cve_id.strip()))


def _headers() -> dict:
    return {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}


def _best_cvss(metrics: dict) -> dict | None:
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version", version),
                "base_score": data.get("baseScore"),
                "base_severity": data.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return None


def _normalize(cve: dict) -> dict:
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
    desc = desc_en or (descriptions[0]["value"] if descriptions else "설명 없음")

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in cwe_ids:
                cwe_ids.append(val)

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")][:8]

    return {
        "id": cve.get("id"),
        "description": desc,
        "cvss": _best_cvss(cve.get("metrics", {})),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cwe_ids": cwe_ids,
        "references": references,
        "source": "NVD (National Vulnerability Database)",
    }


async def lookup_cve(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    if not is_valid_cve_id(cve_id):
        return {"error": "invalid_format", "message": f"올바른 CVE ID 형식이 아닙니다: {cve_id} (예: CVE-2021-44228)"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_BASE_URL, params={"cveId": cve_id}, headers=_headers())
    except httpx.TimeoutException:
        return {"error": "timeout", "message": "NVD API 응답이 시간 내에 오지 않았습니다. 잠시 후 다시 시도하세요."}
    except httpx.HTTPError as e:
        return {"error": "network", "message": f"NVD API 연결 실패: {e}"}

    if resp.status_code in (403, 429):
        return {"error": "rate_limited", "message": "NVD API 요청 한도를 초과했습니다. 잠시 후 다시 시도하거나 NVD_API_KEY를 설정하세요."}
    if resp.status_code != 200:
        return {"error": "upstream_error", "message": f"NVD API 오류 (HTTP {resp.status_code})"}

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": "not_found", "message": f"{cve_id}를 NVD에서 찾을 수 없습니다."}

    return _normalize(vulns[0]["cve"])


async def search_cves(keyword: str, results_per_page: int = 10) -> dict:
    keyword = keyword.strip()
    if len(keyword) < 3:
        return {"error": "invalid_query", "message": "검색어는 3자 이상 입력하세요."}

    results_per_page = max(1, min(results_per_page, 20))
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                _BASE_URL,
                params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
                headers=_headers(),
            )
    except httpx.TimeoutException:
        return {"error": "timeout", "message": "NVD API 응답이 시간 내에 오지 않았습니다. 잠시 후 다시 시도하세요."}
    except httpx.HTTPError as e:
        return {"error": "network", "message": f"NVD API 연결 실패: {e}"}

    if resp.status_code in (403, 429):
        return {"error": "rate_limited", "message": "NVD API 요청 한도를 초과했습니다. 잠시 후 다시 시도하거나 NVD_API_KEY를 설정하세요."}
    if resp.status_code != 200:
        return {"error": "upstream_error", "message": f"NVD API 오류 (HTTP {resp.status_code})"}

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    results = [_normalize(v["cve"]) for v in vulns]
    for r in results:
        if r["description"] and len(r["description"]) > 220:
            r["description"] = r["description"][:220].rstrip() + "..."
    return {"results": results, "total_results": data.get("totalResults", len(results))}
