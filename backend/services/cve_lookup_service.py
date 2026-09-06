"""NVD(미국 국가 취약점 데이터베이스) 공식 REST API 연동.

이 프로젝트의 다른 앱들과 달리 Claude API를 쓰지 않는다 — Anthropic API 키 유무와 무관하게
항상 실제 외부 API(NVD)를 실시간으로 조회한다. NVD_API_KEY는 선택 사항이며, 없으면
공개 레이트리밋(30초당 5건)이 적용되고 있으면(30초당 50건) 더 여유롭게 조회할 수 있다.
"""
import asyncio
import os
import re
from datetime import datetime, timedelta, timezone
import httpx
from dotenv import load_dotenv
from services import mode_manager, cve_offline_store

load_dotenv()

_NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

HAS_API_KEY = bool(_NVD_API_KEY)

# "지금 최신 데이터 가져오기" — 사용자가 nvd.nist.gov에서 피드 파일을 직접 받아 올리지
# 않아도, 이 앱이 직접 NVD REST API를 lastModStartDate/lastModEndDate로 조회해 최근
# 수정된 CVE를 페이지네이션으로 전부 가져와 로컬 캐시에 적재한다. import_feed()가 쓰는
# 것과 동일한 {"vulnerabilities": [{"cve": {...}}]} 응답 스키마를 그대로 재사용.
_REFRESH_MAX_DAYS = 30  # NVD API 실제 한도(약 120일)보다 훨씬 보수적으로 잡아 한 번의
                        # 요청이 과도하게 오래 걸리지 않게 함(수동 피드 가져오기는 더 넓은 범위용)
_REFRESH_PAGE_SIZE = 2000  # NVD API 최대 페이지 크기
_REFRESH_DELAY = 0.7 if HAS_API_KEY else 6.5  # App17 dependency_scan_service와 동일한 레이트리밋 대응 패턴


async def get_network_mode() -> str:
    """'online'(NVD 실시간 조회) 또는 'offline'(로컬 캐시/가져온 피드만 조회) — 폐쇄망에서는
    자동으로 offline이 감지된다."""
    return await mode_manager.get_external_api_mode("cve", "https://services.nvd.nist.gov/")


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

    if await get_network_mode() == "offline":
        cached = cve_offline_store.get(cve_id)
        if cached:
            return cached
        return {
            "error": "offline_not_cached",
            "message": f"폐쇄망(오프라인) 모드입니다 — {cve_id}는 로컬 캐시에 없습니다. "
                       "인터넷이 되는 환경에서 한 번 조회해두거나, NVD 데이터 피드를 가져오기(import) 하세요.",
        }

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

    normalized = _normalize(vulns[0]["cve"])
    cve_offline_store.upsert(cve_id, normalized, source="live")
    return normalized


async def search_cves(keyword: str, results_per_page: int = 10) -> dict:
    keyword = keyword.strip()
    if len(keyword) < 3:
        return {"error": "invalid_query", "message": "검색어는 3자 이상 입력하세요."}

    results_per_page = max(1, min(results_per_page, 20))

    if await get_network_mode() == "offline":
        results = cve_offline_store.search(keyword, limit=results_per_page)
        return {"results": results, "total_results": len(results), "_offline_cache": True}

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
        if r.get("id"):
            cve_offline_store.upsert(r["id"], r, source="live")
        if r["description"] and len(r["description"]) > 220:
            r["description"] = r["description"][:220].rstrip() + "..."
    return {"results": results, "total_results": data.get("totalResults", len(results))}


async def refresh_recent(days: int = 7) -> dict:
    """최근 N일간 NVD에서 신규 등록/수정된 CVE를 전부 가져와 로컬 캐시에 적재한다 —
    사용자가 피드 파일을 수동으로 받아 올리지 않아도, 이 앱이 직접 NVD API를 페이지네이션
    호출해 최신화한다("피드 가져오기"는 여전히 더 넓은 과거 범위를 반입할 때 유용해 그대로
    유지). 온라인일 때만 동작 — 오프라인이면 애초에 최신화할 데이터를 가져올 수 없다."""
    days = max(1, min(days, _REFRESH_MAX_DAYS))

    if await get_network_mode() == "offline":
        return {
            "error": "offline",
            "message": "인터넷에 연결할 수 없어 최신화할 수 없습니다 — 온라인 상태에서 다시 시도하거나, 미리 받아둔 피드 파일을 [피드 가져오기]로 업로드하세요.",
        }

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    date_fmt = "%Y-%m-%dT%H:%M:%S.000"
    base_params = {
        "lastModStartDate": start.strftime(date_fmt),
        "lastModEndDate": end.strftime(date_fmt),
        "resultsPerPage": _REFRESH_PAGE_SIZE,
    }

    imported = 0
    total_results = 0
    start_index = 0
    pages = 0

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                resp = await client.get(
                    _BASE_URL, params={**base_params, "startIndex": start_index}, headers=_headers()
                )
                if resp.status_code in (403, 429):
                    return {
                        "error": "rate_limited",
                        "message": "NVD API 요청 한도를 초과했습니다. 잠시 후 다시 시도하거나 NVD_API_KEY를 설정하세요.",
                        "imported": imported,
                    }
                if resp.status_code == 404:
                    return {
                        "error": "invalid_range",
                        "message": f"요청한 기간({days}일)이 NVD API가 허용하는 범위를 벗어났습니다. 더 짧은 기간으로 다시 시도하세요.",
                        "imported": imported,
                    }
                if resp.status_code != 200:
                    return {"error": "upstream_error", "message": f"NVD API 오류 (HTTP {resp.status_code})", "imported": imported}

                data = resp.json()
                total_results = data.get("totalResults", 0)
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cve", {})
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    cve_offline_store.upsert(cve_id, _normalize(cve), source="refresh")
                    imported += 1

                pages += 1
                start_index += len(vulns)
                if not vulns or start_index >= total_results:
                    break
                await asyncio.sleep(_REFRESH_DELAY)
    except httpx.TimeoutException:
        return {"error": "timeout", "message": "NVD API 응답이 시간 내에 오지 않았습니다. 잠시 후 다시 시도하세요.", "imported": imported}
    except httpx.HTTPError as e:
        return {"error": "network", "message": f"NVD API 연결 실패: {e}", "imported": imported}

    return {
        "imported": imported,
        "total_in_range": total_results,
        "pages": pages,
        "days": days,
    }
