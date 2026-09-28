"""IoC 분석기(App 4)의 AI 판정을 실제 위협 인텔리전스 DB로 보강한다.

지금까지 App 4는 Claude의 추론(또는 Mock 데이터)만으로 악성 여부를 판정했는데,
이 모듈은 AbuseIPDB(IP 평판)·AlienVault OTX(커뮤니티 IOC 공유)의 실제 조회 결과를
같이 붙여 "AI 추정"과 "실제 검증 데이터"를 나란히 보여준다. VirusTotal은 무료 API
약관상 상업적 재판매가 금지되어 있어 제외함 — 필요 시 유료 라이선스 계약 후 별도 추가.

두 키 다 선택 사항(opt-in) — 다른 앱들의 Mock/Live 패턴과 동일하게, 미설정 시
해당 provider는 조용히 건너뛰고 결과에 아예 포함되지 않는다(기존 동작에 회귀 없음).
AbuseIPDB는 IP만, OTX는 IP/도메인/해시를 지원 — email 타입은 두 서비스 다 대상이 아니라
그대로 AI 판정만 유지된다.

무료 한도(AbuseIPDB 일 1,000건, OTX 사실상 무제한이나 매너상 제한)를 아끼기 위해
동일 IoC는 24시간 캐싱한다(`backend/data/threat_intel_cache.db`, gitignore 대상).
"""

import asyncio
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()

IS_ABUSEIPDB_CONFIGURED = bool(ABUSEIPDB_API_KEY)
IS_OTX_CONFIGURED = bool(OTX_API_KEY)
IS_CONFIGURED = IS_ABUSEIPDB_CONFIGURED or IS_OTX_CONFIGURED

_CACHE_TTL_SECONDS = 24 * 60 * 60
_TIMEOUT = 8.0

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_intel_cache.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
_conn.execute(
    """
    CREATE TABLE IF NOT EXISTS cache (
        ioc TEXT NOT NULL,
        provider TEXT NOT NULL,
        data TEXT NOT NULL,
        fetched_at REAL NOT NULL,
        PRIMARY KEY (ioc, provider)
    )
    """
)
_conn.commit()
_lock = threading.Lock()


def _cache_get(ioc: str, provider: str) -> dict | None:
    with _lock:
        row = _conn.execute(
            "SELECT data, fetched_at FROM cache WHERE ioc = ? AND provider = ?", (ioc, provider)
        ).fetchone()
    if row is None:
        return None
    data_json, fetched_at = row
    if time.time() - fetched_at > _CACHE_TTL_SECONDS:
        return None
    return json.loads(data_json)


def _cache_set(ioc: str, provider: str, data: dict) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO cache (ioc, provider, data, fetched_at) VALUES (?, ?, ?, ?)",
            (ioc, provider, json.dumps(data, ensure_ascii=False), time.time()),
        )
        _conn.commit()


async def _check_abuseipdb(ip: str) -> dict | None:
    cached = _cache_get(ip, "abuseipdb")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
        if resp.status_code != 200:
            return {"available": False, "error": f"HTTP {resp.status_code}"}
        d = resp.json().get("data", {})
        result = {
            "available": True,
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "last_reported_at": d.get("lastReportedAt"),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        }
    except httpx.HTTPError as e:
        result = {"available": False, "error": str(e)}

    _cache_set(ip, "abuseipdb", result)
    return result


_OTX_SECTION = {"ip": "IPv4", "domain": "domain", "hash": "file"}


async def _check_otx(ioc: str, ioc_type: str) -> dict | None:
    section = _OTX_SECTION.get(ioc_type)
    if section is None:
        return None

    cached = _cache_get(ioc, "otx")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
            )
        if resp.status_code != 200:
            return {"available": False, "error": f"HTTP {resp.status_code}"}
        d = resp.json()
        result = {
            "available": True,
            "pulse_count": d.get("pulse_info", {}).get("count", 0),
            "link": f"https://otx.alienvault.com/indicator/{section.lower()}/{ioc}",
        }
    except httpx.HTTPError as e:
        result = {"available": False, "error": str(e)}

    _cache_set(ioc, "otx", result)
    return result


async def enrich_one(ioc: str, ioc_type: str) -> dict | None:
    """단일 IoC를 설정된 provider들로 조회해 {"abuseipdb": {...}, "otx": {...}} 형태로 반환.
    아무 provider도 설정 안 됐거나 해당 타입을 지원하는 provider가 없으면 None."""
    tasks = {}
    if IS_ABUSEIPDB_CONFIGURED and ioc_type == "ip":
        tasks["abuseipdb"] = _check_abuseipdb(ioc)
    if IS_OTX_CONFIGURED and ioc_type in _OTX_SECTION:
        tasks["otx"] = _check_otx(ioc, ioc_type)

    if not tasks:
        return None

    values = await asyncio.gather(*tasks.values())
    return dict(zip(tasks.keys(), values))


async def enrich_results(results: list[dict]) -> list[dict]:
    """analyze_ioc()가 반환한 결과 리스트에 threat_intel 필드를 붙인다 (in-place 아님, 새 리스트 반환)."""
    if not IS_CONFIGURED:
        return results

    enrichments = await asyncio.gather(
        *(enrich_one(r["ioc"], r.get("ioc_type", "unknown")) for r in results)
    )
    enriched = []
    for r, ti in zip(results, enrichments):
        if ti is not None:
            r = {**r, "threat_intel": ti}
        enriched.append(r)
    return enriched
