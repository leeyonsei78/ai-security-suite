"""App 15(CVE 실시간 조회)의 폐쇄망 지원 — NVD는 외부 실시간 API라 로컬 LLM으로 대체할 수
없다. 대신 다음 두 경로로 로컬 캐시를 채운다:

1. 인터넷이 되는 동안 조회에 성공할 때마다 자동으로 이 캐시에 적재(write-through).
2. 온라인 상태에서 미리 받아둔 NVD 공식 데이터 피드(JSON 2.0, nvdcve-2.0-*.json —
   https://nvd.nist.gov/vuln/data-feeds)를 폐쇄망으로 반입해 `import_feed()`로 일괄 적재.

폐쇄망에서는 이 캐시에 있는 것만 조회 가능하다 — 실시간성은 없지만, 최소한 "완전히
동작 불능"이 아니라 마지막으로 동기화된 시점 기준의 실제 데이터를 계속 조회할 수 있다.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_cache.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
_conn.execute(
    """
    CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'live',
        cached_at REAL NOT NULL
    )
    """
)
_conn.commit()
_lock = threading.Lock()


def upsert(cve_id: str, data: dict, source: str = "live") -> None:
    with _lock:
        _conn.execute(
            "INSERT INTO cve_cache (cve_id, data, source, cached_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET data=excluded.data, source=excluded.source, cached_at=excluded.cached_at",
            (cve_id.upper(), json.dumps(data, ensure_ascii=False), source, time.time()),
        )
        _conn.commit()


def get(cve_id: str) -> dict | None:
    with _lock:
        row = _conn.execute("SELECT data FROM cve_cache WHERE cve_id = ?", (cve_id.upper(),)).fetchone()
    if not row:
        return None
    data = json.loads(row[0])
    data["_offline_cache"] = True
    return data


def search(keyword: str, limit: int = 10) -> list[dict]:
    like = f"%{keyword.lower()}%"
    with _lock:
        rows = _conn.execute(
            "SELECT data FROM cve_cache WHERE LOWER(data) LIKE ? ORDER BY cached_at DESC LIMIT ?",
            (like, limit),
        ).fetchall()
    results = []
    for (raw,) in rows:
        d = json.loads(raw)
        d["_offline_cache"] = True
        results.append(d)
    return results


def stats() -> dict:
    with _lock:
        count = _conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        latest = _conn.execute("SELECT MAX(cached_at) FROM cve_cache").fetchone()[0]
        by_source = dict(_conn.execute("SELECT source, COUNT(*) FROM cve_cache GROUP BY source").fetchall())
    return {"cached_count": count, "last_updated": latest, "by_source": by_source}


def import_feed(raw_bytes: bytes) -> dict:
    """NVD JSON 2.0 데이터 피드 파일을 파싱해 로컬 캐시에 일괄 적재한다.

    피드 파일은 인터넷이 되는 환경에서 https://nvd.nist.gov/vuln/data-feeds 에서 미리
    내려받아, 승인된 절차(USB 반입 등)로 폐쇄망에 옮긴 뒤 이 함수(업로드 엔드포인트)로
    가져온다.
    """
    from services.cve_lookup_service import _normalize  # 기존 정규화 로직 재사용

    try:
        data = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"올바른 JSON 파일이 아닙니다: {e}") from e

    vulns = data.get("vulnerabilities")
    if vulns is None:
        raise ValueError("NVD JSON 2.0 피드 형식이 아닙니다 (vulnerabilities 필드 없음).")

    imported = 0
    now = time.time()
    with _lock:
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            normalized = _normalize(cve)
            _conn.execute(
                "INSERT INTO cve_cache (cve_id, data, source, cached_at) VALUES (?, ?, 'import', ?) "
                "ON CONFLICT(cve_id) DO UPDATE SET data=excluded.data, source='import', cached_at=excluded.cached_at",
                (cve_id.upper(), json.dumps(normalized, ensure_ascii=False), now),
            )
            imported += 1
        _conn.commit()

    return {"imported": imported, "total_in_feed": len(vulns)}
