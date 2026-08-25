"""히스토리 영속화 계층 — 여러 앱(App 1/2/3/4/5/6/7/8/11/12)이 지금까지 각자
`history: list[dict]` 형태의 메모리 리스트로 관리하던 분석 이력/세션을 SQLite로
옮긴다. 앱마다 저장하는 딕셔너리 모양이 제각각이라 컬럼을 앱별로 나누는 대신,
`app` 이름으로 구분되는 단일 테이블에 JSON 블롭으로 저장하는 범용 구조를 쓴다
— 지금까지 메모리에 쌓던 dict를 그대로 저장하는 것과 동일하되, 서버를 재시작해도
사라지지 않는다는 차이만 있다.

Web CTF 아레나(App 10)·Pwn/Reverse 실습실(App 9)·모의 해킹 랩(App 13)의 상태는
의도적으로 서버 재시작 시 초기화되어야 하는 CTF 연습용 데이터라 이 모듈을 쓰지 않는다.
"""

import json
import sqlite3
import threading
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "history.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
_conn.execute(
    """
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        data TEXT NOT NULL
    )
    """
)
_conn.execute("CREATE INDEX IF NOT EXISTS idx_history_app ON history(app)")
_conn.commit()

_lock = threading.Lock()


def add_entry(app: str, data: dict) -> int:
    """entry를 새로 저장하고, 이 저장소가 부여한 영속 id를 반환한다."""
    with _lock:
        cur = _conn.execute(
            "INSERT INTO history (app, data) VALUES (?, ?)",
            (app, json.dumps(data, ensure_ascii=False)),
        )
        _conn.commit()
        return cur.lastrowid


def get_history(app: str) -> list[dict]:
    with _lock:
        rows = _conn.execute(
            "SELECT id, data FROM history WHERE app = ? ORDER BY id", (app,)
        ).fetchall()
    entries = []
    for row_id, data_json in rows:
        entry = json.loads(data_json)
        entry["id"] = row_id
        entries.append(entry)
    return entries


def get_entry(app: str, entry_id: int) -> dict | None:
    with _lock:
        row = _conn.execute(
            "SELECT data FROM history WHERE app = ? AND id = ?", (app, entry_id)
        ).fetchone()
    if row is None:
        return None
    entry = json.loads(row[0])
    entry["id"] = entry_id
    return entry


def update_entry(app: str, entry_id: int, data: dict) -> None:
    with _lock:
        _conn.execute(
            "UPDATE history SET data = ? WHERE app = ? AND id = ?",
            (json.dumps(data, ensure_ascii=False), app, entry_id),
        )
        _conn.commit()


def clear_history(app: str) -> None:
    with _lock:
        _conn.execute("DELETE FROM history WHERE app = ?", (app,))
        _conn.commit()
