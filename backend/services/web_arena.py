"""Web CTF 아레나 — 실제로 살아있는 취약 웹 서비스를 상대로 연습하는 실전 웹 익스플로잇 랩.

/vuln, /pwn-lab이 텍스트·바이너리 분석 중심이라면, 이 모듈은 진짜 HTTP 요청을
주고받으며 공격하는 경험을 채운다. 세 챌린지 모두 실제로 동작하는 취약점이며,
서버가 재시작될 때마다 in-memory SQLite로 초기화되는 연습용 데이터만 사용한다.
로컬 개발 서버에서만 사용하는 것을 전제로 하며, 실제 서비스 배포용 코드가 아니다.
"""

import secrets
import sqlite3
import threading

FLAGS = {
    "sqli": "WEB{sql1_1nj3ct10n_l0g1n_byp4ss}",
    "idor": "WEB{1dor_expos3d_pr1vat3_ord3r}",
    "xss": "WEB{r3fl3ct3d_xss_unesc4ped}",
}

CHALLENGE_META = [
    {
        "id": "sqli",
        "title": "SQL Injection: 관리자로 로그인하기",
        "difficulty": "입문",
        "situation": "로그인 폼이 파라미터화 없이 SQL 쿼리 문자열을 그대로 조립합니다. admin의 실제 비밀번호를 몰라도 로그인할 수 있는 입력을 찾아보세요.",
        "endpoint": "POST /api/web-arena/sqli/login  { username, password }",
        "hints": [
            "정상 로그인은 username=alice, password=alicepw1 로 먼저 확인해볼 수 있습니다.",
            "username에 ' OR '1'='1 같은 값을 넣으면 WHERE 조건이 항상 참이 될 수 있습니다.",
            "admin으로 로그인하려면 username을 admin'-- 처럼 만들어 뒤의 password 조건 자체를 주석 처리해보세요.",
        ],
    },
    {
        "id": "idor",
        "title": "IDOR: 다른 사람의 주문 훔쳐보기",
        "difficulty": "입문",
        "situation": "guest로 로그인하면 본인 주문(1001)은 정상적으로 볼 수 있습니다. 하지만 서버는 요청한 주문 ID가 정말 내 것인지 검증하지 않습니다.",
        "endpoint": "POST /api/web-arena/idor/login { username } → GET /api/web-arena/idor/orders/{id}",
        "hints": [
            "먼저 username: guest 로 로그인해 세션 토큰을 받으세요.",
            "받은 토큰으로 주문 ID 1001을 조회해 본인 주문이 정상적으로 보이는지 확인하세요.",
            "주문 ID를 1001이 아닌 다른 숫자(예: 1002)로 바꿔서 조회하면 어떻게 될까요?",
        ],
    },
    {
        "id": "xss",
        "title": "Reflected XSS: 검색창에 스크립트 심기",
        "difficulty": "입문",
        "situation": "검색 결과 페이지가 입력값을 이스케이프 없이 그대로 HTML에 출력합니다.",
        "endpoint": "GET /api/web-arena/xss/search?q=...",
        "hints": [
            "일반 검색어를 넣고 응답 HTML 소스를 확인해보세요 — 입력이 그대로 보이나요?",
            "<script>...</script> 같은 태그를 q에 넣으면 응답에 어떻게 반영되는지 확인해보세요.",
            "실제 브라우저가 이 응답을 렌더링했다면 태그 안의 스크립트가 그대로 실행됩니다 — 이 아레나는 태그가 이스케이프 없이 그대로 반영되면 성공으로 판정합니다.",
        ],
    },
]

_lock = threading.Lock()
_conn = sqlite3.connect(":memory:", check_same_thread=False)
SESSIONS: dict[str, str] = {}


def _seed() -> None:
    cur = _conn.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS orders;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, owner TEXT, item TEXT, note TEXT);
        """
    )
    cur.executemany(
        "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "alicepw1", "user"),
            (2, "bob", "bobpw2", "user"),
            (3, "admin", "Adm1n_S3cr3t_2026!", "admin"),
        ],
    )
    cur.executemany(
        "INSERT INTO orders (id, owner, item, note) VALUES (?, ?, ?, ?)",
        [
            (1001, "guest", "Widget A", "일반 주문입니다. 특별한 내용은 없습니다."),
            (1002, "admin", "Confidential Contract", f"기밀 메모: {FLAGS['idor']}"),
        ],
    )
    _conn.commit()


_seed()


def sqli_login(username: str, password: str) -> dict:
    # 의도적 취약점: 파라미터화 없이 사용자 입력을 SQL 문자열에 그대로 삽입한다.
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
    with _lock:
        cur = _conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            return {"success": False, "query": query, "error": str(e)}

    if row is None:
        return {"success": False, "query": query}

    _uid, uname, role = row
    result = {"success": True, "query": query, "username": uname, "role": role}
    if role == "admin":
        result["flag"] = FLAGS["sqli"]
    return result


def idor_login(username: str) -> dict:
    token = secrets.token_hex(8)
    SESSIONS[token] = username
    return {"token": token, "username": username}


def is_valid_session(token: str) -> str | None:
    return SESSIONS.get(token)


def idor_get_order(order_id: int) -> dict | None:
    with _lock:
        cur = _conn.cursor()
        # 의도적 취약점: 조회하는 주문이 현재 세션 사용자의 소유인지 검증하지 않는다.
        cur.execute("SELECT id, owner, item, note FROM orders WHERE id=?", (order_id,))
        row = cur.fetchone()
    if row is None:
        return None
    oid, owner, item, note = row
    return {"id": oid, "owner": owner, "item": item, "note": note}


def xss_search(q: str) -> str:
    reveal = ""
    if "<script" in q.lower():
        reveal = f"<div id=\"flag-reveal\">축하합니다! 입력이 이스케이프 없이 그대로 반영되었습니다.<br>{FLAGS['xss']}</div>"
    # 의도적 취약점: 사용자 입력을 이스케이프 없이 그대로 HTML에 반영한다.
    return f"""<!doctype html>
<html><body>
<h3>검색 결과: {q}</h3>
<p>'{q}'에 대한 검색 결과가 없습니다.</p>
{reveal}
</body></html>"""
