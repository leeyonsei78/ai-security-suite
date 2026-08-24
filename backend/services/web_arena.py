"""Web CTF 아레나 — 실제로 살아있는 취약 웹 서비스를 상대로 연습하는 실전 웹 익스플로잇 랩.

/vuln, /pwn-lab이 텍스트·바이너리 분석 중심이라면, 이 모듈은 진짜 HTTP 요청을
주고받으며 공격하는 경험을 채운다. 세 챌린지 모두 실제로 동작하는 취약점이며,
서버가 재시작될 때마다 in-memory SQLite로 초기화되는 연습용 데이터만 사용한다.
로컬 개발 서버에서만 사용하는 것을 전제로 하며, 실제 서비스 배포용 코드가 아니다.
"""

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request

FLAGS = {
    "sqli": "WEB{sql1_1nj3ct10n_l0g1n_byp4ss}",
    "idor": "WEB{1dor_expos3d_pr1vat3_ord3r}",
    "xss": "WEB{r3fl3ct3d_xss_unesc4ped}",
    "ssrf": "WEB{ssrf_p1v0t_t0_1ntern4l_4p1}",
    "jwt": "WEB{jwt_w34k_secr3t_f0rg3d}",
    "ssti": "WEB{sst1_f0rm4t_str1ng_l34k}",
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
    {
        "id": "ssrf",
        "title": "SSRF: 서버를 시켜 내부 API 훔쳐보기",
        "difficulty": "중급",
        "situation": "링크 미리보기 기능이 사용자가 준 URL을 서버가 대신 요청해서 보여줍니다. 이 서버에는 외부에서 직접 접근하면 거부당하는 '내부 전용' API가 하나 있습니다 — 하지만 서버 자신이 요청하면 통과됩니다.",
        "endpoint": "GET /api/web-arena/ssrf/fetch?url=...  (참고: 내부 API는 GET /api/web-arena/ssrf/internal-metadata 에 있지만 직접 접근하면 거부됩니다)",
        "hints": [
            "먼저 url=http://example.com 처럼 평범한 외부 주소로 시도해 미리보기가 정상 동작하는지 확인하세요.",
            "/api/web-arena/ssrf/internal-metadata 를 브라우저/curl로 직접 열어보면 '내부 네트워크에서만 접근 가능'이라는 에러가 나옵니다.",
            "미리보기 기능의 url 파라미터에 내부 API 주소(http://127.0.0.1:8000/api/web-arena/ssrf/internal-metadata)를 넣으면 어떻게 될까요? 서버가 '자기 자신'을 대신 요청하게 만드는 것이 핵심입니다.",
        ],
    },
    {
        "id": "jwt",
        "title": "JWT: 약한 시크릿으로 관리자 토큰 위조하기",
        "difficulty": "중급",
        "situation": "로그인하면 HS256으로 서명된 JWT를 받습니다. 이 서버는 시크릿 키로 흔히 쓰이는 값 중 하나를 그대로 쓰고 있습니다.",
        "endpoint": "POST /api/web-arena/jwt/login { username } → GET /api/web-arena/jwt/admin (Authorization: Bearer <token>)",
        "hints": [
            "먼저 username: guest 로 로그인해 정상 토큰을 받아보세요. role이 user로 되어 있을 것입니다.",
            "JWT는 header.payload.signature 구조입니다. header와 payload는 Base64url로 인코딩만 되어 있을 뿐 암호화된 게 아닙니다 — 디코딩해서 내용을 확인해보세요.",
            "signature는 HS256(HMAC-SHA256)으로 만들어집니다. 시크릿을 안다면 payload를 role: admin으로 바꾼 뒤 서명을 다시 계산해 '위조'할 수 있습니다.",
            "시크릿은 흔한 값입니다 — changeme, secret, password, admin123 같은 값들을 시도해보세요 (jwt_tool 같은 도구는 이런 무차별 대입을 자동화합니다). 아래 [익스플로잇 템플릿]으로 직접 검증해볼 수 있습니다.",
        ],
    },
    {
        "id": "ssti",
        "title": "SSTI: 템플릿 문자열로 서버 내부 값 읽어내기",
        "difficulty": "중급",
        "situation": "인사말 미리보기 기능이 사용자가 입력한 템플릿 문자열을 서버 내부 컨텍스트와 함께 그대로 렌더링합니다. 의도된 사용법은 {user[name]} 같은 값을 보여주는 것이지만, 컨텍스트에는 그보다 훨씬 많은 것이 들어있습니다.",
        "endpoint": "POST /api/web-arena/ssti/render { template }",
        "hints": [
            "먼저 정상적인 사용법인 'Hello, {user[name]}!' 을 넣어 어떻게 렌더링되는지 확인하세요.",
            "이 서버는 Python의 str.format()을 사용자 입력에 그대로 적용합니다 — {key} 나 {key[subkey]} 형식으로 컨텍스트에 있는 아무 값이나 참조할 수 있습니다.",
            "컨텍스트에 user 말고 다른 키가 더 있을 수 있습니다. secret_config 같은 이름을 추측해서 넣어보세요.",
            "형식은 {바깥키[안쪽키]} 입니다 — 따옴표 없이 그대로 씁니다 (예: {secret_config[flag]}).",
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


# ---- SSRF ---------------------------------------------------------------

_SSRF_INTERNAL_HEADER = "X-Internal-Fetcher"
_SSRF_INTERNAL_TOKEN = "web-arena-proxy-v1"
_SSRF_BLOCKED_HOSTS = ("169.254.169.254",)  # 실제 클라우드 메타데이터 IP는 방어적으로 차단


def ssrf_fetch(url: str) -> dict:
    if any(blocked in url for blocked in _SSRF_BLOCKED_HOSTS):
        return {"error": "이 대상은 차단되어 있습니다."}
    # 의도적 취약점: 사용자가 준 URL을 검증 없이 서버가 대신 요청한다 (링크 미리보기 기능).
    try:
        req = urllib.request.Request(url, headers={_SSRF_INTERNAL_HEADER: _SSRF_INTERNAL_TOKEN})
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read(2000).decode(errors="replace")
        return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read(500).decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def ssrf_internal_metadata(internal_header: str | None) -> dict:
    # 이 엔드포인트는 원래 내부망에서만 접근 가능해야 하는 API를 흉내낸다.
    # 데모 편의상 '내부 요청'인지는 ssrf_fetch가 심어주는 특수 헤더로만 판별한다.
    if internal_header != _SSRF_INTERNAL_TOKEN:
        return {"error": "이 엔드포인트는 내부 네트워크에서만 접근 가능합니다."}
    return {"service": "internal-metadata", "flag": FLAGS["ssrf"]}


# ---- JWT ------------------------------------------------------------------

JWT_SECRET = "changeme123"  # 의도적으로 흔한/약한 시크릿


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict, secret: str) -> str:
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def jwt_decode_verify(token: str, secret: str) -> dict | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig_b64 = _b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None
    try:
        return json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None


def jwt_login(username: str) -> dict:
    # 게스트/일반 사용자는 항상 role=user로만 발급된다.
    token = jwt_encode({"username": username, "role": "user"}, JWT_SECRET)
    return {"token": token}


def jwt_check_admin(token: str) -> dict:
    # 의도적 취약점: 시크릿이 약해서 무차별 대입/추측이 가능하다.
    payload = jwt_decode_verify(token, JWT_SECRET)
    if payload is None:
        return {"error": "서명이 유효하지 않습니다."}
    if payload.get("role") != "admin":
        return {"error": "관리자 권한이 아닙니다.", "payload": payload}
    return {"payload": payload, "flag": FLAGS["jwt"]}


# ---- SSTI -------------------------------------------------------------

def ssti_render(template: str) -> dict:
    # 의도적 취약점: 사용자 입력을 Python str.format()에 그대로 적용한다.
    # 컨텍스트는 일부러 순수 dict/문자열/정수만 담아 __globals__ 체인으로 이어지는
    # 진짜 코드 실행(RCE)까지는 불가능하게 막아두었다 — 이 챌린지는 정보 노출까지만 재현한다.
    context = {
        "user": {"name": "guest", "role": "user"},
        "secret_config": {"flag": FLAGS["ssti"], "db_password": "s3cr3t_db_pw"},
    }
    try:
        rendered = template.format(**context)
        return {"rendered": rendered}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ---- 공유 스코어보드 (팀/친구와 같은 서버에 접속해 같이 연습할 때 사용) -----------

_scoreboard_lock = threading.Lock()
SCOREBOARD: dict[str, dict[str, float]] = {}


def submit_flag(name: str, challenge_id: str, flag: str) -> dict:
    expected = FLAGS.get(challenge_id)
    if expected is None:
        return {"correct": False, "error": "Unknown challenge"}
    correct = flag.strip() == expected
    if correct:
        with _scoreboard_lock:
            SCOREBOARD.setdefault(name, {})
            SCOREBOARD[name].setdefault(challenge_id, time.time())
    return {"correct": correct}


def get_scoreboard() -> list[dict]:
    with _scoreboard_lock:
        rows = []
        for name, solved in SCOREBOARD.items():
            rows.append({"name": name, "solved": solved, "count": len(solved)})
    rows.sort(key=lambda r: (-r["count"], min(r["solved"].values()) if r["solved"] else 0))
    return rows
