from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from services import web_arena

router = APIRouter(prefix="/api/web-arena", tags=["web-arena"])


@router.get("/challenges")
async def list_challenges():
    return {"challenges": web_arena.CHALLENGE_META}


class SqliLoginRequest(BaseModel):
    username: str
    password: str


@router.post("/sqli/login")
async def sqli_login(request: SqliLoginRequest):
    return web_arena.sqli_login(request.username, request.password)


class IdorLoginRequest(BaseModel):
    username: str


@router.post("/idor/login")
async def idor_login(request: IdorLoginRequest):
    if not request.username.strip():
        raise HTTPException(status_code=400, detail="username is required")
    return web_arena.idor_login(request.username.strip())


@router.get("/idor/orders/{order_id}")
async def idor_get_order(order_id: int, authorization: str | None = Header(None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    username = web_arena.is_valid_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="유효하지 않은 세션입니다. 먼저 로그인하세요.")
    order = web_arena.idor_get_order(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다.")
    return order


@router.get("/xss/search", response_class=HTMLResponse)
async def xss_search(q: str = ""):
    return web_arena.xss_search(q)


@router.get("/ssrf/fetch")
def ssrf_fetch(url: str):
    # 일부러 async def가 아닌 일반 def로 선언한다: FastAPI는 일반 def 경로 함수를
    # 자동으로 스레드풀에서 실행하므로, urllib의 블로킹 호출이 이 서버 자신을
    # 다시 호출할 때도(자기 참조 SSRF) 메인 이벤트 루프를 막지 않는다.
    return web_arena.ssrf_fetch(url)


@router.get("/ssrf/internal-metadata")
def ssrf_internal_metadata(x_internal_fetcher: str | None = Header(None)):
    return web_arena.ssrf_internal_metadata(x_internal_fetcher)


class JwtLoginRequest(BaseModel):
    username: str


@router.post("/jwt/login")
async def jwt_login(request: JwtLoginRequest):
    if not request.username.strip():
        raise HTTPException(status_code=400, detail="username is required")
    return web_arena.jwt_login(request.username.strip())


@router.get("/jwt/admin")
async def jwt_admin(authorization: str | None = Header(None)):
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authorization 헤더가 필요합니다.")
    return web_arena.jwt_check_admin(token)


class SstiRenderRequest(BaseModel):
    template: str


@router.post("/ssti/render")
async def ssti_render(request: SstiRenderRequest):
    return web_arena.ssti_render(request.template)


class BflaLoginRequest(BaseModel):
    username: str


@router.post("/bfla/login")
async def bfla_login(request: BflaLoginRequest):
    if not request.username.strip():
        raise HTTPException(status_code=400, detail="username is required")
    return web_arena.bfla_login(request.username.strip())


class BflaDeleteRequest(BaseModel):
    token: str
    target_username: str


@router.post("/bfla/delete-user")
async def bfla_delete_user(request: BflaDeleteRequest):
    return web_arena.bfla_delete_user(request.token, request.target_username)


@router.post("/massassign/register")
async def massassign_register(request: Request):
    # 일부러 고정된 Pydantic 스키마를 쓰지 않는다: 실제 Mass Assignment 취약점은 서버가 "어떤 필드가
    # 들어올지 미리 정해두지 않고" 클라이언트가 보낸 JSON을 그대로 받아들이는 데서 생기기 때문에,
    # username 외에 어떤 필드가 오든(role, is_admin 등) 그대로 전달되는 상황을 재현해야 한다.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="유효한 JSON이 아닙니다.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="유효한 JSON 객체가 아닙니다.")
    username = str(body.get("username", "")).strip()
    if not username:
        raise HTTPException(status_code=400, detail="username is required")
    extra_fields = {k: v for k, v in body.items() if k != "username"}
    return web_arena.massassign_register(username, extra_fields)


@router.get("/massassign/profile")
async def massassign_profile(username: str = ""):
    return web_arena.massassign_profile(username)


class VerifyRequest(BaseModel):
    challenge_id: str
    flag: str


@router.post("/verify")
async def verify_flag(request: VerifyRequest):
    expected = web_arena.FLAGS.get(request.challenge_id)
    if expected is None:
        raise HTTPException(status_code=404, detail="Unknown challenge")
    return {"correct": request.flag.strip() == expected}


class ScoreboardSubmitRequest(BaseModel):
    name: str
    challenge_id: str
    flag: str


@router.post("/scoreboard/submit")
async def scoreboard_submit(request: ScoreboardSubmitRequest):
    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="이름을 입력하세요.")
    return web_arena.submit_flag(name, request.challenge_id, request.flag)


@router.get("/scoreboard")
async def scoreboard():
    return {"rows": web_arena.get_scoreboard()}
