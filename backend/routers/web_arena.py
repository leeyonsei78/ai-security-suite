from fastapi import APIRouter, Header, HTTPException
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


class VerifyRequest(BaseModel):
    challenge_id: str
    flag: str


@router.post("/verify")
async def verify_flag(request: VerifyRequest):
    expected = web_arena.FLAGS.get(request.challenge_id)
    if expected is None:
        raise HTTPException(status_code=404, detail="Unknown challenge")
    return {"correct": request.flag.strip() == expected}
