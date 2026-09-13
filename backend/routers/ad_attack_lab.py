from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services import ad_attack_lab

router = APIRouter(prefix="/api/ad-attack-lab", tags=["ad-attack-lab"])


@router.get("/stages")
async def get_stages():
    return {"stages": ad_attack_lab.STAGES, "roe": ad_attack_lab.ROE_NOTICE, "domain": ad_attack_lab.DOMAIN}


@router.get("/recon")
async def recon(query: str = "all"):
    return {"output": ad_attack_lab.recon(query)}


class KerberoastRequest(BaseModel):
    spn: str


@router.post("/kerberoast")
async def kerberoast(request: KerberoastRequest):
    return ad_attack_lab.kerberoast(request.spn)


class AsrepRequest(BaseModel):
    username: str


@router.post("/asrep-roast")
async def asrep_roast(request: AsrepRequest):
    return ad_attack_lab.asrep_roast(request.username)


class CrackRequest(BaseModel):
    account: str
    password_guess: str


@router.post("/crack")
async def crack(request: CrackRequest):
    return ad_attack_lab.crack(request.account, request.password_guess)


class DcsyncRequest(BaseModel):
    username: str
    password: str


@router.post("/dcsync")
async def dcsync(request: DcsyncRequest):
    return ad_attack_lab.dcsync(request.username, request.password)


class VerifyRequest(BaseModel):
    flag: str


@router.post("/verify")
async def verify(request: VerifyRequest):
    return ad_attack_lab.verify_flag(request.flag)


@router.get("/wordlist", response_class=PlainTextResponse)
async def wordlist():
    return "\n".join(ad_attack_lab.WORDLIST)


@router.get("/exploit-template", response_class=PlainTextResponse)
async def exploit_template():
    return ad_attack_lab.EXPLOIT_TEMPLATE
