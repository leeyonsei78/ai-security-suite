from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.pwn_lab import CHALLENGES, LAB_SETUP, FLAGS, get_challenge

router = APIRouter(prefix="/api/pwn-lab", tags=["pwn-lab"])


@router.get("/challenges")
async def list_challenges():
    return {"challenges": CHALLENGES, "lab_setup": LAB_SETUP}


@router.get("/challenges/{challenge_id}/source", response_class=PlainTextResponse)
async def download_source(challenge_id: str):
    challenge = get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge["source_code"]


@router.get("/dockerfile", response_class=PlainTextResponse)
async def download_dockerfile():
    return LAB_SETUP["dockerfile"]


class VerifyRequest(BaseModel):
    challenge_id: str
    flag: str


@router.post("/verify")
async def verify_flag(request: VerifyRequest):
    expected = FLAGS.get(request.challenge_id)
    if expected is None:
        raise HTTPException(status_code=404, detail="Unknown challenge")
    return {"correct": request.flag.strip() == expected}
