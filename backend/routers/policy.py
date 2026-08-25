from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.policy_service import generate_policy, generate_markdown_report
from services.policy_guide import POLICY_PREP_GUIDE, ENVIRONMENT_RECON
from services import db

router = APIRouter(prefix="/api/policy", tags=["security-policy"])

APP_NAME = "policy"

VALID_ENV_TYPES = {"web_server", "cloud", "internal_network", "container", "database"}


class GenerateRequest(BaseModel):
    environment_type: str = "web_server"
    compliance: list[str] = []
    description: str


@router.get("/guide")
async def get_guide():
    return {**POLICY_PREP_GUIDE, "environment_recon": ENVIRONMENT_RECON}


@router.post("/generate")
async def generate(request: GenerateRequest):
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Empty description")
    if len(request.description) > 10000:
        raise HTTPException(status_code=400, detail="Description too long (max 10,000 chars)")
    if request.environment_type not in VALID_ENV_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid environment_type, must be one of {sorted(VALID_ENV_TYPES)}")

    result = generate_policy(request.environment_type, request.compliance, request.description)
    entry = {
        "environment_type": request.environment_type,
        "compliance": request.compliance,
        "preview": request.description[:100].replace("\n", " "),
        **result,
    }
    entry["id"] = db.add_entry(APP_NAME, entry)
    return entry


@router.get("/history")
async def get_history():
    history = db.get_history(APP_NAME)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int):
    entry = db.get_entry(APP_NAME, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return generate_markdown_report(entry)
