from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.policy_service import generate_policy, generate_markdown_report
from services.policy_guide import POLICY_PREP_GUIDE, ENVIRONMENT_RECON

router = APIRouter(prefix="/api/policy", tags=["security-policy"])

history: list[dict] = []

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
        "id": len(history) + 1,
        "environment_type": request.environment_type,
        "compliance": request.compliance,
        "preview": request.description[:100].replace("\n", " "),
        **result,
    }
    history.append(entry)
    return entry


@router.get("/history")
async def get_history():
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    history.clear()
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int):
    entry = next((h for h in history if h["id"] == entry_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return generate_markdown_report(entry)
