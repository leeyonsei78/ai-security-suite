from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services.phishing_sim_service import (
    generate_phishing_sim, generate_markdown_report, SCENARIO_LABELS, DIFFICULTY_LABELS,
)
from services import db

router = APIRouter(prefix="/api/phishing-sim", tags=["phishing-sim"])

APP_NAME = "phishing_sim"

VALID_SCENARIOS = set(SCENARIO_LABELS.keys())
VALID_DIFFICULTIES = set(DIFFICULTY_LABELS.keys())


class GenerateRequest(BaseModel):
    scenario_type: str = "it_password_reset"
    difficulty: str = "beginner"
    context: str = ""


@router.get("/scenarios")
async def get_scenarios():
    return {
        "scenarios": [{"id": k, "label": v} for k, v in SCENARIO_LABELS.items()],
        "difficulties": [{"id": k, "label": v} for k, v in DIFFICULTY_LABELS.items()],
    }


@router.post("/generate")
async def generate(request: GenerateRequest):
    if request.scenario_type not in VALID_SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Invalid scenario_type, must be one of {sorted(VALID_SCENARIOS)}")
    if request.difficulty not in VALID_DIFFICULTIES:
        raise HTTPException(status_code=400, detail=f"Invalid difficulty, must be one of {sorted(VALID_DIFFICULTIES)}")
    if len(request.context) > 2000:
        raise HTTPException(status_code=400, detail="Context too long (max 2,000 chars)")

    result = generate_phishing_sim(request.scenario_type, request.difficulty, request.context)
    entry = {**result}
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
