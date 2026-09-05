from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.incident_service import create_plan, chat_response
from services import db

router = APIRouter(prefix="/api/incident", tags=["incident"])

APP_NAME = "incident"


class PlanRequest(BaseModel):
    incident_type: str
    severity: str = "HIGH"
    description: str


class ChatRequest(BaseModel):
    session_id: int
    message: str


@router.post("/create")
async def create(request: PlanRequest):
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Description required")

    plan = await create_plan(request.incident_type, request.severity, request.description)
    session_data = {
        "incident_type": request.incident_type,
        "severity": request.severity,
        "description": request.description,
        "plan": plan,
        "chat_history": [],
    }
    session_id = db.add_entry(APP_NAME, session_data)
    return {"session_id": session_id, **plan}


@router.post("/chat")
async def chat(request: ChatRequest):
    session = db.get_entry(APP_NAME, request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Empty message")

    reply = await chat_response(
        session["incident_type"], session["severity"],
        session["description"], session["chat_history"], request.message,
    )
    session["chat_history"].append({"role": "user", "content": request.message})
    session["chat_history"].append({"role": "assistant", "content": reply})
    db.update_entry(APP_NAME, request.session_id, session)
    return {"reply": reply}


@router.get("/sessions")
async def list_sessions():
    return {"sessions": [
        {"id": s["id"], "incident_type": s["incident_type"],
         "severity": s["severity"], "description": s["description"][:80]}
        for s in db.get_history(APP_NAME)
    ]}


@router.delete("/sessions")
async def clear_sessions():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
