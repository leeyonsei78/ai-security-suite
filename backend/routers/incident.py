from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.incident_service import create_plan, chat_response

router = APIRouter(prefix="/api/incident", tags=["incident"])

sessions: dict[int, dict] = {}
_next_id = 1


class PlanRequest(BaseModel):
    incident_type: str
    severity: str = "HIGH"
    description: str


class ChatRequest(BaseModel):
    session_id: int
    message: str


@router.post("/create")
async def create(request: PlanRequest):
    global _next_id
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Description required")

    plan = create_plan(request.incident_type, request.severity, request.description)
    session_id = _next_id
    _next_id += 1
    sessions[session_id] = {
        "id": session_id,
        "incident_type": request.incident_type,
        "severity": request.severity,
        "description": request.description,
        "plan": plan,
        "chat_history": [],
    }
    return {"session_id": session_id, **plan}


@router.post("/chat")
async def chat(request: ChatRequest):
    session = sessions.get(request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Empty message")

    reply = chat_response(
        session["incident_type"], session["severity"],
        session["description"], session["chat_history"], request.message,
    )
    session["chat_history"].append({"role": "user", "content": request.message})
    session["chat_history"].append({"role": "assistant", "content": reply})
    return {"reply": reply}


@router.get("/sessions")
async def list_sessions():
    return {"sessions": [
        {"id": s["id"], "incident_type": s["incident_type"],
         "severity": s["severity"], "description": s["description"][:80]}
        for s in sessions.values()
    ]}


@router.delete("/sessions")
async def clear_sessions():
    sessions.clear()
    return {"message": "Cleared"}
