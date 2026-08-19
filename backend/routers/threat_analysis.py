from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from services.threat_analysis_service import analyze, chat

router = APIRouter(prefix="/api/threat", tags=["threat_analysis"])

_sessions: dict[int, dict] = {}
_next_id = 1


class AnalyzeRequest(BaseModel):
    analysis_type: str
    input_data: str
    context: Optional[str] = ""


class ChatRequest(BaseModel):
    session_id: int
    message: str


@router.post("/analyze")
async def run_analyze(req: AnalyzeRequest):
    global _next_id
    if not req.input_data.strip():
        raise HTTPException(status_code=400, detail="input_data required")
    valid_types = {"malware", "forensics", "memory", "threat_intel"}
    if req.analysis_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"analysis_type must be one of {valid_types}")

    result = analyze(req.analysis_type, req.input_data, req.context or "")
    session_id = _next_id
    _next_id += 1
    _sessions[session_id] = {
        "id": session_id,
        "analysis_type": req.analysis_type,
        "input_data": req.input_data,
        "summary": result.get("summary", ""),
        "chat_history": [],
    }
    return {"session_id": session_id, **result}


@router.post("/chat")
async def run_chat(req: ChatRequest):
    session = _sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Empty message")

    reply = chat(
        session["analysis_type"],
        session["summary"],
        session["chat_history"],
        req.message,
    )
    session["chat_history"].append({"role": "user", "content": req.message})
    session["chat_history"].append({"role": "assistant", "content": reply})
    return {"reply": reply}


@router.delete("/sessions")
async def clear_sessions():
    _sessions.clear()
    return {"message": "Cleared"}
