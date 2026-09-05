from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from services.threat_analysis_service import analyze, chat
from services.threat_collection_guide import COLLECTION_GUIDE
from services import db

router = APIRouter(prefix="/api/threat", tags=["threat_analysis"])

APP_NAME = "threat_analysis"


class AnalyzeRequest(BaseModel):
    analysis_type: str
    input_data: str
    context: Optional[str] = ""


class ChatRequest(BaseModel):
    session_id: int
    message: str


@router.get("/guide")
async def get_guide():
    return {"collection_guide": COLLECTION_GUIDE}


@router.post("/analyze")
async def run_analyze(req: AnalyzeRequest):
    if not req.input_data.strip():
        raise HTTPException(status_code=400, detail="input_data required")
    valid_types = {"malware", "forensics", "memory", "threat_intel"}
    if req.analysis_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"analysis_type must be one of {valid_types}")

    result = await analyze(req.analysis_type, req.input_data, req.context or "")
    session_data = {
        "analysis_type": req.analysis_type,
        "input_data": req.input_data,
        "summary": result.get("summary", ""),
        "chat_history": [],
    }
    session_id = db.add_entry(APP_NAME, session_data)
    return {"session_id": session_id, **result}


@router.post("/chat")
async def run_chat(req: ChatRequest):
    session = db.get_entry(APP_NAME, req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Empty message")

    reply = await chat(
        session["analysis_type"],
        session["summary"],
        session["chat_history"],
        req.message,
    )
    session["chat_history"].append({"role": "user", "content": req.message})
    session["chat_history"].append({"role": "assistant", "content": reply})
    db.update_entry(APP_NAME, req.session_id, session)
    return {"reply": reply}


@router.delete("/sessions")
async def clear_sessions():
    db.clear_history(APP_NAME)
    return {"message": "Cleared"}
