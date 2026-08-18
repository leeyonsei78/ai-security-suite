from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.ioc_service import analyze_ioc

router = APIRouter(prefix="/api/ioc", tags=["ioc"])

history: list[dict] = []


class AnalyzeRequest(BaseModel):
    content: str


@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if len(request.content) > 10000:
        raise HTTPException(status_code=400, detail="Too many IoCs")

    results = analyze_ioc(request.content)
    if not results:
        raise HTTPException(status_code=400, detail="No valid IoCs found")

    entry = {"id": len(history) + 1, "results": results, "total": len(results)}
    history.append(entry)
    return entry


@router.get("/history")
async def get_history():
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history():
    history.clear()
    return {"message": "Cleared"}
