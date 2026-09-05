"""여러 앱의 붙여넣기 textarea에 공용으로 쓰이는 파일 업로드 → 텍스트 추출 엔드포인트.
txt/csv/json 같은 텍스트 파일과 docx/pdf/xlsx 같은 바이너리 문서를 모두 받아 순수 텍스트로
변환해 반환한다 — 원본 파일은 서버에 저장하지 않는다."""
from fastapi import APIRouter, HTTPException, UploadFile, File
from services.file_extract import extract_text, ExtractError

router = APIRouter(prefix="/api", tags=["extract"])

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20MB


@router.post("/extract-text")
async def extract_text_endpoint(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="파일이 너무 큽니다 (최대 20MB)")
    try:
        result = extract_text(file.filename or "", raw)
    except ExtractError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"파일을 처리하지 못했습니다: {e}")
    return {"filename": file.filename, **result}
