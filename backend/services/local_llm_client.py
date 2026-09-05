"""사내 폐쇄망에 구성된 로컬 LLM(Ollama/vLLM/LM Studio/text-generation-webui 등,
OpenAI 호환 `/v1/chat/completions` 엔드포인트를 제공하는 서버라면 전부 해당)을 호출한다.

각 앱의 Claude 시스템 프롬프트를 그대로 재사용할 수 있도록 `call_local_llm()`의
시그니처를 `anthropic.Anthropic().messages.create()` 호출부와 최대한 비슷하게 맞췄다 —
vulnerability_service처럼 "cloud면 anthropic, local이면 이 함수" 두 줄만 갈아끼우면 되게.
"""
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

_BASE_URL = os.getenv("LOCAL_LLM_BASE_URL", "").strip().rstrip("/")
_MODEL = os.getenv("LOCAL_LLM_MODEL", "").strip() or "llama3.1"
_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "").strip()


class LocalLLMError(RuntimeError):
    pass


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if _API_KEY:
        h["Authorization"] = f"Bearer {_API_KEY}"
    return h


def call_local_llm(system_prompt: str, user_prompt: str, max_tokens: int = 2048, temperature: float = 0.2) -> str:
    """동기 호출 — 각 서비스 모듈의 기존 동기 `_real_analyze()` 안에서 anthropic 클라이언트
    호출과 같은 자리에 바로 끼워 넣을 수 있게 일부러 동기로 만들었다."""
    if not _BASE_URL:
        raise LocalLLMError("LOCAL_LLM_BASE_URL이 설정되지 않았습니다.")

    payload = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    try:
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(f"{_BASE_URL}/chat/completions", headers=_headers(), json=payload)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        raise LocalLLMError(f"로컬 LLM 호출 실패 ({_BASE_URL}): {e}") from e

    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise LocalLLMError(f"로컬 LLM 응답 형식이 예상과 다릅니다: {data}") from e
