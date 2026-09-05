"""전 앱 공용 "실행 모드" 관리자 — 폐쇄망(인터넷 차단) 환경 지원을 위해 도입.

AI 기반 앱(App 3 등)의 분석 백엔드를 4가지로 정의한다:
  - cloud:   Claude Cloud API (기존 LIVE)
  - local:   사내에 구성한 로컬 LLM (Ollama/vLLM/LM Studio 등 OpenAI 호환 서버)
  - offline: 규칙/정규식 기반 결정론적 분석 엔진 — 네트워크 호출 전혀 없음(폐쇄망 기본값)
  - mock:    기존 방식의 샘플/데모 데이터 — 실제 분석이 아니라 도구 사용법을 익히기 위한
             학습용 모드로 명시적으로만 선택 가능(자동 감지 대상 아님)

우선순위(자동 감지, override 없을 때): cloud(설정+도달 가능) > local(설정+도달 가능) > offline.
mock은 사용자가 명시적으로 선택했을 때만 쓰인다 — 실제 운영에서 조용히 "가짜 분석"으로
빠지는 걸 막기 위함.

CVE 조회(App 15)처럼 Claude를 아예 안 쓰고 외부 실시간 API(NVD 등)에만 의존하는 앱은
`get_external_api_mode()`로 별도의 online/offline 축을 재사용한다(App 21 DNS 보안 점검 등
향후 확장 대상도 동일 패턴 적용 가능).
"""
import json
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()

_ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
_LOCAL_LLM_BASE_URL = os.getenv("LOCAL_LLM_BASE_URL", "").strip().rstrip("/")
_LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "").strip()
_LOCAL_LLM_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "").strip()

_OVERRIDES_PATH = Path(__file__).resolve().parent.parent / "data" / "mode_overrides.json"

AI_MODES = ("cloud", "local", "offline", "mock")

_REACHABILITY_TTL = 30.0  # seconds — 매 요청마다 네트워크 체크하지 않도록 캐시
_reachability_cache: dict[str, tuple[float, bool]] = {}


def has_cloud_key() -> bool:
    return bool(_ANTHROPIC_API_KEY) and _ANTHROPIC_API_KEY != "your_anthropic_api_key_here"


def has_local_llm_config() -> bool:
    return bool(_LOCAL_LLM_BASE_URL)


def local_llm_info() -> dict:
    return {"base_url": _LOCAL_LLM_BASE_URL or None, "model": _LOCAL_LLM_MODEL or None}


def _local_llm_headers() -> dict:
    return {"Authorization": f"Bearer {_LOCAL_LLM_API_KEY}"} if _LOCAL_LLM_API_KEY else {}


async def _probe(url: str, headers: dict | None = None, timeout: float = 2.0) -> bool:
    """호스트에 어떤 형태로든 HTTP 응답이 오면 '도달 가능'으로 간주한다(401/404도 OK) —
    실제로 원하는 건 그 엔드포인트의 정상 동작이 아니라 네트워크 경로 자체의 생사 여부다."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            await client.get(url, headers=headers or {})
        return True
    except Exception:
        return False


async def is_host_reachable(cache_key: str, url: str, headers: dict | None = None, force: bool = False) -> bool:
    now = time.time()
    cached = _reachability_cache.get(cache_key)
    if not force and cached and (now - cached[0]) < _REACHABILITY_TTL:
        return cached[1]
    ok = await _probe(url, headers=headers)
    _reachability_cache[cache_key] = (now, ok)
    return ok


async def is_cloud_reachable(force: bool = False) -> bool:
    if not has_cloud_key():
        return False
    return await is_host_reachable("cloud", "https://api.anthropic.com/", force=force)


async def is_local_llm_reachable(force: bool = False) -> bool:
    if not has_local_llm_config():
        return False
    return await is_host_reachable(
        "local", f"{_LOCAL_LLM_BASE_URL}/models", headers=_local_llm_headers(), force=force
    )


# ---- override 저장(선택한 모드를 서버 재시작에도 유지) ----

def _load_overrides() -> dict:
    try:
        with open(_OVERRIDES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_overrides(data: dict) -> None:
    _OVERRIDES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_OVERRIDES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def get_override(key: str) -> str | None:
    return _load_overrides().get(key)


def set_override(key: str, value: str | None) -> None:
    data = _load_overrides()
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    _save_overrides(data)


# ---- AI 모드(cloud/local/offline/mock) ----

async def get_ai_mode() -> str:
    override = get_override("ai")
    if override == "mock":
        return "mock"
    if override == "offline":
        return "offline"
    if override == "cloud" and has_cloud_key():
        return "cloud"
    if override == "local" and has_local_llm_config():
        return "local"
    # override가 없거나(자동) 무효(예: cloud로 지정했는데 키가 없음) 하면 자동 감지로 폴백
    if has_cloud_key() and await is_cloud_reachable():
        return "cloud"
    if has_local_llm_config() and await is_local_llm_reachable():
        return "local"
    return "offline"


def set_ai_override(mode: str | None) -> None:
    if mode is not None and mode not in AI_MODES:
        raise ValueError(f"invalid mode: {mode}")
    set_override("ai", mode)


async def get_ai_status() -> dict:
    cloud_configured = has_cloud_key()
    local_configured = has_local_llm_config()
    cloud_reachable = await is_cloud_reachable() if cloud_configured else False
    local_reachable = await is_local_llm_reachable() if local_configured else False
    effective = await get_ai_mode()
    llm_info = local_llm_info()
    return {
        "effective_mode": effective,
        "override": get_override("ai"),
        "modes": {
            "cloud": {
                "label": "Claude Cloud", "configured": cloud_configured, "reachable": cloud_reachable,
                "selectable": cloud_configured,
            },
            "local": {
                "label": "로컬 LLM", "configured": local_configured, "reachable": local_reachable,
                "selectable": local_configured, "base_url": llm_info["base_url"], "model": llm_info["model"],
            },
            "offline": {
                "label": "오프라인 규칙 기반 (폐쇄망)", "configured": True, "reachable": True, "selectable": True,
            },
            "mock": {
                "label": "Mock 데모 (학습용)", "configured": True, "reachable": True, "selectable": True,
            },
        },
    }


# ---- 외부 실시간 API 의존 앱(App 15 CVE 조회 등)용 online/offline 축 ----

async def get_external_api_mode(key: str, url: str, headers: dict | None = None) -> str:
    override = get_override(key)
    if override == "offline":
        return "offline"
    if override == "online":
        return "online"
    return "online" if await is_host_reachable(key, url, headers=headers) else "offline"


def set_external_api_override(key: str, mode: str | None) -> None:
    if mode is not None and mode not in ("online", "offline"):
        raise ValueError(f"invalid mode: {mode}")
    set_override(key, mode)
