import csv
import io
import os
import json
import re
import httpx
from dotenv import load_dotenv
from services.mock_ioc import generate_mock_ioc, detect_type
from services.ioc_offline_engine import analyze_offline
from services import mode_manager, local_llm_client, claude_cli_client, usage_log

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a threat intelligence analyst. Analyze each provided Indicator of Compromise (IoC).

For each IoC in the list, respond with a JSON array where each element has this structure:
{
  "ioc": "the exact IoC value",
  "ioc_type": "ip|domain|hash|email|unknown",
  "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN",
  "confidence": 0-100,
  "category": "brief category (e.g. C2 서버, 피싱 도메인, 랜섬웨어, 봇넷, 정상 IP)",
  "description": "why this IoC is suspicious or clean — be specific",
  "tags": ["tag1", "tag2"],
  "recommendation": "what action to take"
}

Verdict guide:
- MALICIOUS (80-100 confidence): confirmed threat
- SUSPICIOUS (40-79): some red flags, needs investigation
- CLEAN (80-100): no known threat
- UNKNOWN: cannot determine

Respond ONLY with the JSON array, no other text."""


_REFORMAT_SYSTEM_PROMPT = (
    "You are a data reformatting tool. Convert the analyst write-up into a JSON array with exactly one "
    "element per indicator, in this schema: "
    '{"ioc": "...", "ioc_type": "ip|domain|hash|email|unknown", '
    '"verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN", "confidence": <integer 0-100>, "category": "...", '
    '"description": "...", "tags": ["..."], "recommendation": "..."}. Output ONLY the JSON.'
)

_VERDICT_KEYWORDS = [
    (("malicious", "phishing", "confirmed threat", "compromise", "malware", "c2 "), "MALICIOUS"),
    (("suspicious", "anonymiz", "typosquat", "caution", "risk", "flag"), "SUSPICIOUS"),
    (("benign", "clean", "placeholder", "safe", "non-actionable", "not a real", "reserved"), "CLEAN"),
]

_CONFIDENCE_WORDS = {
    "high": 85, "medium-high": 65, "medium": 50, "low-medium": 40, "low": 25,
    "n/a": 0, "none": 0, "unknown": 0,
}


def _normalize_verdict(raw) -> str:
    if not raw:
        return "UNKNOWN"
    text = str(raw).strip().upper()
    if text in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"):
        return text
    low = str(raw).lower()
    for keywords, verdict in _VERDICT_KEYWORDS:
        if any(k in low for k in keywords):
            return verdict
    return "UNKNOWN"


def _normalize_confidence(raw) -> int:
    if isinstance(raw, (int, float)):
        return max(0, min(100, int(raw)))
    if isinstance(raw, str):
        key = raw.strip().lower()
        if key in _CONFIDENCE_WORDS:
            return _CONFIDENCE_WORDS[key]
        digits = re.search(r"\d+", raw)
        if digits:
            return max(0, min(100, int(digits.group())))
    return 0


def _pick(item: dict, candidates: list[str], default=""):
    for key in candidates:
        if key in item and item[key]:
            return item[key]
    return default


def _find_item_array(data):
    """claude_cli의 2차 변환 결과가 배열 그대로일 수도, {"indicators": [...]}처럼 감싸져
    있을 수도 있다(실측 확인) — 어떤 키로 감쌌든 dict로 이루어진 첫 배열을 찾는다."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                return v
    return []


def _extract_json_blob(text: str):
    start_candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    start = min(start_candidates) if start_candidates else -1
    end = max(text.rfind("}"), text.rfind("]")) + 1
    if start == -1 or end <= start:
        raise ValueError(f"응답에서 JSON 구조를 찾지 못했습니다: {text[:200]}")
    return json.loads(text[start:end])


def _call_claude_cli_retry(system_prompt: str, user_prompt: str, attempts: int = 2) -> str:
    """Claude Code CLI는 --output-format json을 줘도 이따금(비결정적으로) JSON 래퍼 없이
    순수 산문으로만 응답할 때가 있다(실측 확인 — 같은 호출을 반복해보면 어떤 시도는 정상
    래핑되고 어떤 시도는 안 됨). 한 번 실패로 바로 오프라인 폴백까지 가지 않도록, 실패 시
    같은 요청을 한 번 더 재시도한다."""
    last_error = None
    for _ in range(attempts):
        try:
            return claude_cli_client.call_claude_cli(system_prompt, user_prompt)
        except claude_cli_client.ClaudeCliError as e:
            last_error = e
    raise last_error


def _analyze_via_claude_cli(iocs: list[str]) -> list[dict]:
    """Claude Code CLI 헤드리스 모드는 아무리 강하게 지시해도(7가지 프롬프트 변형으로 실측)
    정확한 스키마의 순수 JSON을 내놓지 않는다 — 항상 자기 방식의 필드명과 산문 설명으로
    응답한다. 대신 1차로 자유 서술 분석을 받고, 2차로 그 서술을 JSON으로 "변환"해달라고
    별도 요청한 뒤(이것도 정확한 필드명은 안 지키지만 최소한 유효한 JSON 구조는 안정적으로
    내놓음), 필드명·판정 문구·신뢰도 표현을 관대하게 정규화한다. 호출 2번이라 cloud/local보다
    느리고(각 10~30초) 비용도 2배지만, 그래도 API 크레딧 대비 저렴하다(개발 중 실측 1회당
    총 $0.01 안팎). 두 호출 모두 비결정적으로 실패할 수 있어(위 _call_claude_cli_retry 참고)
    각각 한 번씩 재시도한다."""
    ioc_list = "\n".join(f"- {v} (type: {detect_type(v)})" for v in iocs)
    analysis_text = _call_claude_cli_retry(SYSTEM_PROMPT, f"Analyze these IoCs:\n{ioc_list}")

    reformat_user = (
        f"Indicators analyzed (in this order): {', '.join(iocs)}\n\nAnalyst write-up to convert:\n{analysis_text}"
    )
    reformatted_text = _call_claude_cli_retry(_REFORMAT_SYSTEM_PROMPT, reformat_user)
    items = _find_item_array(_extract_json_blob(reformatted_text))

    results = []
    for i, ioc in enumerate(iocs):
        item = items[i] if i < len(items) else {}
        description = _pick(item, ["description", "reasoning", "implication"])
        if isinstance(description, list):
            description = " ".join(str(x) for x in description)
        tags = item.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)]
        results.append({
            "ioc": _pick(item, ["ioc", "indicator"], ioc) or ioc,
            "ioc_type": _pick(item, ["ioc_type", "type"], detect_type(ioc)),
            "verdict": _normalize_verdict(_pick(item, ["verdict", "assessment"])),
            "confidence": _normalize_confidence(_pick(item, ["confidence"])),
            "category": _pick(item, ["category"], "일반"),
            "description": description or "",
            "tags": [str(t) for t in tags],
            "recommendation": _pick(item, ["recommendation", "recommended_action"], ""),
        })
    return results


def _real_analyze(iocs: list[str], backend: str = "cloud") -> list[dict]:
    if backend == "claude_cli":
        return _analyze_via_claude_cli(iocs)

    ioc_list = "\n".join(f"- {v} (type: {detect_type(v)})" for v in iocs)
    user_prompt = f"Analyze these IoCs:\n{ioc_list}"

    if backend == "local":
        text = local_llm_client.call_local_llm(SYSTEM_PROMPT, user_prompt, max_tokens=2048)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        usage_log.log_usage("ioc", message.usage, model="claude-sonnet-4-6")
        text = message.content[0].text

    start = text.find("[")
    end = text.rfind("]") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return [{"ioc": v, "ioc_type": detect_type(v), "verdict": "UNKNOWN",
             "confidence": 0, "category": "오류", "description": "파싱 실패",
             "tags": [], "recommendation": "다시 시도해 주세요."} for v in iocs]


async def analyze_ioc(content: str) -> list[dict]:
    """실행 모드(cloud/local/offline/mock)를 판별해 알맞은 분석 경로로 위임한다 (App 3 패턴과 동일).

    오프라인 모드는 IoC 판정에 필요한 위협 인텔리전스 DB가 로컬에 없다는 근본적 한계 때문에,
    구조적으로 확인 가능한 것(사설 IP/타이포스쿼팅/해시 포맷)만 판정하고 나머지는 정직하게
    UNKNOWN으로 보고한다 (ioc_offline_engine.py의 ENGINE_DISCLAIMER 참고).
    """
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines:
        return []

    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        results = generate_mock_ioc(content)
    elif mode in ("local", "cloud", "claude_cli"):
        try:
            results = _real_analyze(lines, backend=mode)
        except Exception as e:
            results = analyze_offline(lines, detect_type)
            backend_label = {"local": "로컬 LLM", "claude_cli": "Claude Code CLI"}.get(mode, "외부 AI API")
            reason = f"{backend_label} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            for r in results:
                r["fallback_reason"] = reason
            mode = "offline"
    else:
        results = analyze_offline(lines, detect_type)

    for r in results:
        r["mode"] = mode
    return results


# "예시 불러오기"가 항상 같은 고정 문자열만 채워주던 것과 달리, abuse.ch URLhaus(무료·인증
# 불필요 공개 위협 인텔리전스 피드, https://urlhaus.abuse.ch/api/)의 "최근 보고된 악성 URL"
# 목록을 실시간으로 가져와 실제 예시로 채운다. 이 앱 자체가 이 피드로 판정을 내리는 것은
# 아니고(판정은 여전히 AI/오프라인 규칙 엔진이 수행), 어디서 실제 사례를 구할 수 있는지
# 보여주는 용도.
_URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


async def fetch_real_examples(limit: int = 6) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_URLHAUS_RECENT_CSV)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        raise RuntimeError(f"URLhaus에서 실시간 예시를 가져오지 못했습니다: {e}") from e

    urls = []
    for row in csv.reader(io.StringIO(resp.text)):
        if not row or row[0].startswith("#"):
            continue
        if len(row) > 2 and row[2]:
            urls.append(row[2])
        if len(urls) >= limit:
            break

    if not urls:
        raise RuntimeError("가져온 데이터에서 URL을 찾지 못했습니다 — URLhaus 피드 형식이 바뀌었을 수 있습니다.")
    return urls
