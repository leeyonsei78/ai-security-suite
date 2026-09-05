import os
import json
from dotenv import load_dotenv
from services.mock_ioc import generate_mock_ioc, detect_type
from services.ioc_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

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


def _real_analyze(iocs: list[str], backend: str = "cloud") -> list[dict]:
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
    elif mode in ("local", "cloud"):
        try:
            results = _real_analyze(lines, backend=mode)
        except Exception as e:
            results = analyze_offline(lines, detect_type)
            reason = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            for r in results:
                r["fallback_reason"] = reason
            mode = "offline"
    else:
        results = analyze_offline(lines, detect_type)

    for r in results:
        r["mode"] = mode
    return results
