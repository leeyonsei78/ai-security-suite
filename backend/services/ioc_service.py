import os
import json
from dotenv import load_dotenv
from services.mock_ioc import generate_mock_ioc, detect_type

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

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


def _real_analyze(iocs: list[str]) -> list[dict]:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    ioc_list = "\n".join(f"- {v} (type: {detect_type(v)})" for v in iocs)
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyze these IoCs:\n{ioc_list}"}],
    )
    text = message.content[0].text
    start = text.find("[")
    end = text.rfind("]") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return [{"ioc": v, "ioc_type": detect_type(v), "verdict": "UNKNOWN",
             "confidence": 0, "category": "오류", "description": "파싱 실패",
             "tags": [], "recommendation": "다시 시도해 주세요."} for v in iocs]


def analyze_ioc(content: str) -> list[dict]:
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines:
        return []
    if IS_MOCK:
        return generate_mock_ioc(content)
    return _real_analyze(lines)
