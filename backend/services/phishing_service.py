import os
import json
from dotenv import load_dotenv
from services.mock_phishing import generate_mock_phishing
from services.phishing_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing and social engineering detection.
Analyze the provided content (email body, URL, or text) and determine if it is malicious.

Respond ONLY with valid JSON in this exact structure:
{
  "verdict": "MALICIOUS|PHISHING|SUSPICIOUS|SAFE",
  "score": 0-100,
  "summary": "one-paragraph analysis summary",
  "indicators": ["list of suspicious signals found"],
  "safe_indicators": ["list of legitimate signals found"],
  "recommendation": "what the user should do"
}

Verdict guide:
- MALICIOUS (80-100): Clear malware delivery or confirmed phishing
- PHISHING (60-79): Strong phishing signals, likely credential theft
- SUSPICIOUS (30-59): Some red flags, needs caution
- SAFE (0-29): No significant threats detected"""


def _real_analyze(content: str, backend: str = "cloud") -> dict:
    user_prompt = f"Analyze this content for phishing/malicious signals:\n\n{content}"

    if backend == "local":
        text = local_llm_client.call_local_llm(SYSTEM_PROMPT, user_prompt, max_tokens=1024)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Parse failed", "raw": text}


async def analyze_phishing(content: str) -> dict:
    """실행 모드(cloud/local/offline/mock)를 판별해 알맞은 분석 경로로 위임한다 (App 3 패턴과 동일)."""
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_phishing(content)
    elif mode in ("local", "cloud"):
        try:
            data = _real_analyze(content, backend=mode)
        except Exception as e:
            data = analyze_offline(content)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(content)

    data["mode"] = mode
    return data
