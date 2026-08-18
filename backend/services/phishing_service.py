import os
import json
from dotenv import load_dotenv
from services.mock_phishing import generate_mock_phishing

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

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


def _real_analyze(content: str) -> dict:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyze this content for phishing/malicious signals:\n\n{content}"}],
    )
    text = message.content[0].text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Parse failed", "raw": text}


def analyze_phishing(content: str) -> dict:
    if IS_MOCK:
        return generate_mock_phishing(content)
    return _real_analyze(content)
