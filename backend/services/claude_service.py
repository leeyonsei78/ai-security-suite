import os
import json
from dotenv import load_dotenv
from services.mock_data import generate_mock_analysis

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
# Mock mode when key is absent or left as the example placeholder
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

SYSTEM_PROMPT = """You are a cybersecurity expert analyzing security logs and events.
For each log entry or batch of logs provided, you must:
1. Identify threats or suspicious patterns
2. Classify severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
3. Explain what happened and why it's a concern
4. Suggest immediate remediation steps

Respond in JSON format with this structure:
{
  "summary": "overall analysis summary",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "events": [
    {
      "id": "unique identifier",
      "timestamp": "from log or null",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "threat category (e.g., Brute Force, SQL Injection, Malware, etc.)",
      "description": "what happened",
      "source_ip": "IP if present or null",
      "affected_resource": "affected system/resource or null",
      "remediation": "recommended action"
    }
  ],
  "statistics": {
    "total_events": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}"""


def _real_analyze(log_content: str) -> dict:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyze the following security logs:\n\n{log_content}"}],
    )
    text = message.content[0].text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Failed to parse response", "raw": text}


def analyze_logs(log_content: str) -> dict:
    if IS_MOCK:
        return generate_mock_analysis(log_content)
    return _real_analyze(log_content)
