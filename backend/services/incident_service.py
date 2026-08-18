import os
import json
from dotenv import load_dotenv
from services.mock_incident import generate_mock_plan, generate_mock_chat

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

PLAN_PROMPT = """You are an expert incident response consultant (DFIR).
Generate a structured incident response plan in Korean based on the incident details.

Respond ONLY with valid JSON:
{
  "summary": "한 문단 요약",
  "estimated_time": "예상 대응 시간",
  "key_contacts": ["담당 부서/역할 목록"],
  "phases": [
    {
      "id": "phase_id",
      "name": "단계명",
      "timeframe": "소요 시간",
      "color": "red|orange|yellow|purple|blue|green",
      "steps": ["구체적인 조치 항목들"]
    }
  ]
}

Include 5-6 phases: 즉시조치 → 조사 → 봉쇄 → 제거 → 복구 → 사후조치.
Be specific and actionable for the given incident type and severity."""

CHAT_PROMPT = """You are an expert incident response consultant.
The user is dealing with a {incident_type} security incident (severity: {severity}).
Incident description: {description}

Answer their question concisely in Korean. Be practical and specific."""


def create_plan(incident_type: str, severity: str, description: str) -> dict:
    if IS_MOCK:
        return generate_mock_plan(incident_type, severity, description)
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=3000,
        system=PLAN_PROMPT,
        messages=[{"role": "user", "content":
            f"Incident Type: {incident_type}\nSeverity: {severity}\nDescription: {description}"}],
    )
    text = message.content[0].text
    start, end = text.find("{"), text.rfind("}") + 1
    if start != -1 and end > start:
        return {"incident_type": incident_type, "severity": severity,
                "description": description, **json.loads(text[start:end])}
    return generate_mock_plan(incident_type, severity, description)


def chat_response(incident_type: str, severity: str, description: str,
                  history: list[dict], message: str) -> str:
    if IS_MOCK:
        return generate_mock_chat(incident_type, message)
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    system = CHAT_PROMPT.format(
        incident_type=incident_type, severity=severity, description=description)
    messages = history + [{"role": "user", "content": message}]
    resp = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=1024,
        system=system, messages=messages)
    return resp.content[0].text
