import os
import json
from dotenv import load_dotenv
from services.mock_incident import generate_mock_plan, generate_mock_chat
from services.incident_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

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

_CHAT_OFFLINE_NOTICE = (
    "이 기능은 AI 모드(Claude Cloud 또는 로컬 LLM)에서만 지원됩니다. 현재 모드: {mode_label} — "
    "NavBar에서 로컬 LLM이 설정되어 있다면 그쪽으로 전환하거나, 인터넷이 연결되면 자동으로 "
    "Claude Cloud를 쓸 수 있습니다. 왼쪽 대응 계획의 단계별 체크리스트는 그대로 활용하세요."
)
_MODE_LABEL = {"offline": "오프라인 규칙 기반(폐쇄망)", "mock": "Mock 데모"}


def _real_plan(incident_type: str, severity: str, description: str, backend: str = "cloud") -> dict:
    user_prompt = f"Incident Type: {incident_type}\nSeverity: {severity}\nDescription: {description}"
    if backend == "local":
        text = local_llm_client.call_local_llm(PLAN_PROMPT, user_prompt, max_tokens=3000)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=3000,
            system=PLAN_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text
    start, end = text.find("{"), text.rfind("}") + 1
    if start != -1 and end > start:
        return {"incident_type": incident_type, "severity": severity,
                "description": description, **json.loads(text[start:end])}
    raise ValueError("응답에서 JSON을 파싱하지 못했습니다")


async def create_plan(incident_type: str, severity: str, description: str) -> dict:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_plan(incident_type, severity, description)
    elif mode in ("local", "cloud"):
        try:
            data = _real_plan(incident_type, severity, description, backend=mode)
        except Exception as e:
            data = analyze_offline(incident_type, severity, description)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(incident_type, severity, description)

    data["mode"] = mode
    return data


async def chat_response(incident_type: str, severity: str, description: str,
                         history: list[dict], message: str) -> str:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        return generate_mock_chat(incident_type, message)
    if mode == "offline":
        return _CHAT_OFFLINE_NOTICE.format(mode_label=_MODE_LABEL["offline"])

    system = CHAT_PROMPT.format(incident_type=incident_type, severity=severity, description=description)
    try:
        if mode == "local":
            # local_llm_client는 단일 system+user 프롬프트만 받으므로(다회차 대화 미지원),
            # 지금까지의 대화를 하나의 사용자 프롬프트로 평탄화해 최소한의 맥락을 유지한다.
            transcript = "\n".join(f"{m['role']}: {m['content']}" for m in history)
            user_prompt = f"{transcript}\nuser: {message}" if transcript else message
            return local_llm_client.call_local_llm(system, user_prompt, max_tokens=1024)
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=1024,
            system=system, messages=history + [{"role": "user", "content": message}])
        return resp.content[0].text
    except Exception as e:
        backend_label = "로컬 LLM" if mode == "local" else "Claude Cloud"
        return f"{backend_label} 응답 생성에 실패했습니다: {e}. 잠시 후 다시 시도하거나 다른 모드를 사용하세요."
