import os
import json
from dotenv import load_dotenv
from services.mock_threat_analysis import generate_mock_analysis, generate_mock_chat
from services.threat_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

_PROMPTS = {
    "malware": """You are a malware analyst. Analyze the provided sample data (strings, code, behavior logs, hashes, or descriptions).
Respond ONLY with valid JSON:
{
  "analysis_type": "malware",
  "malware_type": "악성코드 종류 (e.g. RAT, Ransomware, InfoStealer)",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "summary": "한 문단 분석 요약 (한국어)",
  "capabilities": ["악성 기능 목록"],
  "iocs": [{"type":"domain|ip|url|hash_md5|hash_sha256|file|registry|mutex","value":"...","description":"..."}],
  "mitre_techniques": [{"id":"T####.###","name":"...","tactic":"...","color":"orange|yellow|purple|pink|teal|violet|amber|red|rose|gray"}],
  "behavior": {"network":"...","file_system":"...","registry":"...","processes":"..."},
  "recommendations": ["조치 항목"]
}""",

    "forensics": """You are a digital forensics expert. Analyze the provided artifacts (logs, file listings, registry exports, event logs).
Respond ONLY with valid JSON:
{
  "analysis_type": "forensics",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "summary": "한 문단 요약 (한국어)",
  "timeline": [{"time":"YYYY-MM-DD HH:MM:SS","event":"...","severity":"CRITICAL|HIGH|MEDIUM|LOW"}],
  "artifacts": [{"type":"file|registry|process|network|log","value":"...","suspicious":true|false,"description":"..."}],
  "findings": ["주요 발견 사항 목록"],
  "recommendations": ["조치 항목"]
}""",

    "memory": """You are a memory forensics expert. Analyze the provided memory artifacts (process lists, memory strings, network connections).
Respond ONLY with valid JSON:
{
  "analysis_type": "memory",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "summary": "한 문단 요약 (한국어)",
  "suspicious_processes": [{"pid":0,"name":"...","parent_pid":0,"parent_name":"...","risk":"CRITICAL|HIGH|MEDIUM|LOW","issue":"..."}],
  "injected_code": [{"target_process":"...","technique":"...","size_bytes":0,"description":"..."}],
  "network_artifacts": [{"local":"...","remote":"...","state":"...","process":"...","suspicious":true|false}],
  "strings_of_interest": ["주목할 문자열"],
  "recommendations": ["조치 항목"]
}""",

    "threat_intel": """You are a threat intelligence analyst. Analyze the provided IoCs, TTPs, or attack description to identify the threat actor and campaign.
Respond ONLY with valid JSON:
{
  "analysis_type": "threat_intel",
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0-100,
  "summary": "한 문단 요약 (한국어)",
  "threat_actor": {"name":"...","aliases":["..."],"origin":"...","motivation":"...","active_since":"...","targets":["..."],"sophistication":"..."},
  "mitre_techniques": [{"id":"T####","name":"...","tactic":"...","color":"red|pink|orange|yellow|purple|violet|rose|gray"}],
  "similar_campaigns": [{"name":"...","overlap":"xx%","description":"..."}],
  "detection_opportunities": ["탐지 기회"],
  "recommendations": ["조치 항목"]
}""",
}

_CHAT_SYSTEM = """You are a cybersecurity expert specializing in {domain}.
The analyst is investigating the following:
Analysis type: {analysis_type}
Key findings: {summary}

Answer questions concisely in Korean. Be specific and actionable."""

_DOMAIN_MAP = {
    "malware": "malware analysis and reverse engineering",
    "forensics": "digital forensics and incident response",
    "memory": "memory forensics",
    "threat_intel": "threat intelligence and threat actor profiling",
}

_CHAT_OFFLINE_NOTICE = (
    "이 기능은 AI 모드(Claude Cloud 또는 로컬 LLM)에서만 지원됩니다. 현재 모드: {mode_label} — "
    "NavBar에서 로컬 LLM이 설정되어 있다면 그쪽으로 전환하거나, 인터넷이 연결되면 자동으로 "
    "Claude Cloud를 쓸 수 있습니다."
)
_MODE_LABEL = {"offline": "오프라인 규칙 기반(폐쇄망)", "mock": "Mock 데모"}


def _real_analyze(analysis_type: str, input_data: str, context: str, backend: str = "cloud") -> dict:
    prompt = _PROMPTS.get(analysis_type, _PROMPTS["malware"])
    user_content = f"Context: {context}\n\nSample/Artifact Data:\n{input_data}" if context else f"Sample/Artifact Data:\n{input_data}"

    if backend == "local":
        text = local_llm_client.call_local_llm(prompt, user_content, max_tokens=4096)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        text = message.content[0].text

    start, end = text.find("{"), text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    raise ValueError("응답에서 JSON을 파싱하지 못했습니다")


async def analyze(analysis_type: str, input_data: str, context: str) -> dict:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_analysis(analysis_type, input_data, context)
    elif mode in ("local", "cloud"):
        try:
            data = _real_analyze(analysis_type, input_data, context, backend=mode)
        except Exception as e:
            data = analyze_offline(analysis_type, input_data, context)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(analysis_type, input_data, context)

    data["mode"] = mode
    return data


async def chat(analysis_type: str, summary: str, history: list[dict], message: str) -> str:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        return generate_mock_chat(analysis_type, message)
    if mode == "offline":
        return _CHAT_OFFLINE_NOTICE.format(mode_label=_MODE_LABEL["offline"])

    system = _CHAT_SYSTEM.format(
        domain=_DOMAIN_MAP.get(analysis_type, "cybersecurity"),
        analysis_type=analysis_type,
        summary=summary[:500],
    )
    try:
        if mode == "local":
            transcript = "\n".join(f"{m['role']}: {m['content']}" for m in history)
            user_prompt = f"{transcript}\nuser: {message}" if transcript else message
            return local_llm_client.call_local_llm(system, user_prompt, max_tokens=1024)
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system,
            messages=history + [{"role": "user", "content": message}],
        )
        return resp.content[0].text
    except Exception as e:
        backend_label = "로컬 LLM" if mode == "local" else "Claude Cloud"
        return f"{backend_label} 응답 생성에 실패했습니다: {e}. 잠시 후 다시 시도하거나 다른 모드를 사용하세요."
