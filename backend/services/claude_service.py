import asyncio
import os
import json
from dotenv import load_dotenv
from services.mock_data import generate_mock_analysis
from services.log_offline_engine import analyze_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

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


def _real_analyze(log_content: str, backend: str = "cloud") -> dict:
    """동기(블로킹) 호출 — cloud/local 둘 다 네트워크 I/O를 동기로 수행하므로, 호출부인
    analyze_logs()가 항상 run_in_executor()로 스레드에 위임해서 부른다."""
    user_prompt = f"Analyze the following security logs:\n\n{log_content}"

    if backend == "local":
        text = local_llm_client.call_local_llm(SYSTEM_PROMPT, user_prompt, max_tokens=4096)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Failed to parse response", "raw": text}


async def analyze_logs(log_content: str) -> dict:
    """실행 모드(cloud/local/offline/mock)를 판별해 알맞은 분석 경로로 위임한다.

    cloud/local 호출(anthropic SDK, local_llm_client)은 동기·블로킹이라 그대로 await하면
    이 함수를 호출하는 이벤트 루프(특히 App1 monitor.py·App23 attack_monitor.py의 WebSocket
    수신 루프)가 API 응답을 기다리는 동안 멎어버린다 — 이 프로젝트에서 이미 겪은 클래스의
    버그(App10 SSRF 데드락과 동일 유형)라, 여기서 loop.run_in_executor()로 스레드에 위임해
    호출부는 그냥 `await analyze_logs(...)`만 쓰면 되게 캡슐화했다. offline/mock 분기는
    순수 CPU 연산이라 이벤트 루프를 막지 않으므로 executor로 감쌀 필요가 없다.
    """
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_analysis(log_content)
    elif mode in ("local", "cloud"):
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, _real_analyze, log_content, mode)
        except Exception as e:
            # 사전 도달성 체크를 통과했더라도 실제 호출 시점에 실패할 수 있다(타임아웃, 로컬
            # LLM 재시작 등) — 조용히 실패시키는 대신 오프라인 규칙 기반으로 폴백한다.
            data = analyze_offline(log_content)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 규칙 기반 분석으로 대체됨: {e}"
            mode = "offline"
    else:
        data = analyze_offline(log_content)

    data["mode"] = mode
    return data
