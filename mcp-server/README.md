# AI Security Suite MCP 서버

이 앱(장비 관리·방화벽 감사·IoC 분석·CVE 조회·통합 리스크 현황 등)을 Claude Desktop이나
Claude Code 같은 MCP 클라이언트가 "도구"로 직접 호출할 수 있게 노출하는 얇은 래퍼입니다.
새로 분석하지 않고, 이미 떠 있는 백엔드(`http://localhost:8000`)의 REST API를 그대로 호출합니다.

## ⚠️ 반드시 별도 가상환경에 설치할 것

`mcp[cli]` 패키지는 `backend/requirements.txt`가 요구하는 것보다 훨씬 최신 버전의
`starlette`를 필요로 합니다 — **같은 Python 환경에 함께 설치하면 FastAPI 백엔드가
깨집니다** (`starlette<0.39.0` 요구 vs `mcp`가 끌어오는 `starlette>=0.49`).
반드시 이 폴더 전용 가상환경을 만들어 설치하세요:

```bash
cd mcp-server
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

## 사용 전 준비

1. 백엔드가 실행 중이어야 합니다: `cd backend && uvicorn main:app --reload --port 8000`
2. (선택) 백엔드에 `API_KEY`를 설정했다면 `AI_SECURITY_SUITE_API_KEY` 환경변수로 동일한 값을 전달하세요.
3. (선택) 백엔드가 다른 호스트/포트에 있다면 `AI_SECURITY_SUITE_BASE_URL` 환경변수로 지정하세요.

## Claude Desktop에 등록

`claude_desktop_config.json`(Claude Desktop 설정 파일)에 추가:

```json
{
  "mcpServers": {
    "ai-security-suite": {
      "command": "C:\\test_AI_security\\mcp-server\\.venv\\Scripts\\python.exe",
      "args": ["C:\\test_AI_security\\mcp-server\\server.py"]
    }
  }
}
```

## Claude Code에 등록

```bash
claude mcp add ai-security-suite -- C:\test_AI_security\mcp-server\.venv\Scripts\python.exe C:\test_AI_security\mcp-server\server.py
```

## 제공 도구

| 도구 | 설명 |
|---|---|
| `list_devices` | 등록된 장비 전체와 최근 점검 상태 조회 |
| `get_device_meta` | 등록 가능한 장비 유형/벤더/분석 방식 값 조회 |
| `register_device` | 새 장비 등록 (SSH 비밀번호/개인키, WinRM, 클라우드 CLI 지원) |
| `collect_now` | 장비를 지금 즉시 수집·분석 |
| `get_device_history` | 장비의 과거 점검 이력 조회 |
| `delete_device` | 장비 삭제 |
| `get_alerts` | CRITICAL 알림 로그 조회 |
| `get_risk_overview` | 통합 리스크 대시보드(앱/장비별 미해결 CRITICAL 등) 조회 |
| `analyze_firewall_rules` | 방화벽 규칙 텍스트 즉석 감사 (등록 없이) |
| `analyze_ioc` | IP/도메인/해시/이메일 악성 여부 판별 |
| `lookup_cve` | CVE 번호로 NVD 공식 데이터 실시간 조회 (다른 도구의 CVE 언급 교차검증용) |

## 안전 참고

- 이 서버는 백엔드가 이미 하는 것(선택적 `API_KEY` 검사) 외에 별도 인가를 하지 않습니다 —
  신뢰하는 에이전트에만 연결하세요.
- `register_device`/`collect_now`는 실제 장비에 접속해 정보를 수집합니다 — 접근 권한이
  있는 장비에 대해서만 에이전트가 이 도구를 쓰도록 프롬프트/정책으로 안내하세요.
- `delete_device`는 되돌릴 수 없습니다.
