# n8n 연동 가이드

이 프로젝트의 모든 앱은 FastAPI REST API(`/api/*`)로 동작하므로, n8n의 **HTTP Request 노드**로
직접 호출해 자동화할 수 있습니다. 별도 SDK나 커스텀 n8n 노드 없이 지금 있는 백엔드 코드 그대로
사용 가능합니다.

## 1. 연결 방법

1. 백엔드를 평소처럼 실행: `cd backend && uvicorn main:app --reload --port 8000`
2. n8n을 같은 머신(또는 같은 네트워크)에서 실행
   - n8n을 Docker로 띄운 경우, `localhost`는 컨테이너 자신을 가리키므로 호스트의 백엔드에
     접근하려면 `http://host.docker.internal:8000`(Mac/Windows) 또는 호스트 IP를 사용하세요.
   - n8n을 같은 호스트에서 npm/npx로 직접 실행했다면 `http://localhost:8000` 그대로 사용 가능.
3. n8n 워크플로우의 HTTP Request 노드에 `http://localhost:8000/api/...` 형태로 URL 지정

베이스 URL을 워크플로우마다 하드코딩하지 않도록, `n8n-workflows/` 예제들은 모두
환경변수 `AI_SECURITY_SUITE_BASE_URL`을 우선 사용합니다(n8n 설정의 environment variables에
등록하거나, [Settings → Environments] 또는 `.env`로 n8n 프로세스에 주입).

## 2. 자동화에 쓰기 좋은 엔드포인트

| 엔드포인트 | 메서드 | 용도 |
|---|---|---|
| `/api/alerts` | GET | 탐지형 앱 7개(대시보드/피싱/취약점/IoC/웹스캐너/인젝션탐지/모델감사)가 CRITICAL 판정 시 쌓이는 알림 로그. **폴링해서 Slack/Jira/티켓 시스템으로 라우팅하기 가장 좋은 단일 진입점** |
| `/api/cve/{cve_id}` | GET | CVE 번호로 NVD 실시간 조회 (Claude API 불필요, 외부 인터넷 필요) |
| `/api/cve/search?keyword=` | GET | 키워드(제품명 등)로 CVE 검색 → 신규/고위험 CVE 감시 |
| `/api/ioc/analyze` | POST `{content}` | IP/도메인/해시/이메일 등 IoC 목록 일괄 판별 |
| `/api/vuln/analyze` | POST `{content, input_type}` | 포트스캔/설정파일/코드/메모리덤프 분석 |
| `/api/webscan/scan` | POST `{url}` | 대상 URL의 보안 헤더/SSL/노출 경로 실시간 점검 (Live 모드, 허가된 사이트만) |
| `/api/phishing/analyze` | POST `{content, input_type}` | 이메일/URL/텍스트 피싱 여부 판정 |
| `/api/injection/analyze` | POST | 프롬프트 인젝션/탈옥 시도 판정 |

모든 POST 엔드포인트는 JSON 바디를 받고 JSON을 반환합니다. 요청/응답 필드는 각 라우터
(`backend/routers/*.py`)와 서비스(`backend/services/*.py`)를 참고하세요 — 이 문서는 n8n
연동 관점의 요약만 다룹니다.

## 3. 예제 워크플로우 (`n8n-workflows/`)

바로 n8n에 Import(우측 상단 `...` 메뉴 → Import from File)해서 쓸 수 있는 예제 3개:

- **`alerts-polling-to-slack.json`**: 5분마다 `/api/alerts`를 폴링해 최근 5분 내 새 CRITICAL
  알림만 걸러 Slack으로 전송. 7개 탐지형 앱을 한 번에 커버하는 가장 범용적인 예제.
- **`cve-daily-watch.json`**: 매일 오전 9시, 지정한 키워드 목록(예: `log4j`, `openssl`)으로
  `/api/cve/search`를 조회해 CVSS 7.0 이상만 Slack으로 요약 전송.
- **`ioc-batch-analysis.json`**: Webhook으로 IoC 목록을 받아 `/api/ioc/analyze`에 넘기고,
  분석 결과를 요청자에게 즉시 응답 + MALICIOUS 판정이 하나라도 있으면 Slack 알림.

Import 후 해야 할 일:
1. Slack 노드에 n8n의 Slack 자격증명(OAuth 또는 Bot Token) 연결 + 채널 선택
   (자격증명은 워크플로우 파일에 포함되지 않으므로 매번 다시 연결해야 합니다)
2. `AI_SECURITY_SUITE_BASE_URL` 환경변수를 n8n에 설정 (없으면 `http://localhost:8000`로 동작)
3. `API_KEY`를 아래 4번처럼 켰다면 `AI_SECURITY_SUITE_API_KEY`도 함께 설정

## 4. 인증 (선택)

백엔드는 기본적으로 인증이 없습니다(로컬 개발 도구로 설계됨). n8n을 백엔드와 **다른
호스트/컨테이너/네트워크**에서 실행해 API를 외부에 노출해야 한다면, `API_KEY` 환경변수를
설정해 최소한의 보호를 켤 수 있습니다.

```bash
# backend/.env
API_KEY=원하는_임의의_긴_문자열
```

설정하면 모든 `/api/*` 요청(웹소켓 포함)에 `X-API-Key` 헤더가 이 값과 정확히 일치해야
통과합니다(`/api/mode`는 헬스체크 용도로 예외). n8n 쪽 HTTP Request 노드에는 이미
`X-API-Key: {{ $env.AI_SECURITY_SUITE_API_KEY }}` 헤더가 예제에 포함돼 있으니, n8n에
`AI_SECURITY_SUITE_API_KEY` 환경변수만 같은 값으로 설정하면 됩니다.

⚠️ **주의**: `API_KEY`를 켜면 프론트엔드(React) 요청도 이 헤더 없이는 401을 받습니다.
n8n에서만 백엔드를 호출하고 브라우저 프론트엔드는 계속 로컬에서만 쓴다면 문제 없지만,
프론트도 같이 써야 한다면 Vite 프록시(`frontend/vite.config.js`)에서 `X-API-Key`를
주입하도록 별도로 수정해야 합니다(이 문서 범위 밖 — 필요해지면 추가 작업).

가장 간단하고 지금까지의 이 프로젝트 방식과 맞는 대안은, `API_KEY`를 켜는 대신
n8n을 백엔드와 같은 신뢰된 로컬 네트워크에만 두고 방화벽으로 외부 접근을 막는
것입니다(Web CTF 아레나의 LAN 스코어보드 공유와 동일한 접근).

## 5. 검증

`backend/services/auth.py` 추가 후 다음을 확인했습니다:

- `API_KEY` 미설정 시: 기존과 동일하게 `/api/*` 전부 인증 없이 응답 (회귀 없음)
- `API_KEY` 설정 시: `X-API-Key` 헤더 없이 요청 → 401, 잘못된 값 → 401, 올바른 값 → 정상 응답
- 세 예제 워크플로우 JSON은 n8n import 포맷으로 유효성 검증(파싱) 완료. 실제 n8n 인스턴스에
  이 세션에서 접근할 수 없어 import 후 실제 실행까지는 확인하지 못했습니다 — 사용자 환경에서
  최초 1회 직접 Import해 Slack 자격증명 연결 후 실행 확인을 권장합니다.
