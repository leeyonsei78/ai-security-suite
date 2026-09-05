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
| `/api/attack-monitor/history?mode=real` | GET | App 23(실시간 공격 모니터링 & 대응 센터)의 실제 시스템 분석 이력 — 각 항목에 `created_at`(ISO 타임스탬프)이 있어 "마지막 폴링 이후 새 항목만" 필터링 가능 |
| `/api/attack-monitor/exposure` | GET | 이 PC의 현재 노출 상태(방화벽 로깅/RDP/로그온 실패/열린 포트/Defender) 즉시 조회 — 정기 스냅샷 수집에 적합 |

모든 POST 엔드포인트는 JSON 바디를 받고 JSON을 반환합니다. 요청/응답 필드는 각 라우터
(`backend/routers/*.py`)와 서비스(`backend/services/*.py`)를 참고하세요 — 이 문서는 n8n
연동 관점의 요약만 다룹니다.

## 3. 예제 워크플로우 (`n8n-workflows/`)

바로 n8n에 Import(우측 상단 `...` 메뉴 → Import from File, 또는 캔버스에 JSON 클립보드 붙여넣기)해서
쓸 수 있는 예제들:

- **`alerts-polling-to-slack.json`**: 5분마다 `/api/alerts`를 폴링해 최근 5분 내 새 CRITICAL
  알림만 걸러 Slack으로 전송. 7개 탐지형 앱을 한 번에 커버하는 가장 범용적인 예제.
- **`cve-daily-watch.json`**: 매일 오전 9시, 지정한 키워드 목록(예: `log4j`, `openssl`)으로
  `/api/cve/search`를 조회해 CVSS 7.0 이상만 Slack으로 요약 전송.
- **`ioc-batch-analysis.json`**: Webhook으로 IoC 목록을 받아 `/api/ioc/analyze`에 넘기고,
  분석 결과를 요청자에게 즉시 응답 + MALICIOUS 판정이 하나라도 있으면 Slack 알림.
- **`attack-monitor-report-to-slack.json`**: 5분마다 App 23의 `/api/attack-monitor/history?mode=real`를
  폴링해, 최근 생성된 것 중 INFO가 아닌 분석 결과를 이벤트 목록까지 포함한 상세 메시지로 Slack에 전송.
  `alerts-polling-to-slack.json`이 이미 모든 탐지형 앱(App 23 포함)의 **CRITICAL** 알림을 한 줄 요약으로
  커버하므로, 이 워크플로우는 그보다 더 자세한 리포트가 필요할 때만 추가로 켜는 보조용입니다(둘 다 켜면
  CRITICAL 건에 한해 메시지가 두 번 옵니다).
- **`attack-monitor-to-notion.json`**: 15분마다 같은 엔드포인트를 폴링해, INFO가 아닌 분석 결과를
  Notion 데이터베이스에 한 행씩 누적 — 실시간 알림이 아니라 장기 추세를 보기 위한 이력 로그 용도.
  Notion 연동 설정은 아래 "6. Notion 연동" 참고.
- **`push-alert-webhook-receiver.json`**: 위 예제들과 반대 방향(Pull이 아니라 Push) — 이 앱이 CRITICAL을
  탐지한 순간 n8n Webhook으로 직접 보내는 것을 **받는** 쪽 워크플로우. 설정은 아래 "8. n8n Push 연동" 참고.

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

## 6. Notion 연동 (`attack-monitor-to-notion.json`)

App 23(실시간 공격 모니터링 & 대응 센터)의 분석 결과를 Notion 데이터베이스에 계속 쌓아
장기 추세를 모니터링하고 싶을 때 사용합니다. n8n의 Notion 노드를 쓰므로 Notion 쪽 준비가
먼저 필요합니다 (이 프로젝트 코드/Claude는 Notion API를 직접 호출하지 않습니다 — 인증·데이터
저장 전부 n8n·Notion 쪽에서 이루어집니다).

1. **Notion 통합(Integration) 생성**: [notion.so/my-integrations](https://www.notion.so/my-integrations)에서
   새 내부 통합(Internal Integration)을 만들고 토큰을 발급받습니다.
2. **로그용 데이터베이스 생성**: Notion에 새 데이터베이스를 만들고 아래 속성(컬럼)을 추가합니다
   (이름과 타입이 워크플로우의 `propertiesUi` 매핑과 일치해야 합니다):

   | 속성 이름 | 타입 |
   |---|---|
   | 제목(Name) | Title (기본 제공) |
   | 위협도 | Select (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW` 옵션) |
   | 요약 | Text |
   | 이벤트수 | Number |
   | 분류 | Text |
   | 모드 | Select (`real` 옵션) |
   | 분석ID | Number |
   | 발생시각 | Date |
   | 리포트 | URL |

3. 데이터베이스 우측 상단 `···` → `연결 추가`에서 1번에서 만든 통합을 연결합니다(이걸 빼먹으면
   n8n이 "object not found" 에러를 냅니다).
4. 데이터베이스 페이지 URL에서 32자리 ID를 복사해, `attack-monitor-to-notion.json`을 n8n에
   Import한 뒤 `Notion: append log row` 노드의 `databaseId` 값(`여기에_Notion_데이터베이스_ID_입력`)을
   교체합니다.
5. n8n에 Notion 자격증명(위 통합 토큰)을 연결하고 워크플로우를 활성화합니다.
6. 기본 필터는 `threat_level`이 `INFO`가 아닌 결과만 남깁니다 — App 23의 실제 모드가 20초마다
   도는 루프라 INFO까지 전부 쌓으면 하루 수천 행이 생기기 때문입니다. 전체를 다 쌓고 싶으면
   `Filter: new non-INFO since last poll` 코드 노드에서 해당 필터 줄만 지우면 됩니다.

**완료** (2026-09-05): 위 1~6단계 전부 완료 — 데이터베이스 속성 8개 생성, 연결 추가, n8n Import,
Notion 자격증명 연결, 활성화(Publish)까지 마치고 실제 페이지 생성까지 API로 재확인함. 실제 진행하며
발견한 것: (1) 이 데이터베이스의 속성 8개가 Notion UI 입력 과정의 인코딩 문제로 깨져 저장돼 있어
Notion API로 속성 ID 기준 PATCH해 복구 (2) 이 n8n 버전(Notion 노드 typeVersion 2.2)의 date 속성
파라미터 키는 `dateValue`가 아니라 `date` — 워크플로우 파일에도 반영됨.

## 8. n8n Push 연동 (이 앱 → n8n)

지금까지의 연동은 전부 n8n이 이 앱의 API를 **폴링**하는 방향(Pull)이었습니다. 반대로 이 앱이 CRITICAL을
탐지한 그 순간 n8n에 **직접 알려주고** 싶다면(Push), `backend/services/notify.py`가 Slack/이메일과
별도로 n8n의 Webhook 트리거를 호출하는 기능을 지원합니다.

**동작 방식**: 탐지형 앱이 CRITICAL로 판정하면 `notify.send_alert()`가 `N8N_WEBHOOK_URL`에 다음
JSON을 POST합니다 —사람이 읽는 Slack/이메일 텍스트와 달리 n8n 워크플로우가 그대로 조건 분기·필드
매핑에 쓸 수 있는 구조화된 필드입니다:

```json
{
  "app": "vuln",
  "app_label": "취약점 스캐너",
  "severity": "CRITICAL",
  "summary": "...",
  "entry_id": 123,
  "created_at": "2026-09-05T06:19:32.842206+00:00"
}
```

**설정 방법**:

1. n8n 쪽에 이 페이로드를 받을 워크플로우를 만듭니다 — 가장 빠른 방법은 예제
   `push-alert-webhook-receiver.json`을 그대로 Import하는 것입니다(Webhook 트리거 → 메시지 포맷
   → Slack 전송 예시. Slack 자리에 Jira 티켓 생성, PagerDuty 인시던트 오픈 등 원하는 자동화를
   붙이면 됩니다).
2. 워크플로우를 **Publish(활성화)**해 Production URL을 확정합니다 — Webhook 노드의
   "Production URL" 탭에서 확인 가능(예: `http://localhost:5678/webhook/ai-security-push-alert`).
3. `backend/.env`(또는 프로젝트 루트 `.env`)에 그 URL을 설정:
   ```bash
   N8N_WEBHOOK_URL=http://localhost:5678/webhook/ai-security-push-alert
   ```
4. 백엔드를 재시작합니다 — 환경변수는 프로세스 시작 시 한 번만 읽으므로 `--reload`로는
   반영되지 않습니다.

⚠️ **방향에 따라 호스트 이름이 다릅니다**: n8n이 이 앱의 API를 부를 때(Pull, 위 1~7절)는 n8n이
Docker 컨테이너 안에 있어 `host.docker.internal:8000`이 필요했지만, 이번엔 반대로 이 앱(Windows
네이티브 프로세스)이 n8n을 부르는 방향이라 Docker Desktop이 5678 포트를 호스트에 게시해주는 한
`http://localhost:5678/...`을 그대로 쓰면 됩니다.

`N8N_WEBHOOK_URL`만 설정하고 `SLACK_WEBHOOK_URL`/`SMTP_*`는 비워둬도 Mock 모드에서 벗어납니다
(`notify.IS_MOCK`은 세 채널 중 하나라도 설정되면 false) — n8n Push만 단독으로 써도 됩니다.

**검증 완료** (2026-09-05): `push-alert-webhook-receiver.json`을 Import·Publish한 뒤, 실제
프로덕션 Webhook에 curl로 직접 POST해 200 응답과 n8n 실행 성공(Slack 전송 성공)을 확인했고,
이어서 `backend/services/notify.send_alert()`를 실제로 호출해 백엔드 → n8n Webhook → Slack까지
end-to-end로 성공하는 것을 n8n 실행 로그로 재확인했습니다.

## 7. 검증

`backend/services/auth.py` 추가 후 다음을 확인했습니다:

- `API_KEY` 미설정 시: 기존과 동일하게 `/api/*` 전부 인증 없이 응답 (회귀 없음)
- `API_KEY` 설정 시: `X-API-Key` 헤더 없이 요청 → 401, 잘못된 값 → 401, 올바른 값 → 정상 응답
- 세 예제 워크플로우 JSON은 n8n import 포맷으로 유효성 검증(파싱) 완료. 실제 n8n 인스턴스에
  이 세션에서 접근할 수 없어 import 후 실제 실행까지는 확인하지 못했습니다 — 사용자 환경에서
  최초 1회 직접 Import해 Slack 자격증명 연결 후 실행 확인을 권장합니다.
- **App 23(공격 모니터링) → Slack 연동은 이미 실제로 동작 중임을 확인함** (2026-09-05): App 23을
  `notify.APP_LABELS`에 추가한 시점부터, 기존에 이미 Import·활성화돼 있던 범용 `alerts-polling-to-slack.json`이
  코드 변경 없이 자동으로 App 23의 CRITICAL 알림도 포함하게 됨 — 이 세션 중 App 23에서 발생한 CRITICAL
  판정(분석 ID 341, 343)이 실제로 `#ai-security-suite` Slack 채널에 정상 도착한 것을 `slack_read_channel`로
  확인했다. `attack-monitor-report-to-slack.json`/`attack-monitor-to-notion.json` 두 신규 워크플로우는
  파싱 검증만 완료했고 실제 n8n Import·실행 확인은 사용자 환경에서 필요.
