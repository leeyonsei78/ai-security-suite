# AI Security Suite

Claude AI를 활용한 보안 분석 도구 모음.

## 진행 상황 (Progress)

| # | 앱 | 상태 |
|---|---|---|
| 1 | AI 보안 분석 대시보드 | ✅ 완료 |
| 2 | 피싱/악성 콘텐츠 탐지기 | ✅ 완료 |
| 3 | 취약점 스캐너 + 리포트 | ✅ 완료 |
| 4 | IoC 분석기 | ✅ 완료 |
| 5 | 인시던트 리스폰스 어시스턴트 | ✅ 완료 |
| 6 | 웹 취약점 스캐너 | ✅ 완료 |
| 7 | 위협 분석 랩 | ✅ 완료 |
| 8 | 프롬프트 인젝션 탐지기 | ✅ 완료 |

---

## 완료된 앱 요약

### App 1: AI 보안 분석 대시보드 `/`
로그/이벤트를 Claude AI로 분석해 위협 탐지 및 시각화.
- 로그 파일 업로드 또는 텍스트 직접 입력
- 위협 분류 (Critical / High / Medium / Low / Info)
- 위협 분포 파이차트 + 통계 카드
- 이벤트 목록 (소스 IP, 심각도, 대응 방안)

### App 2: 피싱/악성 콘텐츠 탐지기 `/phishing`
이메일 본문·URL·텍스트 → AI가 피싱·악성 여부 판단.
- 판정: MALICIOUS / PHISHING / SUSPICIOUS / SAFE
- 위험도 점수 (0–100) + 위험 신호 목록

### App 3: 취약점 스캐너 `/vuln`
포트 스캔 결과·설정 파일·코드 → AI가 취약점 분석 + Markdown 리포트 생성.
- 입력: nmap 결과 / nginx·sshd 설정 파일 / 소스코드
- CVE/CWE 매핑, 심각도별 분류
- Markdown 리포트 다운로드
- **시나리오 따라하기 모드**: 상단 [자유 분석]/[시나리오 따라하기] 탭 전환
  - "처음 해보는 사람"(입문 3종) / "해킹 대회 준비"(CTF 대비 4종: 포트스캔·코드·설정·메모리 덤프) / "모의 해킹 실전"(1종) / "개인정보 유출 대응"(1종) 총 9개 시나리오
  - 시나리오 선택 시 상황 설명·학습 목표·따라하기 단계·실전 팁 + 샘플 데이터 자동 입력
  - 스캔 실행 후 "확인 포인트" 체크리스트가 실제 결과와 자동 대조되어 ✅ 표시
  - **CTF 준비 가이드**: "해킹 대회 준비" 그룹 상단에 접이식 [무엇부터 배워야 할지 보기] 패널 — 기초 지식, 6개 분야(Web/Forensics/Crypto/Reverse/Pwn/Misc)별 핵심 개념, 필수 도구, 추천 학습 순서, 연습 사이트(picoCTF·OverTheWire·TryHackMe/HackTheBox·CTFtime)
  - **메모리 덤프 분석**: 입력 유형에 "메모리 덤프" 추가 (Volatility pstree/netscan/cmdline, strings 출력 분석) — 프로세스 마스커레이딩, C2 의심 연결, 인코딩된 PowerShell 실행, 메모리 내 Base64 문자열 탐지
  - **개인정보 유출 사고 대응** (`privacy-breach-1`): 취약점 발견 → 개인정보 유출 확인 → 사고 대응까지 이어지는 시나리오. "사고 대응 절차" 체크리스트(6단계: 탐지/즉시조치/법적 신고/정보주체 통지/원인조사/재발방지)를 처음부터 끝까지 클릭하며 따라갈 수 있음 (`response_plan` 필드, 진행률 표시, 로컬 상태만 — 새로고침 시 초기화)
  - **모의 해킹(침투테스트) 처음부터 끝까지** (`pentest-fullchain-1`): 사전 협의(RoE 승인)부터 정찰·스캐닝/열거·취약점 분석·PoC 공격·권한 상승·흔적 정리/보고까지 7단계 실전 방법론을 `response_plan` 체크리스트로 따라갈 수 있음. 승인 없는 대상은 절대 테스트하지 않는다는 원칙을 1단계에 명시
  - **개인정보(PII) 노출 체크 통합**: 시나리오 모드뿐 아니라 자유 분석을 포함한 모든 스캔 결과에 `personal_data_exposure` 필드(CONFIRMED/POTENTIAL/NONE, 유형, 설명, 개인정보보호법 관련 안내) 포함 — 결과 화면에 배너로 표시되고 Markdown 리포트에도 별도 섹션으로 반영됨
  - **CVSS 점수 + 컴플라이언스 매핑**: 모든 분석 결과(Mock/Live, 시나리오/자유분석 무관)의 각 취약점에 CVSS 3.1 추정 점수·벡터와 PCI-DSS/ISMS-P/개인정보보호법 등 관련 컴플라이언스 태그가 자동으로 추가됨. `vulnerability_service.py`의 `_enrich()`가 심각도 기반으로 일괄 부여하는 방식이라 개별 mock 데이터 수정 없이도 신규 시나리오에 자동 적용됨 (참고용 추정치이며 정확한 산정은 전문가 검토 필요 — UI/리포트에 고지)
  - `GET /api/vuln/scenarios`로 시나리오 목록 + `ctf_prep_guide` 제공, `POST /api/vuln/analyze`에 `scenario_id` 전달 시 Mock 모드에서도 시나리오별로 결정론적인(체크리스트와 항상 일치하는) 결과 반환 (`backend/services/vuln_scenarios.py`)

### App 4: IoC 분석기 `/ioc`
IP·도메인·파일 해시·이메일 → 알려진 악성 지표 여부 판별.
- 자동 타입 감지 (IP / 도메인 / MD5·SHA256 / 이메일)
- 여러 IoC 일괄 분석, 결과 복사

### App 5: 인시던트 리스폰스 어시스턴트 `/incident`
보안 사고 유형 선택 → AI가 단계별 대응 계획 + 체크리스트 생성.
- 6가지 유형: 랜섬웨어·데이터 유출·DDoS·피싱·악성코드·내부자 위협
- 심각도 선택 (Critical / High / Medium / Low)
- 6단계 대응 계획 (즉시조치→조사→봉쇄→제거→복구→사후조치)
- 체크리스트 + 진행률 표시
- AI 채팅으로 추가 질문 가능

### App 7: 위협 분석 랩 `/threat`
악성코드·포렌식 아티팩트·메모리 포렌식·위협 인텔리전스를 AI로 심층 분석.
- 악성코드 분석: 악성코드 종류·기능·IoC·MITRE ATT&CK·행위 분석 (network/file/registry/process)
- 포렌식 아티팩트: 공격 타임라인·의심 아티팩트·주요 발견 사항
- 메모리 포렌식: 의심 프로세스·코드 인젝션·네트워크 아티팩트·주목 문자열
- 위협 인텔리전스: 위협 행위자 프로파일·MITRE ATT&CK·유사 캠페인·탐지 기회
- MITRE ATT&CK 배지 클릭 시 attack.mitre.org 공식 문서 연결
- 분석 후 AI 채팅으로 심층 질문 가능

### App 6: 웹 취약점 스캐너 `/webscan`
URL 입력 → HTTP 요청으로 보안 헤더·SSL·노출 경로를 실시간 점검.
- 보안 헤더 7종 (HSTS, CSP, X-Frame-Options 등)
- SSL/TLS 인증서 유효성·만료일·버전
- 민감 경로 12개 탐지 (/.env, /.git, /admin 등)
- 서버 정보 노출 여부 (Server, X-Powered-By)
- **Live 모드**: 실제 HTTP 요청으로 실시간 점검 (허가된 사이트만!)

### App 8: 프롬프트 인젝션 탐지기 `/injection`
AI 챗봇/에이전트에 입력되는 콘텐츠를 분석해 프롬프트 인젝션·탈옥(jailbreak) 시도를 판정.
- 입력 유형 3종: 사용자 프롬프트(직접) / 외부 문서(간접 인젝션, RAG·요약 대상) / 대화 로그(멀티턴)
- 판정: INJECTION / JAILBREAK / SUSPICIOUS / SAFE + 위험 점수(0–100)
- 탐지 기법 배지 (Instruction Override, DAN/Role-play Jailbreak, Indirect Prompt Injection, Delimiter Spoofing 등)
- 위험 신호 / 안전 신호 / 권장 조치 + 최근 분석 이력

---

## 공통 기능

- **Mock / Live 모드**: `.env`에 `ANTHROPIC_API_KEY` 없으면 자동 Mock 모드
- **사용 가이드**: 모든 페이지에 접이식 GuidePanel 포함
- **네비게이션 바**: MOCK/LIVE 배지 + 전체 메뉴

---

## 향후 개발 예정 (Roadmap)

### 기존 기능 강화
- [ ] **실시간 모니터링**: 로그를 주기적으로 자동 분석 (WebSocket)
- [ ] **알림 시스템**: Critical 탐지 시 이메일/슬랙 알림
- [ ] **히스토리 DB**: 메모리 저장 → SQLite 영속화

### 새 도구 추가
- [ ] **보안 정책 생성기**: 시스템 환경 설명 → 방화벽 규칙/보안 정책 초안 자동 생성
- [ ] **AI 모델 감사**: LLM API 설정, 시스템 프롬프트 노출 여부 점검

---

## 기술 스택

```
Backend:  Python 3.11+ / FastAPI / Uvicorn / httpx
AI:       Anthropic Claude API (claude-sonnet-4-6)
Frontend: React 18 / Vite / TailwindCSS / react-router-dom
```

## 디렉토리 구조

```
test_AI_security/
├── CLAUDE.md
├── .env.example
├── .gitignore
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   ├── routers/
│   │   ├── analyze.py        ← App 1
│   │   ├── phishing.py       ← App 2
│   │   ├── vulnerability.py  ← App 3 (+ /scenarios)
│   │   ├── ioc.py            ← App 4
│   │   ├── incident.py       ← App 5
│   │   ├── webscan.py        ← App 6
│   │   ├── threat_analysis.py ← App 7
│   │   └── prompt_injection.py ← App 8
│   └── services/
│       ├── claude_service.py
│       ├── mock_data.py
│       ├── phishing_service.py / mock_phishing.py
│       ├── vulnerability_service.py / mock_vulnerability.py / vuln_scenarios.py
│       ├── ioc_service.py / mock_ioc.py
│       ├── incident_service.py / mock_incident.py
│       ├── webscan_service.py / mock_webscan.py
│       ├── threat_analysis_service.py / mock_threat_analysis.py
│       └── prompt_injection_service.py / mock_prompt_injection.py
└── frontend/
    ├── package.json
    └── src/
        ├── App.jsx
        ├── components/
        │   ├── NavBar.jsx
        │   ├── GuidePanel.jsx
        │   ├── SeverityBadge.jsx
        │   ├── StatCard.jsx
        │   └── VulnScenarioGuide.jsx
        └── pages/
            ├── Dashboard.jsx
            ├── PhishingDetector.jsx
            ├── VulnerabilityScanner.jsx
            ├── IoCAnalyzer.jsx
            ├── IncidentResponse.jsx
            ├── WebScanner.jsx
            ├── ThreatAnalysis.jsx
            └── PromptInjectionDetector.jsx
```

## 실행 방법

```bash
# 백엔드
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 프론트엔드
cd frontend
npm install
npm run dev
```

## 환경 변수 (.env)

```
ANTHROPIC_API_KEY=your_key_here
```
API 키 없으면 Mock 모드로 자동 동작.

---

## 이어서 작업하는 방법

세션이 끊기면:
1. 이 파일의 **진행 상황 표** 확인
2. 서버 재시작: 백엔드 `uvicorn main:app --reload --port 8000`, 프론트엔드 `npm run dev`
3. **Roadmap**에서 다음 작업 선택
