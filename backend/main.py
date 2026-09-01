from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services.auth import require_api_key
from routers.analyze import router as analyze_router
from routers.phishing import router as phishing_router
from routers.vulnerability import router as vuln_router
from routers.ioc import router as ioc_router
from routers.incident import router as incident_router
from routers.webscan import router as webscan_router
from routers.threat_analysis import router as threat_router
from routers.prompt_injection import router as injection_router
from routers.pwn_lab import router as pwn_lab_router
from routers.web_arena import router as web_arena_router
from routers.policy import router as policy_router
from routers.model_audit import router as model_audit_router
from routers.monitor import router as monitor_router
from routers.pentest_lab import router as pentest_lab_router
from routers.alerts import router as alerts_router
from routers.phishing_sim import router as phishing_sim_router
from routers.cve_lookup import router as cve_lookup_router
from services.claude_service import IS_MOCK

app = FastAPI(title="AI Security Suite", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    # 와일드카드: 이 앱은 쿠키 기반 인증을 쓰지 않아(모든 토큰은 Authorization 헤더로 전달)
    # allow_credentials=False와 조합해도 안전하다. Web CTF 아레나의 공유 스코어보드처럼
    # 같은 네트워크(LAN)의 팀원이 다른 호스트/포트에서 접속해 연습할 수 있도록 개방한다.
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API_KEY 환경변수가 설정된 경우에만 X-API-Key 헤더를 요구한다(기본값은 미설정 =
# 인증 없음, 지금까지의 동작과 동일). n8n 등 외부 자동화 도구에서 이 백엔드를
# 로컬/신뢰된 네트워크 밖으로 노출할 때 켜는 것을 권장 (docs/n8n-integration.md 참고).
# /api/mode는 헬스체크 성격이라 인증 없이 열어둔다.
_authed = [Depends(require_api_key)]
app.include_router(analyze_router, dependencies=_authed)
app.include_router(phishing_router, dependencies=_authed)
app.include_router(vuln_router, dependencies=_authed)
app.include_router(ioc_router, dependencies=_authed)
app.include_router(incident_router, dependencies=_authed)
app.include_router(webscan_router, dependencies=_authed)
app.include_router(threat_router, dependencies=_authed)
app.include_router(injection_router, dependencies=_authed)
app.include_router(pwn_lab_router, dependencies=_authed)
app.include_router(web_arena_router, dependencies=_authed)
app.include_router(policy_router, dependencies=_authed)
app.include_router(model_audit_router, dependencies=_authed)
app.include_router(monitor_router, dependencies=_authed)
app.include_router(pentest_lab_router, dependencies=_authed)
app.include_router(alerts_router, dependencies=_authed)
app.include_router(phishing_sim_router, dependencies=_authed)
app.include_router(cve_lookup_router, dependencies=_authed)


@app.get("/")
def root():
    return {"status": "ok", "app": "AI Security Suite"}


@app.get("/api/mode")
def get_mode():
    return {"mock": IS_MOCK, "mode": "mock" if IS_MOCK else "live"}
