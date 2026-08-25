from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

app.include_router(analyze_router)
app.include_router(phishing_router)
app.include_router(vuln_router)
app.include_router(ioc_router)
app.include_router(incident_router)
app.include_router(webscan_router)
app.include_router(threat_router)
app.include_router(injection_router)
app.include_router(pwn_lab_router)
app.include_router(web_arena_router)
app.include_router(policy_router)
app.include_router(model_audit_router)
app.include_router(monitor_router)
app.include_router(pentest_lab_router)


@app.get("/")
def root():
    return {"status": "ok", "app": "AI Security Suite"}


@app.get("/api/mode")
def get_mode():
    return {"mock": IS_MOCK, "mode": "mock" if IS_MOCK else "live"}
