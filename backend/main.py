from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from services.auth import require_api_key
from services import mode_manager
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
from routers.firewall_audit import router as firewall_audit_router
from routers.infra_scan import router as infra_scan_router
from routers.iam_audit import router as iam_audit_router
from routers.secret_scan import router as secret_scan_router
from routers.container_audit import router as container_audit_router
from routers.dns_security import router as dns_security_router
from routers.dashboard_overview import router as dashboard_overview_router
from routers.attack_monitor import router as attack_monitor_router
from routers.fsi_csp_audit import router as fsi_csp_audit_router
from routers.extract import router as extract_router

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
app.include_router(firewall_audit_router, dependencies=_authed)
app.include_router(infra_scan_router, dependencies=_authed)
app.include_router(iam_audit_router, dependencies=_authed)
app.include_router(secret_scan_router, dependencies=_authed)
app.include_router(container_audit_router, dependencies=_authed)
app.include_router(dns_security_router, dependencies=_authed)
app.include_router(dashboard_overview_router, dependencies=_authed)
app.include_router(attack_monitor_router, dependencies=_authed)
app.include_router(fsi_csp_audit_router, dependencies=_authed)
app.include_router(extract_router, dependencies=_authed)


@app.get("/")
def root():
    return {"status": "ok", "app": "AI Security Suite"}


class ModeOverrideRequest(BaseModel):
    mode: str | None = None  # "cloud" | "local" | "offline" | "mock" | null(자동 감지로 복귀)


@app.get("/api/mode")
async def get_mode():
    """전역 AI 실행 모드 상태 — App 3처럼 mode_manager를 도입한 앱들이 공용으로 참조한다.
    아직 mode_manager로 전환하지 않은 나머지 앱들은 여전히 각자의 claude_service.IS_MOCK을
    쓰므로(이번 롤아웃은 App 3/15부터 시작), 이 엔드포인트는 "전역 AI 모드 셀렉터"(NavBar)
    전용이며 개별 앱의 실제 동작을 보장하지 않는다 — 문서화된 단계적 확장 계획 참고."""
    return await mode_manager.get_ai_status()


@app.post("/api/mode/override")
async def set_mode_override(request: ModeOverrideRequest):
    try:
        mode_manager.set_ai_override(request.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await mode_manager.get_ai_status()
