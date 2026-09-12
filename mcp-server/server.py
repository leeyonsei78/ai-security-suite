"""AI Security Suite를 Claude Desktop/Claude Code 같은 MCP 클라이언트에게 도구로
노출하는 MCP 서버 — "AI 에이전트와 연계"의 첫 번째 방향(도구화).

새 분석 로직을 만들지 않는다 — 이미 떠 있는 백엔드(기본 http://localhost:8000)의
REST API를 그대로 호출하는 얇은 래퍼다. 그래서 이 서버를 쓰려면 먼저
`cd backend && uvicorn main:app --reload --port 8000`으로 백엔드가 실행 중이어야 한다.

Claude Desktop/Claude Code 설정에 등록하면(README.md 참고) stdio로 통신하며,
Claude가 "장비 등록해줘", "지금 감사 돌려줘", "CRITICAL 알림 있어?" 같은 대화를
그대로 도구 호출로 처리할 수 있게 된다.

주의: 이 서버는 백엔드 REST API가 이미 갖고 있는 권한 검사(선택적 API_KEY)만 따르고
별도의 인가를 하지 않는다 — 이 MCP 서버를 신뢰하는 에이전트에게만 연결할 것.
"""

import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

BASE_URL = os.getenv("AI_SECURITY_SUITE_BASE_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("AI_SECURITY_SUITE_API_KEY", "").strip()

mcp = MCPServer(
    "ai-security-suite",
    instructions=(
        "장비(방화벽/스위치/서버/클라우드 계정) 등록, 자동/수동 보안 점검 실행, 알림·리스크 현황 조회, "
        "방화벽 규칙·IoC 즉석 분석, CVE 조회를 제공하는 AI Security Suite에 접근하는 도구입니다. "
        "실제 장비에 접속해 정보를 수집하고 분석하므로, 등록·수집 도구는 사용자가 접근 권한을 가진 "
        "장비에 대해서만 호출하세요."
    ),
)


def _headers() -> dict:
    return {"X-API-Key": API_KEY} if API_KEY else {}


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.get(f"{BASE_URL}{path}", params=params, headers=_headers())
        r.raise_for_status()
        return r.json()


async def _post(path: str, json: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(f"{BASE_URL}{path}", json=json, headers=_headers())
        r.raise_for_status()
        return r.json()


async def _delete(path: str) -> Any:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.delete(f"{BASE_URL}{path}", headers=_headers())
        r.raise_for_status()
        return r.json()


# ── 장비 관리 (App 27) ──────────────────────────────────────────────

@mcp.tool()
async def list_devices() -> dict:
    """등록된 모든 장비(방화벽/서버/클라우드 계정 등)와 최근 점검 상태를 조회한다."""
    return await _get("/api/devices")


@mcp.tool()
async def get_device_meta() -> dict:
    """장비를 등록할 때 선택 가능한 장비 유형/벤더/분석 방식/수집 주기 값을 조회한다.
    register_device를 호출하기 전에 유효한 값을 확인하는 용도로 먼저 호출하는 것이 좋다."""
    return await _get("/api/devices/meta")


@mcp.tool()
async def register_device(
    name: str, device_type: str, analyzer: str, vendor: str | None = None,
    host: str = "", port: int | None = None, username: str = "", password: str | None = None,
    auth_method: str = "password", context: str = "", interval_minutes: int = 60, enabled: bool = True,
) -> dict:
    """새 장비를 등록한다. device_type: network_device|linux_host|windows_host|aws_account|
    azure_subscription|gcp_project. analyzer: firewall_audit|iam_audit|log_analysis
    (장비 유형별로 선택 가능한 값이 다름 — get_device_meta로 먼저 확인 권장).
    network_device는 vendor(cisco_ios|fortinet|palo_alto|juniper) 필수.
    auth_method가 private_key면 password 인자에 PEM 형식 개인키 텍스트를 그대로 담아 전달한다.
    등록 즉시 enabled=True면 곧바로 한 번 점검이 자동 실행된다."""
    payload = {
        "name": name, "device_type": device_type, "analyzer": analyzer, "vendor": vendor,
        "host": host, "port": port, "username": username, "password": password,
        "auth_method": auth_method, "context": context, "interval_minutes": interval_minutes,
        "enabled": enabled,
    }
    return await _post("/api/devices", payload)


@mcp.tool()
async def collect_now(device_id: int) -> dict:
    """등록된 장비 하나를 지금 즉시 수집·분석한다(주기를 기다리지 않음). 결과에는 종합
    위험도(overall_risk 또는 threat_level)와 findings/events가 포함된다."""
    return await _post(f"/api/devices/{device_id}/collect-now")


@mcp.tool()
async def get_device_history(device_id: int) -> dict:
    """장비 하나의 과거 점검 이력 전체를 최신순으로 조회한다."""
    return await _get(f"/api/devices/{device_id}/history")


@mcp.tool()
async def delete_device(device_id: int) -> dict:
    """등록된 장비를 삭제한다(접속 정보와 자동 점검 설정이 함께 삭제됨). 되돌릴 수 없다."""
    return await _delete(f"/api/devices/{device_id}")


# ── 알림 · 통합 리스크 현황 ─────────────────────────────────────────

@mcp.tool()
async def get_alerts() -> dict:
    """지금까지 발생한 CRITICAL 등급 알림 로그를 최신순으로 조회한다(어느 앱/장비에서
    무엇이 발견됐는지, 처리 여부 포함)."""
    return await _get("/api/alerts")


@mcp.tool()
async def get_risk_overview() -> dict:
    """통합 리스크 대시보드 데이터 — 앱/장비별 실행 건수·미해결 CRITICAL 건수·최근
    알림을 한 번에 조회한다. "지금 뭐가 제일 급한지" 같은 질문에 적합하다."""
    return await _get("/api/dashboard/overview")


# ── 즉석 분석 (장비 등록 없이 텍스트만으로 바로 분석) ────────────────

@mcp.tool()
async def analyze_firewall_rules(source_type: str, content: str, context: str = "") -> dict:
    """방화벽/네트워크 정책 규칙 텍스트를 등록 없이 즉석으로 감사한다. source_type:
    iptables|aws_sg|azure_nsg|gcp_fw|router_switch|vpn_gateway|windows_fw|other."""
    return await _post("/api/firewall-audit/analyze", {"source_type": source_type, "content": content, "context": context})


@mcp.tool()
async def analyze_ioc(indicators: list[str]) -> dict:
    """IP/도메인/파일 해시/이메일 목록이 알려진 악성 지표인지 판별한다."""
    return await _post("/api/ioc/analyze", {"content": "\n".join(indicators)})


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict:
    """CVE 번호(예: CVE-2021-44228)로 NVD 공식 데이터(CVSS 점수·설명·참고링크)를 실시간
    조회한다. 다른 도구가 CVE를 언급했을 때 정확한지 교차검증하는 용도로 특히 유용하다."""
    return await _get(f"/api/cve/{cve_id}")


if __name__ == "__main__":
    mcp.run(transport="stdio")
