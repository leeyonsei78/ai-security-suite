from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from services import dependency_scan_service, network_scan_service, db, notify

router = APIRouter(prefix="/api/infra-scan", tags=["infra-scan"])

APP_DEP = "infra_scan_dependency"
APP_NET = "infra_scan_network"

DISCLAIMER = (
    "의존성 스캔은 NVD 키워드 검색 기반 best-effort 매칭입니다(정밀 SCA는 pip-audit/npm audit/Trivy 등 전용 도구 권장). "
    "네트워크 스캔은 소유권을 확인할 수 있는 사설망(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)과 로컬호스트만 지원하며, "
    "승인하지 않은 대상에는 사용하지 마세요."
)


class DependencyRequest(BaseModel):
    manifest_type: str = "pip"
    content: str


class NetworkRequest(BaseModel):
    target: str
    authorized: bool = False


@router.get("/guide")
async def get_guide():
    return {
        "disclaimer": DISCLAIMER,
        "dependency": {
            "manifest_types": [
                {"id": "pip", "label": "Python (requirements.txt)", "example": "flask==2.0.1\nrequests>=2.25.0\nPyYAML==5.3.1"},
                {"id": "npm", "label": "Node.js (package.json)", "example": '{\n  "dependencies": {\n    "express": "^4.17.1",\n    "lodash": "4.17.15"\n  }\n}'},
            ],
            "note": f"한 번에 최대 {dependency_scan_service.MAX_PACKAGES}개 패키지까지 스캔합니다 (NVD 요청 한도 보호).",
        },
        "network": {
            "allowed_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8 (localhost)"],
            "ports_scanned": len(network_scan_service.COMMON_PORTS),
            "note": "전체 포트 스윕이 아닌 흔한 서비스 포트만 빠르게 점검하는 용도입니다. 정밀 스캔은 nmap -sV를 직접 사용하세요.",
        },
    }


@router.post("/dependency/analyze")
async def analyze_dependency(request: DependencyRequest):
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    if request.manifest_type not in ("pip", "npm"):
        raise HTTPException(status_code=400, detail="manifest_type must be 'pip' or 'npm'")

    result = await dependency_scan_service.scan_dependencies(request.manifest_type, request.content)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["message"])

    entry = {"preview": request.content.strip()[:100].replace("\n", " "), **result}
    entry["id"] = db.add_entry(APP_DEP, entry)

    if entry.get("highest_severity") == "CRITICAL":
        summary = f"의존성 스캔에서 CRITICAL 등급 CVE 발견 ({request.manifest_type}, {entry['packages_scanned']}개 패키지 중)"
        await notify.alert_if_critical(APP_DEP, True, "CRITICAL", summary, entry["id"])

    return entry


@router.get("/dependency/history")
async def dependency_history():
    history = db.get_history(APP_DEP)
    return {"history": history, "total": len(history)}


@router.delete("/dependency/history")
async def clear_dependency_history():
    db.clear_history(APP_DEP)
    return {"message": "Cleared"}


@router.get("/dependency/report/{entry_id}", response_class=PlainTextResponse)
async def dependency_report(entry_id: int):
    entry = db.get_entry(APP_DEP, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return dependency_scan_service.generate_markdown_report(entry)


@router.post("/network/scan")
async def scan_network(request: NetworkRequest):
    if not request.target.strip():
        raise HTTPException(status_code=400, detail="Empty target")

    result = await network_scan_service.scan_target(request.target.strip(), request.authorized)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["message"])

    entry = {**result}
    entry["id"] = db.add_entry(APP_NET, entry)

    if entry.get("highest_severity") == "CRITICAL":
        summary = f"네트워크 스캔에서 CRITICAL 등급 CVE 발견 (대상: {entry['target']}, 열린 포트 {len(entry['open_ports'])}개 중)"
        await notify.alert_if_critical(APP_NET, True, "CRITICAL", summary, entry["id"])

    return entry


@router.get("/network/history")
async def network_history():
    history = db.get_history(APP_NET)
    return {"history": history, "total": len(history)}


@router.delete("/network/history")
async def clear_network_history():
    db.clear_history(APP_NET)
    return {"message": "Cleared"}


@router.get("/network/report/{entry_id}", response_class=PlainTextResponse)
async def network_report(entry_id: int):
    entry = db.get_entry(APP_NET, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return network_scan_service.generate_markdown_report(entry)
