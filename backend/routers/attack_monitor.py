import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from services import attack_monitor_service as ams
from services import aws_activity_monitor as awsmon
from services import db, notify
from services.claude_service import analyze_logs
from services.live_monitor import generate_batch

router = APIRouter(prefix="/api/attack-monitor", tags=["attack-monitor"])

APP_REAL = "attack_monitor"
APP_DEMO = "attack_monitor_demo"
APP_AWS = "attack_monitor_aws"

REAL_INTERVAL_SECONDS = 20
SIM_INTERVAL_SECONDS = 8
AWS_INTERVAL_SECONDS = 15
REAL_WINDOW_MINUTES = 5


class RemoteTarget(BaseModel):
    host: str
    username: str | None = None
    password: str | None = None


class ExposureRequest(BaseModel):
    target: RemoteTarget | None = None


class CheckRemoteRequest(BaseModel):
    target: RemoteTarget


@router.get("/exposure")
async def get_exposure():
    """지금 이 PC의 실제 노출 상태(방화벽 로깅/RDP/최근 로그온 실패/전체 인터페이스에 열린 포트/
    Defender 상태)를 결정론적으로 즉시 점검한다. AI를 쓰지 않는 라이브 조회(App 15/17/19/21과 같은 패턴).
    항상 이 백엔드가 실행 중인 PC 자신을 대상으로 한다 — 원격 대상을 지정하려면 아래
    POST /exposure를 쓰세요(하위 호환을 위해 이 GET은 그대로 둠)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, ams.get_exposure_snapshot)


@router.post("/exposure")
async def get_exposure_for_target(request: ExposureRequest):
    """target을 지정하면 그 원격 Windows PC를(WinRM), 지정하지 않으면 이 PC 자신을 점검한다."""
    loop = asyncio.get_event_loop()
    target = request.target.model_dump() if request.target else None
    return await loop.run_in_executor(None, ams.get_exposure_snapshot, target)


@router.post("/check-remote")
async def check_remote(request: CheckRemoteRequest):
    """본격적인 모니터링을 시작하기 전에 원격 대상에 실제로 연결되는지 먼저 확인한다."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, ams.check_remote_connection, request.target.model_dump())


@router.post("/check-aws")
async def check_aws():
    """AWS(LocalStack 샌드박스) 모니터링을 시작하기 전에 test-range-localstack 컨테이너가
    실제로 떠 있는지 먼저 확인한다."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, awsmon.check_connection)


@router.websocket("/ws")
async def attack_monitor_ws(websocket: WebSocket):
    mode = websocket.query_params.get("mode", "simulate")
    if mode not in ("real", "simulate", "aws"):
        mode = "simulate"

    await websocket.accept()
    pending_injections: list[str] = []
    baseline_listeners: set | None = None
    target_holder: dict = {"target": None}

    async def receive_loop():
        try:
            while True:
                msg = await websocket.receive_json()
                if mode == "simulate" and msg.get("type") == "inject" and msg.get("line"):
                    pending_injections.append(str(msg["line"])[:300])
                elif mode == "real" and msg.get("type") == "set_target":
                    target_holder["target"] = msg.get("target") or None
        except Exception:
            pass

    loop = asyncio.get_event_loop()
    interval = REAL_INTERVAL_SECONDS if mode == "real" else AWS_INTERVAL_SECONDS if mode == "aws" else SIM_INTERVAL_SECONDS
    receiver_task = None

    try:
        await websocket.send_json({"type": "connected", "mode": mode, "interval_seconds": interval})

        if mode == "real":
            # 원격 대상을 지정하려면 클라이언트가 연결 직후 바로 {"type":"set_target",...}를
            # 보내야 한다 — 짧게(최대 1.5초) 기다렸다가 그 사이 도착한 첫 대상을 반영한 뒤,
            # 이후 변경 사항은 아래 receiver_task가 계속 수신한다(안 보내면 기존처럼
            # 이 PC 자신을 대상으로 함 — 하위 호환).
            try:
                first_msg = await asyncio.wait_for(websocket.receive_json(), timeout=1.5)
                if first_msg.get("type") == "set_target":
                    target_holder["target"] = first_msg.get("target") or None
            except asyncio.TimeoutError:
                pass

        receiver_task = asyncio.create_task(receive_loop())

        if mode == "real":
            # 실제 리스닝 포트의 baseline을 먼저 한 번 잡아둬야, 이후 주기에서 "새로 열린 포트"만
            # 이상 신호로 취급할 수 있다 (안 그러면 매 주기 기존 30여 개 포트가 전부 "신규"로 잡힘).
            _, baseline_listeners = await loop.run_in_executor(
                None, ams.collect_real_signals, None, REAL_WINDOW_MINUTES, target_holder["target"]
            )

        while True:
            await asyncio.sleep(interval)

            if mode == "real":
                # PowerShell 서브프로세스 호출은 블로킹 — WebSocket 이벤트 루프를 막지 않도록
                # 이 프로젝트에서 반복된 패턴(App 1 monitor.py 등)대로 스레드로 위임한다.
                batch_text, baseline_listeners = await loop.run_in_executor(
                    None, ams.collect_real_signals, baseline_listeners, REAL_WINDOW_MINUTES, target_holder["target"]
                )
            elif mode == "aws":
                # docker 서브프로세스 호출도 블로킹 — 동일한 이유로 스레드 위임.
                batch_text = await loop.run_in_executor(None, awsmon.collect_events, interval + 5)
            else:
                injected = pending_injections.copy()
                pending_injections.clear()
                batch_text = generate_batch(injected)

            # analyze_logs()가 cloud/local일 때 내부적으로 run_in_executor에 위임하므로 여기서는
            # 그냥 await만 하면 된다(PowerShell/docker 수집 부분만 이 라우터가 직접 run_in_executor로 감쌈).
            result = await analyze_logs(batch_text)
            result = ams.enrich_with_response(result)
            result["mode"] = mode
            result["raw_log"] = batch_text
            if mode == "real":
                result["target_host"] = (target_holder["target"] or {}).get("host")
            elif mode == "aws":
                result["target_host"] = "AWS 샌드박스 (LocalStack)"
                result["engine_note"] = awsmon.ENGINE_NOTE
            else:
                result["target_host"] = None
            app_name = APP_REAL if mode == "real" else APP_AWS if mode == "aws" else APP_DEMO
            result["filename"] = app_name
            # n8n 등 외부 자동화가 "마지막 폴링 이후 새 항목만" 걸러낼 수 있도록 최상위 타임스탬프를 남긴다
            # (db.py의 SQLite created_at 컬럼은 get_history()가 반환하는 JSON 블롭에는 포함되지 않음).
            result["created_at"] = datetime.now(timezone.utc).isoformat()

            result["id"] = db.add_entry(app_name, result)

            # 데모(시뮬레이션) 모드는 가짜 데이터라 실제 Slack/이메일 알림을 절대 트리거하지 않는다 —
            # 사용자가 데모를 눌렀는데 "진짜 공격 발생" 알림이 오면 안 되기 때문에 real/aws 모드만 연결.
            # aws 모드는 LocalStack 샌드박스라 실제 운영 환경은 아니지만, 사용자가 그 안에서 실제로
            # 만든/변경한 리소스를 반영하는 진짜 신호이므로(합성 로그가 아님) real과 동일하게 취급한다.
            if mode in ("real", "aws"):
                await notify.alert_if_critical(
                    app_name, result.get("threat_level") == "CRITICAL", "CRITICAL",
                    result.get("summary", ""), result["id"],
                )

            await websocket.send_json({"type": "event", **result})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if receiver_task:
            receiver_task.cancel()


def _app_name_for(mode: str) -> str:
    return APP_REAL if mode == "real" else APP_AWS if mode == "aws" else APP_DEMO


@router.get("/history")
async def get_history(mode: str = "real"):
    app_name = _app_name_for(mode)
    history = db.get_history(app_name)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history(mode: str = "real"):
    app_name = _app_name_for(mode)
    db.clear_history(app_name)
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int, mode: str = "real"):
    app_name = _app_name_for(mode)
    entry = db.get_entry(app_name, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return ams.generate_markdown_report(entry)
