import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse

from services import attack_monitor_service as ams
from services import db, notify
from services.claude_service import analyze_logs
from services.live_monitor import generate_batch

router = APIRouter(prefix="/api/attack-monitor", tags=["attack-monitor"])

APP_REAL = "attack_monitor"
APP_DEMO = "attack_monitor_demo"

REAL_INTERVAL_SECONDS = 20
SIM_INTERVAL_SECONDS = 8
REAL_WINDOW_MINUTES = 5


@router.get("/exposure")
async def get_exposure():
    """지금 이 PC의 실제 노출 상태(방화벽 로깅/RDP/최근 로그온 실패/전체 인터페이스에 열린 포트/
    Defender 상태)를 결정론적으로 즉시 점검한다. AI를 쓰지 않는 라이브 조회(App 15/17/19/21과 같은 패턴)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, ams.get_exposure_snapshot)


@router.websocket("/ws")
async def attack_monitor_ws(websocket: WebSocket):
    mode = websocket.query_params.get("mode", "simulate")
    if mode not in ("real", "simulate"):
        mode = "simulate"

    await websocket.accept()
    pending_injections: list[str] = []
    baseline_listeners: set | None = None

    async def receive_loop():
        try:
            while True:
                msg = await websocket.receive_json()
                if mode == "simulate" and msg.get("type") == "inject" and msg.get("line"):
                    pending_injections.append(str(msg["line"])[:300])
        except Exception:
            pass

    receiver_task = asyncio.create_task(receive_loop())
    loop = asyncio.get_event_loop()
    interval = REAL_INTERVAL_SECONDS if mode == "real" else SIM_INTERVAL_SECONDS

    try:
        await websocket.send_json({"type": "connected", "mode": mode, "interval_seconds": interval})

        if mode == "real":
            # 실제 리스닝 포트의 baseline을 먼저 한 번 잡아둬야, 이후 주기에서 "새로 열린 포트"만
            # 이상 신호로 취급할 수 있다 (안 그러면 매 주기 기존 30여 개 포트가 전부 "신규"로 잡힘).
            _, baseline_listeners = await loop.run_in_executor(
                None, ams.collect_real_signals, None, REAL_WINDOW_MINUTES
            )

        while True:
            await asyncio.sleep(interval)

            if mode == "real":
                # PowerShell 서브프로세스 호출은 블로킹 — WebSocket 이벤트 루프를 막지 않도록
                # 이 프로젝트에서 반복된 패턴(App 1 monitor.py 등)대로 스레드로 위임한다.
                batch_text, baseline_listeners = await loop.run_in_executor(
                    None, ams.collect_real_signals, baseline_listeners, REAL_WINDOW_MINUTES
                )
            else:
                injected = pending_injections.copy()
                pending_injections.clear()
                batch_text = generate_batch(injected)

            result = await loop.run_in_executor(None, analyze_logs, batch_text)
            result = ams.enrich_with_response(result)
            result["mode"] = mode
            result["raw_log"] = batch_text
            result["filename"] = "attack_monitor_real" if mode == "real" else "attack_monitor_demo"
            # n8n 등 외부 자동화가 "마지막 폴링 이후 새 항목만" 걸러낼 수 있도록 최상위 타임스탬프를 남긴다
            # (db.py의 SQLite created_at 컬럼은 get_history()가 반환하는 JSON 블롭에는 포함되지 않음).
            result["created_at"] = datetime.now(timezone.utc).isoformat()

            app_name = APP_REAL if mode == "real" else APP_DEMO
            result["id"] = db.add_entry(app_name, result)

            # 데모(시뮬레이션) 모드는 가짜 데이터라 실제 Slack/이메일 알림을 절대 트리거하지 않는다 —
            # 사용자가 데모를 눌렀는데 "진짜 공격 발생" 알림이 오면 안 되기 때문에 real 모드만 연결.
            if mode == "real":
                await notify.alert_if_critical(
                    APP_REAL, result.get("threat_level") == "CRITICAL", "CRITICAL",
                    result.get("summary", ""), result["id"],
                )

            await websocket.send_json({"type": "event", **result})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        receiver_task.cancel()


@router.get("/history")
async def get_history(mode: str = "real"):
    app_name = APP_REAL if mode == "real" else APP_DEMO
    history = db.get_history(app_name)
    return {"history": history, "total": len(history)}


@router.delete("/history")
async def clear_history(mode: str = "real"):
    app_name = APP_REAL if mode == "real" else APP_DEMO
    db.clear_history(app_name)
    return {"message": "Cleared"}


@router.get("/report/{entry_id}", response_class=PlainTextResponse)
async def get_report(entry_id: int, mode: str = "real"):
    app_name = APP_REAL if mode == "real" else APP_DEMO
    entry = db.get_entry(app_name, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")
    return ams.generate_markdown_report(entry)
