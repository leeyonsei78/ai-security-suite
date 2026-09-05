import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.claude_service import analyze_logs
from services.live_monitor import generate_batch
from services import db, notify

router = APIRouter(prefix="/api/monitor", tags=["monitor"])

INTERVAL_SECONDS = 8


@router.websocket("/ws")
async def monitor_ws(websocket: WebSocket):
    await websocket.accept()
    pending_injections: list[str] = []

    async def receive_loop():
        try:
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "inject" and msg.get("line"):
                    pending_injections.append(str(msg["line"])[:300])
        except Exception:
            pass

    receiver_task = asyncio.create_task(receive_loop())

    try:
        await websocket.send_json({"type": "connected", "interval_seconds": INTERVAL_SECONDS})
        while True:
            await asyncio.sleep(INTERVAL_SECONDS)
            injected = pending_injections.copy()
            pending_injections.clear()
            batch_text = generate_batch(injected)

            # analyze_logs()가 cloud/local 모드일 때 내부적으로(loop.run_in_executor로) 블로킹
            # 호출을 스레드에 위임하므로, 여기서는 그냥 await만 하면 이 WebSocket의 수신 루프가
            # 막히지 않는다 — 예전에는 이 라우터가 직접 run_in_executor로 감쌌었지만, 이제
            # analyze_logs() 자신이 모드별로 블로킹 여부를 판단해 캡슐화한다.
            result = await analyze_logs(batch_text)
            result["filename"] = "live_monitor"
            result["raw_log"] = batch_text
            # 대시보드(App 1)의 수동 분석과 같은 history에 합류시켜 "개요"/"이벤트" 탭에도 반영되게 한다.
            result["id"] = db.add_entry("dashboard", result)
            await notify.alert_if_critical(
                "dashboard", result.get("threat_level") == "CRITICAL", "CRITICAL",
                result.get("summary", ""), result["id"],
            )

            await websocket.send_json({"type": "event", **result})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        receiver_task.cancel()
