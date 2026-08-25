import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.claude_service import analyze_logs
from services.live_monitor import generate_batch
from routers.analyze import analysis_store

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
    loop = asyncio.get_event_loop()

    try:
        await websocket.send_json({"type": "connected", "interval_seconds": INTERVAL_SECONDS})
        while True:
            await asyncio.sleep(INTERVAL_SECONDS)
            injected = pending_injections.copy()
            pending_injections.clear()
            batch_text = generate_batch(injected)

            # analyze_logs() calls the (blocking) Anthropic SDK in Live mode. Running it directly here
            # would stall this websocket's event loop for the duration of the API call — the same class
            # of bug the Web CTF Arena's SSRF route hit with a blocking urllib call in an async def route.
            # Offload to a thread so the loop stays free to keep receiving injected lines meanwhile.
            result = await loop.run_in_executor(None, analyze_logs, batch_text)
            result["filename"] = "live_monitor"
            result["id"] = len(analysis_store) + 1
            result["raw_log"] = batch_text
            analysis_store.append(result)

            await websocket.send_json({"type": "event", **result})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        receiver_task.cancel()
