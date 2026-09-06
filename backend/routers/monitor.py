import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.claude_service import analyze_logs
from services.live_monitor import generate_batch, list_profiles, PROFILES, DEFAULT_PROFILE
from services import attack_monitor_service as ams
from services import db, notify

router = APIRouter(prefix="/api/monitor", tags=["monitor"])

INTERVAL_SECONDS = 8
REAL_INTERVAL_SECONDS = 20  # App 23와 동일 — 실제 PowerShell 조회는 더 긴 주기가 적절
REAL_WINDOW_MINUTES = 5

REAL_TARGET_LABEL = "실제 이 PC (Windows)"


@router.get("/profiles")
async def get_profiles():
    return {"profiles": list_profiles(), "default": DEFAULT_PROFILE}


@router.websocket("/ws")
async def monitor_ws(websocket: WebSocket):
    await websocket.accept()
    pending_injections: list[str] = []
    # source: "simulated"(합성 로그, 기본값) | "real"(이 PC의 실제 신호 — attack_monitor_service
    # 재사용). App 23이 이미 만든 실제 신호 수집·원격 대상 지정 기능을 이 앱에서 다시 구현하지
    # 않고 그대로 재사용한다 — 원격 서버 대상까지 필요하면 App 23을 안내한다(이 탭은 "이 PC"만).
    state = {"profile": DEFAULT_PROFILE, "source": "simulated"}
    baseline_listeners: set | None = None

    async def receive_loop():
        try:
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "inject" and msg.get("line"):
                    pending_injections.append(str(msg["line"])[:300])
                elif msg.get("type") == "set_profile" and msg.get("profile") in PROFILES:
                    state["profile"] = msg["profile"]
                elif msg.get("type") == "set_source" and msg.get("source") in ("simulated", "real"):
                    state["source"] = msg["source"]
        except Exception:
            pass

    receiver_task = asyncio.create_task(receive_loop())
    loop = asyncio.get_event_loop()

    try:
        await websocket.send_json({"type": "connected", "interval_seconds": INTERVAL_SECONDS})
        while True:
            interval = REAL_INTERVAL_SECONDS if state["source"] == "real" else INTERVAL_SECONDS
            await asyncio.sleep(interval)

            if state["source"] == "real":
                # PowerShell 서브프로세스 호출은 블로킹 — 이 프로젝트에서 반복된 패턴대로 스레드 위임.
                batch_text, baseline_listeners = await loop.run_in_executor(
                    None, ams.collect_real_signals, baseline_listeners, REAL_WINDOW_MINUTES, None
                )
                target_label = REAL_TARGET_LABEL
                filename = "live_monitor_real"
            else:
                injected = pending_injections.copy()
                pending_injections.clear()
                profile = state["profile"]
                batch_text = generate_batch(injected, profile=profile)
                target_label = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])["label"]
                filename = "live_monitor"

            # analyze_logs()가 cloud/local 모드일 때 내부적으로(loop.run_in_executor로) 블로킹
            # 호출을 스레드에 위임하므로, 여기서는 그냥 await만 하면 이 WebSocket의 수신 루프가
            # 막히지 않는다 — 예전에는 이 라우터가 직접 run_in_executor로 감쌌었지만, 이제
            # analyze_logs() 자신이 모드별로 블로킹 여부를 판단해 캡슐화한다.
            result = await analyze_logs(batch_text)
            result["filename"] = filename
            result["raw_log"] = batch_text
            result["target_label"] = target_label
            # 대시보드(App 1)의 수동 분석과 같은 history에 합류시켜 "개요"/"이벤트" 탭 통계에도 반영되게 한다.
            result["id"] = db.add_entry("dashboard", result)
            await notify.alert_if_critical(
                "dashboard", result.get("threat_level") == "CRITICAL", "CRITICAL",
                result.get("summary", ""), result["id"], result,
            )

            await websocket.send_json({"type": "event", **result})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        receiver_task.cancel()
