"""n8n 등 외부 자동화 도구를 설치하지 않아도 정기 점검(App 16)이 돌아가게 하는
내장 스케줄러. APScheduler(순수 파이썬, 외부 브로커·별도 서버 불필요)를 이
백엔드 프로세스 안에 그대로 띄운다.

⚠️ 단일 프로세스 구조를 전제로 한다 — 나중에 여러 워커/서버로 스케일 아웃하면
같은 작업이 워커마다 중복 실행될 수 있다. 그 시점엔 Celery+Beat 같은 분산
스케줄러(외부 브로커 필요)로 이전해야 한다. 지금(단일 서버) 규모에는 충분하다.
"""

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from services import scheduled_jobs_service as jobs_service

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()


def _job_key(job_id: int) -> str:
    return f"scheduled-job-{job_id}"


def schedule_job(job: dict) -> None:
    scheduler.add_job(
        jobs_service.run_job,
        trigger=IntervalTrigger(hours=job["interval_hours"]),
        args=[job["id"]],
        id=_job_key(job["id"]),
        replace_existing=True,
        misfire_grace_time=3600,
    )


def unschedule_job(job_id: int) -> None:
    try:
        scheduler.remove_job(_job_key(job_id))
    except Exception:
        pass


def start() -> None:
    for job in jobs_service.list_jobs():
        if job.get("enabled", True):
            schedule_job(job)
    scheduler.start()
    logger.info("내장 스케줄러 시작됨 (%d개 작업 등록)", len(scheduler.get_jobs()))


def shutdown() -> None:
    scheduler.shutdown(wait=False)
