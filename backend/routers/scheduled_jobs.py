from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import scheduled_jobs_service as jobs_service
from services import scheduler as job_scheduler

router = APIRouter(prefix="/api/scheduled-jobs", tags=["scheduled-jobs"])


class CreateJobRequest(BaseModel):
    job_type: str  # "webscan" | "cve_watch"
    target: str
    interval_hours: int = 24


@router.get("")
async def list_jobs():
    return {"jobs": jobs_service.list_jobs()}


@router.post("")
async def create_job(request: CreateJobRequest):
    try:
        job = jobs_service.create_job(request.job_type, request.target, request.interval_hours)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    job_scheduler.schedule_job(job)
    return job


@router.delete("/{job_id}")
async def delete_job(job_id: int):
    if not jobs_service.get_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    job_scheduler.unschedule_job(job_id)
    jobs_service.delete_job(job_id)
    return {"message": "Deleted"}


@router.post("/{job_id}/run-now")
async def run_now(job_id: int):
    if not jobs_service.get_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    await jobs_service.run_job(job_id)
    return jobs_service.get_job(job_id)
