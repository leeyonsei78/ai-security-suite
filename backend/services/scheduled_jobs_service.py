"""n8n 같은 외부 자동화 도구 없이도 "이 URL을 매일 재점검해서 새로 생긴 문제만
알림", "이 키워드로 매일 CVE 신규 발생 여부 감시" 같은 정기 점검을 이 앱 자체로
할 수 있게 하기 위해 추가 (App 16). 기존 App 6(웹 스캐너)·App 15(CVE 조회)의
서비스 함수를 그대로 재사용하고, 실행 결과는 평소처럼 각 앱의 히스토리에도
그대로 쌓인다 — "누가 트리거했는지"(사람 vs 스케줄러)만 다를 뿐 완전히 별도의
저장소나 로직이 아니다.

같은 값(발견된 이슈 목록/CVE 목록)이 계속 나오는데도 실행할 때마다 알림을 보내면
알림 피로가 생기므로, 직전 실행 결과와 비교해 "새로 나타난 항목"이 있을 때만
notify.alert_if_critical()을 호출한다(fingerprint 비교).
"""

from datetime import datetime, timezone

from services import db, notify
from services.cve_lookup_service import search_cves
from services.webscan_service import scan_url

APP_NAME = "scheduled_jobs"

JOB_TYPES = {"webscan", "cve_watch"}
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 30  # 최대 한 달 간격


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate(job_type: str, target: str, interval_hours: int) -> None:
    if job_type not in JOB_TYPES:
        raise ValueError(f"알 수 없는 job_type: {job_type} (webscan 또는 cve_watch만 가능)")
    if not target.strip():
        raise ValueError("target이 비어 있습니다")
    if not (MIN_INTERVAL_HOURS <= interval_hours <= MAX_INTERVAL_HOURS):
        raise ValueError(f"interval_hours는 {MIN_INTERVAL_HOURS}~{MAX_INTERVAL_HOURS} 사이여야 합니다")


def create_job(job_type: str, target: str, interval_hours: int) -> dict:
    validate(job_type, target, interval_hours)
    job = {
        "job_type": job_type,
        "target": target.strip(),
        "interval_hours": interval_hours,
        "enabled": True,
        "last_run_at": None,
        "last_summary": None,
        "last_error": None,
        "last_fingerprint": [],
    }
    job["id"] = db.add_entry(APP_NAME, job)
    return job


def list_jobs() -> list[dict]:
    return db.get_history(APP_NAME)


def get_job(job_id: int) -> dict | None:
    return db.get_entry(APP_NAME, job_id)


def delete_job(job_id: int) -> None:
    db.delete_entry(APP_NAME, job_id)


async def run_job(job_id: int) -> None:
    job = db.get_entry(APP_NAME, job_id)
    if not job or not job.get("enabled", True):
        return

    if job["job_type"] == "webscan":
        await _run_webscan(job)
    elif job["job_type"] == "cve_watch":
        await _run_cve_watch(job)


async def _run_webscan(job: dict) -> None:
    result = await scan_url(job["target"])
    if result.get("error"):
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": result["error"]})
        return

    entry = dict(result)
    entry["id"] = db.add_entry("webscan", entry)

    findings = entry.get("findings", [])
    fingerprint = sorted(f"{f.get('severity')}:{f.get('title')}" for f in findings)
    previous = set(job.get("last_fingerprint", []))
    new_items = sorted(set(fingerprint) - previous)
    has_new_critical = any(item.startswith("CRITICAL:") for item in new_items)

    if has_new_critical:
        new_titles = [i.split(":", 1)[1] for i in new_items if i.startswith("CRITICAL:")]
        summary = f"[정기 스캔] {job['target']}에서 새로운 CRITICAL 발견: " + ", ".join(new_titles[:5])
        await notify.alert_if_critical("webscan", True, "CRITICAL", summary, entry["id"])

    db.update_entry(APP_NAME, job["id"], {
        **job, "last_run_at": _now(), "last_error": None,
        "last_fingerprint": fingerprint,
        "last_summary": f"위험도 {entry.get('risk_score', 0)}점, 이슈 {len(findings)}건 (신규 {len(new_items)}건)",
    })


async def _run_cve_watch(job: dict) -> None:
    result = await search_cves(job["target"], results_per_page=10)
    if "error" in result:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": result["message"]})
        return

    results = result.get("results", [])
    entry = {"keyword": job["target"], **result}
    entry["id"] = db.add_entry("cve_lookup", entry)

    fingerprint = sorted(r["id"] for r in results if r.get("id"))
    previous = set(job.get("last_fingerprint", []))
    new_ids = sorted(set(fingerprint) - previous)
    high_severity_new = [
        r for r in results
        if r.get("id") in new_ids and (r.get("cvss") or {}).get("base_score", 0) >= 7.0
    ]

    if high_severity_new:
        names = ", ".join(r["id"] for r in high_severity_new[:5])
        summary = f"[정기 CVE 감시] '{job['target']}' 키워드로 새 고위험(CVSS 7.0+) CVE 발견: {names}"
        await notify.alert_if_critical("cve_lookup", True, "CRITICAL", summary, entry["id"])

    db.update_entry(APP_NAME, job["id"], {
        **job, "last_run_at": _now(), "last_error": None,
        "last_fingerprint": fingerprint,
        "last_summary": f"{len(results)}건 검색됨 (신규 {len(new_ids)}건, 그중 고위험 {len(high_severity_new)}건)",
    })
