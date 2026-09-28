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

import asyncio
from datetime import datetime, timezone

from services import aws_cloudtrail_service as ct_service
from services import db, notify
from services.claude_service import analyze_logs
from services.cve_lookup_service import search_cves
from services.webscan_service import scan_url

APP_NAME = "scheduled_jobs"

# cloudwatch_logs/guardduty_findings는 App 17(CloudTrail 연동)에 이미 등록해둔 AWS
# 연결(IAM Role)을 그대로 재사용한다 — 별도의 AWS 연결 관리 화면을 또 만들지 않음
JOB_TYPES = {"webscan", "cve_watch", "cloudwatch_logs", "guardduty_findings"}
AWS_JOB_TYPES = {"cloudwatch_logs", "guardduty_findings"}
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 30  # 최대 한 달 간격
MAX_CLOUDWATCH_EVENTS = 200
MAX_GUARDDUTY_FINDINGS = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate(job_type: str, target: str, interval_hours: int, connection_id: int | None) -> None:
    if job_type not in JOB_TYPES:
        raise ValueError(f"알 수 없는 job_type: {job_type}")
    if job_type == "guardduty_findings":
        pass  # target(Detector ID)은 비워두면 자동 탐지하므로 필수 아님
    elif not target.strip():
        raise ValueError("target이 비어 있습니다")
    if not (MIN_INTERVAL_HOURS <= interval_hours <= MAX_INTERVAL_HOURS):
        raise ValueError(f"interval_hours는 {MIN_INTERVAL_HOURS}~{MAX_INTERVAL_HOURS} 사이여야 합니다")
    if job_type in AWS_JOB_TYPES:
        if not connection_id:
            raise ValueError(f"{job_type}는 App 17에서 등록한 AWS 연결(connection_id)이 필요합니다")
        if not ct_service.get_connection(connection_id):
            raise ValueError(f"connection_id {connection_id}에 해당하는 AWS 연결이 없습니다")


def create_job(job_type: str, target: str, interval_hours: int, connection_id: int | None = None) -> dict:
    validate(job_type, target, interval_hours, connection_id)
    job = {
        "job_type": job_type,
        "target": target.strip(),
        "interval_hours": interval_hours,
        "connection_id": connection_id if job_type in AWS_JOB_TYPES else None,
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
    elif job["job_type"] == "cloudwatch_logs":
        await _run_cloudwatch_logs(job)
    elif job["job_type"] == "guardduty_findings":
        await _run_guardduty_findings(job)


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


def _guardduty_severity_label(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def _run_cloudwatch_logs(job: dict) -> None:
    """AWS CloudWatch Logs 로그 그룹을 App 17의 AWS 연결로 조회 — 원시 텍스트 로그라
    CloudTrail과 마찬가지로 Claude(`analyze_logs()`)에 그대로 흘려보내 위협 여부를 판단한다."""
    conn = ct_service.get_connection(job.get("connection_id"))
    if not conn:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": "AWS 연결을 찾을 수 없습니다 (App 17에서 삭제되었을 수 있음)"})
        return

    try:
        session = ct_service.assume_role(conn["role_arn"], conn.get("external_id", ""), conn.get("region", ""))
        logs_client = session.client("logs")
        start_ms = int((datetime.now(timezone.utc).timestamp() - job["interval_hours"] * 3600) * 1000)
        events: list[dict] = []
        kwargs = {"logGroupName": job["target"], "startTime": start_ms}
        while len(events) < MAX_CLOUDWATCH_EVENTS:
            resp = logs_client.filter_log_events(**kwargs)
            events.extend(resp.get("events", []))
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token
    except Exception as e:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": str(e)})
        return

    if not events:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": None, "last_summary": "새 이벤트 없음"})
        return

    lines = [f"{e.get('timestamp')} {e.get('message', '').strip()}" for e in events[:MAX_CLOUDWATCH_EVENTS]]
    log_content = "\n".join(lines)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, analyze_logs, log_content)
    result["filename"] = f"cloudwatch:{job['target']}"
    result["raw_log"] = log_content
    result["id"] = db.add_entry("dashboard", result)

    await notify.alert_if_critical(
        "dashboard", result.get("threat_level") == "CRITICAL", "CRITICAL",
        f"[CloudWatch Logs: {job['target']}] {result.get('summary', '')}", result["id"],
    )

    db.update_entry(APP_NAME, job["id"], {
        **job, "last_run_at": _now(), "last_error": None,
        "last_summary": f"{len(events)}개 이벤트 분석",
    })


async def _run_guardduty_findings(job: dict) -> None:
    """AWS GuardDuty는 자체 ML로 이미 위협 심각도(Severity 0~10)를 계산해주므로,
    CloudTrail/CloudWatch와 달리 Claude 재분석 없이 그 결과를 그대로 dashboard
    히스토리 형식으로 매핑한다 — 원가 절약 + AWS가 이미 검증한 판정을 그대로 신뢰."""
    conn = ct_service.get_connection(job.get("connection_id"))
    if not conn:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": "AWS 연결을 찾을 수 없습니다 (App 17에서 삭제되었을 수 있음)"})
        return

    try:
        session = ct_service.assume_role(conn["role_arn"], conn.get("external_id", ""), conn.get("region", ""))
        gd = session.client("guardduty")
        detector_id = job["target"].strip()
        if not detector_id:
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                raise RuntimeError("이 AWS 계정에 활성화된 GuardDuty Detector가 없습니다")
            detector_id = detectors[0]

        finding_ids = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
        ).get("FindingIds", [])
        findings = []
        if finding_ids:
            findings = gd.get_findings(
                DetectorId=detector_id, FindingIds=finding_ids[:MAX_GUARDDUTY_FINDINGS]
            ).get("Findings", [])
    except Exception as e:
        db.update_entry(APP_NAME, job["id"], {**job, "last_run_at": _now(), "last_error": str(e)})
        return

    fingerprint = sorted(f["Id"] for f in findings)
    previous = set(job.get("last_fingerprint", []))
    new_findings = [f for f in findings if f["Id"] not in previous]
    new_severe = [f for f in new_findings if _guardduty_severity_label(f.get("Severity", 0)) in ("CRITICAL", "HIGH")]

    if new_severe:
        titles = ", ".join(f.get("Title", f["Id"]) for f in new_severe[:5])
        entry = {
            "summary": f"GuardDuty 신규 탐지 {len(new_severe)}건: {titles}",
            "threat_level": "CRITICAL" if any(_guardduty_severity_label(f.get("Severity", 0)) == "CRITICAL" for f in new_severe) else "HIGH",
            "events": [{
                "id": f["Id"],
                "timestamp": f.get("UpdatedAt"),
                "severity": _guardduty_severity_label(f.get("Severity", 0)),
                "category": f.get("Type", "GuardDuty"),
                "description": f.get("Description", f.get("Title", "")),
                "source_ip": ((f.get("Service", {}).get("Action", {}).get("NetworkConnectionAction", {}) or {}).get("RemoteIpDetails", {}) or {}).get("IpAddressV4"),
                "affected_resource": f.get("Resource", {}).get("ResourceType"),
                "remediation": "AWS GuardDuty 콘솔에서 상세 조사 후 조치하세요.",
            } for f in new_severe],
            "statistics": {"total_events": len(new_severe)},
            "filename": "guardduty",
        }
        entry["id"] = db.add_entry("dashboard", entry)
        await notify.alert_if_critical("dashboard", True, "CRITICAL", entry["summary"], entry["id"])

    db.update_entry(APP_NAME, job["id"], {
        **job, "last_run_at": _now(), "last_error": None,
        "last_fingerprint": fingerprint,
        "last_summary": f"총 {len(findings)}건 중 신규 {len(new_findings)}건(고위험 {len(new_severe)}건)",
    })
