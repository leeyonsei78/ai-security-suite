"""App 5(인시던트 리스폰스 어시스턴트)의 오프라인(폐쇄망) 모드.

App 5의 입력은 자유 텍스트 전문이 아니라 드롭다운(사고 유형×심각도)+짧은 상황 설명이라,
포트스캔/코드처럼 정규식으로 "탐지"할 대상 자체가 없다. 대신 mock_incident.py에 이미 있는
실전 IR(사고 대응) 베스트 프랙티스 플레이북(6종 유형×6단계)을 기반 지식으로 삼되, Mock과
달리 사용자가 실제로 고른 심각도와 입력한 상황 설명을 요약문에 실제로 반영한다 — Mock은
severity/description을 완전히 무시하고 고정 문구만 반환하는 반면, 이 엔진은 최소한 "실제
입력을 반영한 결과"라는 원칙을 지킨다.
"""
from services.mock_incident import _PLANS

_SEVERITY_NOTE = {
    "CRITICAL": "🔴 CRITICAL 등급 — 모든 단계를 최우선·병렬로 진행하고 즉시 경영진 에스컬레이션이 필요합니다.",
    "HIGH": "🟠 HIGH 등급 — 통상보다 빠른 대응이 필요합니다. 즉시조치~봉쇄 단계를 최우선으로 처리하세요.",
    "MEDIUM": "🟡 MEDIUM 등급 — 정해진 절차대로 순차 대응하되 확산 여부를 계속 모니터링하세요.",
    "LOW": "🟢 LOW 등급 — 표준 절차로 대응 가능하나 유사 사고 재발 여부는 계속 추적하세요.",
}

_PII_KEYWORDS = ("개인정보", "고객", "주민등록번호", "카드", "회원", "이메일", "계정정보")
_SCALE_KEYWORDS = {
    "대규모": ("전사", "전체", "모든", "대량", "수백", "수천"),
}

# 사고 유형은 카드 클릭(incident_type)으로만 결정되고 대응 계획(플레이북)도 그 값만 보고 고정되어,
# 사용자가 카드를 잘못 클릭한 채 상황 설명에 완전히 다른 유형을 적어도(예: "피싱 공격" 카드를 선택한
# 채 "랜섬웨어 감염"이라고 입력) 아무 경고 없이 엉뚱한 체크리스트가 그대로 나가는 실제 문제가 있었음
# — 상황 설명에서 다른 유형을 강하게 시사하는 키워드를 찾아 경고하는 최소한의 안전장치.
_TYPE_LABELS = {
    "ransomware": "랜섬웨어", "data_breach": "데이터 유출", "ddos": "DDoS 공격",
    "phishing": "피싱 공격", "malware": "악성코드", "insider_threat": "내부자 위협",
}
_TYPE_KEYWORDS = {
    "ransomware": ("랜섬웨어", "몸값", "암호화", "랜섬노트", "복호화 요구"),
    "data_breach": ("데이터 유출", "정보 유출", "유출됐", "유출되었", "탈취", "다크웹"),
    "ddos": ("ddos", "디도스", "트래픽 폭주", "서비스 거부", "가용성 장애"),
    "phishing": ("피싱", "스미싱", "스피어피싱"),
    "malware": ("악성코드", "바이러스", "트로이목마", "스파이웨어", "멀웨어"),
    "insider_threat": ("내부자", "퇴사자", "내부 직원"),
}


def _detect_type_mismatch(incident_type: str, description: str) -> str | None:
    if not description:
        return None
    lowered = description.lower()
    own_keywords = _TYPE_KEYWORDS.get(incident_type, ())
    if any(k.lower() in lowered for k in own_keywords):
        return None  # 선택한 유형 자체를 시사하는 키워드가 있으면 불일치로 보지 않음
    for other_type, keywords in _TYPE_KEYWORDS.items():
        if other_type == incident_type:
            continue
        if any(k.lower() in lowered for k in keywords):
            return (
                f"⚠️ 선택하신 사고 유형은 '{_TYPE_LABELS.get(incident_type, incident_type)}'인데, "
                f"상황 설명은 '{_TYPE_LABELS.get(other_type, other_type)}'을(를) 가리키는 것처럼 보입니다 — "
                "카드를 잘못 선택하지 않았는지 확인하세요. 아래 체크리스트는 현재 선택된 유형 기준으로 생성됩니다."
            )
    return None

ENGINE_DISCLAIMER = (
    "이 대응 계획은 네트워크 연결 없이 동작하는 사전 정의된 실전 IR(사고 대응) 베스트 프랙티스 "
    "플레이북입니다 — AI가 이 사고의 세부 정황을 새로 분석해 작성한 것이 아니라, 사고 유형별 "
    "표준 절차에 입력하신 심각도·상황 설명을 반영해 조정한 것입니다. 이 사고의 특수성이 크다면 "
    "인터넷 또는 로컬 LLM 연결 시 AI 모드로 재생성하는 것을 권장합니다."
)


def analyze_offline(incident_type: str, severity: str, description: str) -> dict:
    plan = _PLANS.get(incident_type, _PLANS["malware"])
    sev_note = _SEVERITY_NOTE.get((severity or "").upper(), "")

    notes = []
    mismatch_note = _detect_type_mismatch(incident_type, description)
    if mismatch_note:
        notes.append(mismatch_note)
    if description and any(k in description for k in _PII_KEYWORDS):
        notes.append(
            "입력하신 설명에 개인정보 관련 키워드가 포함되어 있습니다 — 개인정보보호법상 신고·통지 "
            "의무 여부를 법무팀/개인정보보호책임자와 함께 조기에 확인하세요."
        )
    if description and any(k in description for k in _SCALE_KEYWORDS["대규모"]):
        notes.append("설명상 피해 규모가 커 보입니다 — 경영진 보고와 외부 커뮤니케이션(고객 공지·PR) 준비를 조기에 시작하세요.")

    summary_parts = [plan["summary"]]
    if sev_note:
        summary_parts.append(sev_note)
    if description:
        summary_parts.append(f"입력하신 상황: {description.strip()[:300]}")
    summary_parts.extend(notes)

    return {
        "incident_type": incident_type,
        "severity": severity,
        "description": description,
        "summary": " ".join(summary_parts),
        "estimated_time": plan["estimated_time"],
        "key_contacts": plan["key_contacts"],
        "phases": plan["phases"],
        "engine_note": ENGINE_DISCLAIMER,
    }
