"""App 11(보안 정책 생성기)의 오프라인(폐쇄망) 모드.

이 앱은 "탐지"가 아니라 "생성" 도구라 vuln_offline_engine.py처럼 자유 텍스트를 정규식으로
판정하는 방식이 그대로 맞지 않는다. 대신 mock_policy.py의 큐레이션 템플릿을 기반으로,
사용자가 실제로 입력한 환경 설명에서 키워드를 추출해 가볍게 커스터마이즈한다 — Mock 모드는
템플릿을 그대로 반환하지만, 오프라인 모드는 실제 입력을 반영한다는 점이 다르다.
"""
from services.mock_policy import _TEMPLATES, _COMPLIANCE_ITEMS

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 템플릿+키워드 매칭 기반 오프라인 엔진이 생성했습니다 — "
    "환경 유형별로 큐레이션된 표준 정책 템플릿에 입력하신 환경 설명에서 발견된 키워드를 반영해 보완한 것으로, "
    "AI가 환경 설명 전체를 이해해 처음부터 새로 작성하는 것은 아닙니다. 인터넷 또는 로컬 LLM을 사용할 수 "
    "있게 되면 AI 모드로 재생성하면 환경 설명 전체를 반영한 맞춤 초안을 받을 수 있습니다."
)

_TECH_KEYWORDS = {
    "nginx": "Nginx (웹 서버/리버스 프록시)",
    "apache": "Apache 웹 서버",
    "mysql": "MySQL 데이터베이스",
    "postgres": "PostgreSQL 데이터베이스",
    "mariadb": "MariaDB 데이터베이스",
    "redis": "Redis (인메모리 데이터스토어)",
    "mongodb": "MongoDB",
    "kubernetes": "Kubernetes 클러스터",
    "k8s": "Kubernetes 클러스터",
    "docker": "Docker 컨테이너",
    "vpn": "VPN",
    "s3": "S3 (오브젝트 스토리지)",
    "iam": "IAM 권한 관리",
    "0.0.0.0": "전체 공개(0.0.0.0) 바인딩",
    "root": "root 계정 직접 사용",
    "평문": "평문 저장/전송",
    "하드코딩": "하드코딩된 자격증명",
}

_COMPLIANCE_KEYWORDS = {
    "PCI-DSS": ["pci", "카드", "결제"],
    "개인정보보호법": ["개인정보", "주민등록번호", "고유식별정보"],
    "GDPR": ["gdpr", "유럽", "eu "],
    "HIPAA": ["hipaa", "의료", "건강정보"],
}


def generate_offline(environment_type: str, compliance: list[str], description: str) -> dict:
    template = _TEMPLATES.get(environment_type, _TEMPLATES["web_server"])
    desc_lower = description.lower()

    found_tech = [label for kw, label in _TECH_KEYWORDS.items() if kw in desc_lower]

    mentioned_compliance = set()
    for fw, keywords in _COMPLIANCE_KEYWORDS.items():
        if any(kw in desc_lower for kw in keywords):
            mentioned_compliance.add(fw)
    missing_but_mentioned = sorted(fw for fw in mentioned_compliance if fw not in compliance)

    frameworks = compliance if compliance else list(_COMPLIANCE_ITEMS.keys())
    compliance_mapping = [
        {"framework": fw, "items": _COMPLIANCE_ITEMS[fw]}
        for fw in frameworks
        if fw in _COMPLIANCE_ITEMS
    ]

    keyword_notes = []
    if found_tech:
        keyword_notes.append(f"환경 설명에서 다음 기술/구성 요소가 언급되었습니다: {', '.join(found_tech)} — 아래 정책 중 관련 항목을 우선 검토하세요.")
    if missing_but_mentioned:
        keyword_notes.append(f"환경 설명에 '{', '.join(missing_but_mentioned)}' 관련 키워드가 있으나 컴플라이언스로 선택되지 않았습니다 — 필요하다면 선택 후 다시 생성하세요.")

    risk_notes = list(template["risk_notes"])
    if "0.0.0.0" in desc_lower or "전체 공개" in description:
        risk_notes.insert(0, "환경 설명에 '전체 공개(0.0.0.0)' 관련 표현이 있습니다 — 불필요하게 공개된 포트/서비스가 있는지 최우선으로 점검하세요.")
    if "하드코딩" in description or "평문" in description:
        risk_notes.insert(0, "환경 설명에 하드코딩/평문 저장 관련 표현이 있습니다 — 시크릿 관리 체계 도입을 우선 검토하세요.")

    summary = template["summary"]
    if found_tech:
        summary += f" (환경 설명에서 발견된 키워드: {', '.join(found_tech)})"

    return {
        "summary": summary,
        "firewall_rules": template["firewall_rules"],
        "policies": template["policies"],
        "risk_notes": risk_notes,
        "compliance_mapping": compliance_mapping,
        "keyword_notes": keyword_notes,
        "engine_note": ENGINE_DISCLAIMER,
    }
