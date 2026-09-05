"""App 14(피싱 모의훈련 이메일 생성기)의 오프라인(폐쇄망) 모드.

mock_phishing_sim.py의 큐레이션 시나리오 템플릿을 기반으로, 조직 컨텍스트 자유 텍스트에서
발견한 조직명을 본문/제목/발신 표시 이름에만 반영한다. 발신 도메인(sender_domain)은 안전
설계상 이 모드에서도 절대 건드리지 않고 항상 .example 그대로 유지한다.
"""
import re

from services.mock_phishing_sim import MOCK_SCENARIOS

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 템플릿 기반 오프라인 엔진이 생성했습니다 — "
    "시나리오별 표준 템플릿에 입력하신 조직 컨텍스트에서 발견한 조직명 등을 반영한 것으로, "
    "AI가 맥락 전체를 이해해 새로 작성하는 것은 아닙니다. 발신 도메인은 안전을 위해 이 모드에서도 "
    "항상 .example로 고정됩니다. 인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 재생성해보세요."
)


# 회사명 뒤에 붙는 법인 접미사(주식회사/㈜/Corp/Inc/스타트업/회사)를 찾아 그 "앞부분"만 회사명으로
# 캡처한다. 접미사 자체를 포함한 통짜 매칭을 쓰면(예: 접미사 목록에 "회사"가 있으므로) "주식회사"라는
# 문자열 안에서 "주식"+"회사"로 스스로와 매칭돼버려 정작 앞의 실제 상호명("테크노바")을 놓치는
# 자기참조 버그가 생긴다 — 그래서 상호명과 접미사를 별도 그룹으로 분리하고 상호명은 최소 2자,
# 사이의 공백(흔한 "테크노바 주식회사" 표기)도 \s*로 허용한다.
_ORG_NAME_RE = re.compile(r"([가-힣A-Za-z0-9]{2,20})\s*(?:주식회사|㈜|Corp\.?|Inc\.?|스타트업|회사)")

# "회사"는 접미사 중 가장 일반적인 단어라 "우리 회사"/"저희 회사"/"당사"처럼 회사 이름을 대지 않고
# 자기 회사를 가리키는 흔한 대명사+"회사" 조합에도 매칭돼버린다(예: "우리 회사는 테크노바 주식회사"에서
# 실제 상호명 "테크노바"보다 앞에 있는 "우리"가 먼저 잡혀버림) — 이런 일반 대명사가 캡처되면 건너뛰고
# 다음 후보를 찾는다.
_GENERIC_ORG_WORDS = {"우리", "저희", "당사", "저희회사", "우리회사", "당사는"}


def generate_offline(scenario_type: str, difficulty: str, context: str) -> dict:
    base = MOCK_SCENARIOS.get(scenario_type, MOCK_SCENARIOS["it_password_reset"])
    result = dict(base)
    result["scenario_type"] = scenario_type
    result["difficulty"] = difficulty

    org_name = next(
        (m.group(1) for m in _ORG_NAME_RE.finditer(context) if m.group(1) not in _GENERIC_ORG_WORDS),
        None,
    )
    if org_name:
        # sender_domain은 절대 치환 대상에 넣지 않는다 — 안전 설계(.example 고정)의 핵심.
        result["subject"] = result["subject"].replace("ACME", org_name)
        result["body"] = result["body"].replace("ACME", org_name)
        result["sender_display_name"] = result["sender_display_name"].replace("ACME", org_name)
        result["context_note"] = (
            f"오프라인 모드: 조직 컨텍스트에서 발견한 조직명('{org_name}')을 본문에 반영했습니다. "
            "발신 도메인은 안전을 위해 여전히 .example로 고정됩니다."
        )
    else:
        result["context_note"] = (
            "오프라인 모드: 조직 컨텍스트에서 조직명을 추출하지 못해 기본 예시(ACME Corp) 그대로 생성되었습니다."
            if context.strip() else "조직 컨텍스트가 입력되지 않아 기본 예시로 생성되었습니다."
        )

    result["engine_note"] = ENGINE_DISCLAIMER
    return result
