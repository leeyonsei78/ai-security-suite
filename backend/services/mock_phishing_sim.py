"""피싱 모의훈련 이메일 생성기 Mock 데이터.

시나리오 유형별로 큐레이션된 예시 하나씩을 제공한다. 실제 브랜드/도메인을 사칭하지 않고
전부 가상의 회사(ACME Corp, App 9 OSINT 챌린지와 동일한 가상 회사를 재사용)와
.example 도메인만 사용해, 그대로 복사해도 실제 공격에 쓸 수 없도록 한다.
"""

MOCK_SCENARIOS = {
    "it_password_reset": {
        "subject": "[중요] ACME 계정 비밀번호가 24시간 후 만료됩니다",
        "sender_display_name": "ACME IT지원팀",
        "sender_domain": "acme-it-support.example",
        "body": (
            "안녕하세요,\n\n"
            "보안 정책에 따라 회원님의 ACME 계정 비밀번호가 24시간 이내에 만료될 예정입니다. "
            "만료 전 아래 링크에서 비밀번호를 갱신하지 않으면 계정 접근이 제한될 수 있습니다.\n\n"
            "[지금 비밀번호 갱신하기]\n\n"
            "본 안내는 발신 전용이며, 회신하실 수 없습니다.\n\n"
            "ACME IT지원팀"
        ),
        "cta_text": "지금 비밀번호 갱신하기",
        "red_flags": [
            {"signal": "발신 도메인 불일치", "explanation": "실제 사내 도메인(acme-corp.example)이 아닌 acme-it-support.example — IT팀을 연상시키지만 공식 도메인이 아닙니다."},
            {"signal": "긴급성 조성", "explanation": "'24시간 이내', '접근 제한' 같은 표현으로 클릭을 서두르게 만듭니다."},
            {"signal": "회신 차단", "explanation": "'회신하실 수 없습니다'로 발신자에게 직접 확인하는 것을 막습니다."},
            {"signal": "링크 텍스트만 있고 실제 URL 미표기", "explanation": "실제 환경이라면 링크에 마우스를 올렸을 때 표시되는 URL이 표시 텍스트와 다를 가능성이 높습니다."},
        ],
        "difficulty_rationale": "가장 흔한 유형의 전형적인 신호(긴급성+도메인 불일치)만 사용해 초급자도 알아채기 쉽게 구성.",
    },
    "parcel_delivery": {
        "subject": "[배송안내] 통관 절차가 보류되었습니다 (주문번호 KR-88213)",
        "sender_display_name": "택배 배송 고객센터",
        "sender_domain": "parcel-tracking-kr.example",
        "body": (
            "고객님의 상품이 통관 절차 중 보류되었습니다.\n\n"
            "관세 미납으로 인해 배송이 중단된 상태이며, 3일 이내 미납 관세(2,500원)를 결제하지 않으면 "
            "상품이 반송 처리됩니다.\n\n"
            "[통관 정보 확인 및 결제하기]\n\n"
            "* 본 안내는 시스템에서 자동 발송되었습니다."
        ),
        "cta_text": "통관 정보 확인 및 결제하기",
        "red_flags": [
            {"signal": "소액 결제 유도", "explanation": "카드 정보를 입력시키기 위해 부담 없어 보이는 소액(2,500원)을 요구하는 전형적인 수법입니다."},
            {"signal": "본인이 주문한 적 없는 상품", "explanation": "실제로 해당 주문번호로 주문한 적이 있는지 확인하지 않고 클릭하게 만듭니다."},
            {"signal": "발신 도메인이 특정 택배사와 무관", "explanation": "실제 택배사 공식 도메인이 아닌 범용적인 이름(parcel-tracking-kr.example)을 사용합니다."},
            {"signal": "반송 위협", "explanation": "짧은 기한(3일) 내 반송된다는 압박으로 판단 시간을 줄입니다."},
        ],
        "difficulty_rationale": "결제 유도형 — 소액이라 경계심이 낮아지는 심리를 이용하므로 중급 신호로 분류.",
    },
    "hr_payroll": {
        "subject": "2026년 1월 급여명세서가 발행되었습니다",
        "sender_display_name": "ACME 인사팀",
        "sender_domain": "acme-hr-notice.example",
        "body": (
            "안녕하세요, ACME 인사팀입니다.\n\n"
            "2026년 1월 급여명세서가 사내 포털에 발행되었습니다. 아래 링크에서 사번과 비밀번호로 "
            "로그인하시어 확인 부탁드립니다.\n\n"
            "[급여명세서 확인하기]\n\n"
            "문의사항은 인사팀으로 연락 바랍니다."
        ),
        "cta_text": "급여명세서 확인하기",
        "red_flags": [
            {"signal": "사내 인증정보 입력 유도", "explanation": "'사번과 비밀번호로 로그인'을 외부 링크에서 요구 — 실제 사내 SSO라면 이미 로그인된 상태에서 접근해야 정상입니다."},
            {"signal": "급여라는 민감 주제", "explanation": "누구나 관심을 가질 만한 주제를 이용해 클릭률을 높입니다."},
            {"signal": "발신 도메인이 사내 정식 도메인과 다름", "explanation": "acme-hr-notice.example — 실제 인사 시스템 도메인이 아닙니다."},
            {"signal": "문의 연락처가 구체적이지 않음", "explanation": "'인사팀으로 연락'만 있고 실제 내선번호·이메일 등 검증 가능한 정보가 없습니다."},
        ],
        "difficulty_rationale": "인증정보 직접 탈취 시도가 포함되어 실제 피해로 이어질 위험이 커 중급~고급 신호로 분류.",
    },
    "ceo_fraud": {
        "subject": "긴급 요청 - 지금 통화 가능한가요?",
        "sender_display_name": "김대표 (대표이사)",
        "sender_domain": "acme-ceo-office.example",
        "body": (
            "지금 회의 중이라 전화를 못 받는데, 급하게 처리할 일이 있어요.\n\n"
            "협력사에 기프트카드 결제가 필요한 상황인데, 회의 끝나고 바로 정산할 테니 "
            "구글기프트카드 50만원 상당 구매해서 코드를 사진 찍어 보내주실 수 있을까요? "
            "지금 이 메일로만 회신 부탁드려요, 급합니다.\n\n"
            "감사합니다."
        ),
        "cta_text": "(버튼 없음 — 회신 유도형)",
        "red_flags": [
            {"signal": "경영진 사칭 + 긴급성", "explanation": "대표이사를 사칭하며 '지금 통화 불가능'이라는 핑계로 직접 확인을 차단합니다."},
            {"signal": "비정상적인 결제 방식", "explanation": "정상적인 업무 프로세스라면 기프트카드로 협력사 결제를 하는 경우가 없습니다."},
            {"signal": "발신 도메인 확인 필요성", "explanation": "acme-ceo-office.example처럼 그럴듯하지만 실제 임원 이메일 도메인과 다릅니다."},
            {"signal": "승인 절차 우회", "explanation": "정식 결재/구매 프로세스 없이 개인이 즉시 처리하도록 요구합니다."},
        ],
        "difficulty_rationale": "이메일 자체에는 링크나 첨부파일이 없어 스팸 필터에 걸리지 않는 경우가 많고, 심리적 압박(직속 상사·긴급)이 강해 고급 신호로 분류.",
    },
    "cloud_share": {
        "subject": "'2026 예산안 최종.xlsx' 문서가 공유되었습니다",
        "sender_display_name": "클라우드 문서 공유 알림",
        "sender_domain": "docshare-notify.example",
        "body": (
            "박이사 님이 회원님과 문서를 공유했습니다.\n\n"
            "'2026 예산안 최종.xlsx'\n\n"
            "[문서 열람하기]\n\n"
            "이 링크는 7일간 유효합니다."
        ),
        "cta_text": "문서 열람하기",
        "red_flags": [
            {"signal": "구체적이지만 확인 불가능한 발신자", "explanation": "'박이사'라는 이름만 있고 실제로 그런 이사가 있는지, 실제로 공유했는지 확인할 방법이 이메일 안에 없습니다."},
            {"signal": "호기심 유발형 파일명", "explanation": "'예산안 최종'처럼 누구나 열어보고 싶어할 만한 민감한 제목을 사용합니다."},
            {"signal": "실제 클라우드 서비스 도메인이 아님", "explanation": "docshare-notify.example — 실제 사용 중인 클라우드 서비스(구글/MS 등)의 공식 도메인이 아닙니다."},
            {"signal": "유효기간 압박", "explanation": "'7일간 유효'로 나중에 확인하지 않고 바로 클릭하도록 유도합니다."},
        ],
        "difficulty_rationale": "실제 협업 알림 메일과 매우 유사한 형식이라 발신 도메인을 직접 확인하지 않으면 알아채기 어려워 고급 신호로 분류.",
    },
    "security_alert": {
        "subject": "[보안경고] 새로운 기기에서 로그인이 감지되었습니다",
        "sender_display_name": "ACME 보안팀",
        "sender_domain": "acme-security-alert.example",
        "body": (
            "회원님의 계정에 등록되지 않은 기기(위치: 해외)에서 로그인 시도가 있었습니다.\n\n"
            "본인이 아니라면 즉시 계정을 보호해야 합니다.\n\n"
            "[계정 보안 즉시 확인하기]\n\n"
            "24시간 내 조치가 없으면 계정이 임시 잠금될 수 있습니다."
        ),
        "cta_text": "계정 보안 즉시 확인하기",
        "red_flags": [
            {"signal": "공포 유발", "explanation": "'해외 로그인 시도'로 즉각적인 불안감을 조성해 이성적 판단을 어렵게 만듭니다."},
            {"signal": "보안팀을 사칭한 도메인", "explanation": "acme-security-alert.example — 진짜 보안팀 공지가 아니라 그럴듯하게 만든 이름입니다."},
            {"signal": "'계정 보안 확인'이 실제로는 자격증명 입력 페이지로 연결", "explanation": "정상적인 보안 알림이라면 앱/포털에 직접 로그인해서 확인하도록 안내하지, 이메일 링크로 로그인시키지 않습니다."},
            {"signal": "잠금 위협 + 짧은 기한", "explanation": "'24시간', '임시 잠금'으로 판단을 서두르게 합니다."},
        ],
        "difficulty_rationale": "보안 경고 자체가 방어 심리를 자극해 오히려 클릭을 유도하는 역설적 구조라 중급 신호로 분류.",
    },
}


def generate_mock_phishing_sim(scenario_type: str, difficulty: str, context: str) -> dict:
    base = MOCK_SCENARIOS.get(scenario_type, MOCK_SCENARIOS["it_password_reset"])
    result = dict(base)
    result["scenario_type"] = scenario_type
    result["difficulty"] = difficulty
    result["context_note"] = (
        f"(Mock 모드에서는 입력하신 조직 컨텍스트('{context[:60]}...')가 실제 문구에 반영되지 않습니다 — "
        "Live 모드에서는 AI가 이를 반영해 맞춤 생성합니다."
        if context.strip() else "조직 컨텍스트가 입력되지 않아 일반적인 예시로 생성되었습니다."
    )
    return result
