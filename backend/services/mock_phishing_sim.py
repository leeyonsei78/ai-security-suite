"""피싱 모의훈련 이메일 생성기 Mock/오프라인 데이터.

시나리오 유형 6종 x 난이도 3단계(초급/중급/고급) = 18개를 큐레이션한다. 난이도별로
같은 시나리오라도 위험 신호의 노출 정도(URL 노출 여부, 긴급성 표현, 발신 도메인의
부자연스러움, 위협 문구 유무 등)를 실제로 다르게 작성해, 난이도를 바꿨을 때 결과물이
실제로 달라지도록 한다 — 이전 버전은 시나리오당 템플릿이 하나뿐이라 난이도를 바꿔도
동일한 내용이 그대로 나오는 문제가 있었음.

실제 브랜드/도메인을 사칭하지 않고 전부 가상의 회사(ACME Corp, App 9 OSINT 챌린지와
동일한 가상 회사를 재사용)와 .example 도메인만 사용해, 그대로 복사해도 실제 공격에
쓸 수 없도록 한다.
"""

MOCK_SCENARIOS = {
    "it_password_reset": {
        "beginner": {
            "subject": "[긴급!!!] ACME 계정 비밀번호가 24시간 후 만료됩니다",
            "sender_display_name": "ACME IT지원팀",
            "sender_domain": "acme-it-verify-center.example",
            "body": (
                "고객님,\n\n"
                "지금 즉시 확인하지 않으면 계정이 잠깁니다!!\n\n"
                "보안 정책에 따라 회원님의 ACME 계정 비밀번호가 24시간 이내에 만료될 예정입니다. "
                "만료 전 아래 링크에서 비밀번호를 갱신하지 않으면 계정 접근이 영구적으로 제한됩니다.\n\n"
                "지금 바로 갱신: http://acme-it-verify-center.example/reset?id=8821\n\n"
                "본 안내는 발신 전용이며, 회신하실 수 없습니다.\n\n"
                "ACME IT지원팀"
            ),
            "cta_text": "지금 비밀번호 갱신하기",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "실제 사내 도메인(acme-corp.example)이 아닌 acme-it-verify-center.example — 'verify-center'처럼 억지로 붙인 단어가 그대로 보입니다."},
                {"signal": "본문에 URL 원문 노출", "explanation": "정상적인 알림 메일과 달리 링크 텍스트가 아닌 실제 URL이 그대로 노출되어 있어 목적지를 바로 확인할 수 있습니다."},
                {"signal": "과장된 긴급성·위협", "explanation": "'지금 즉시', '영구적으로 제한' 등 실제 IT 부서라면 잘 쓰지 않는 과장된 표현을 씁니다."},
                {"signal": "느낌표 남용", "explanation": "'!!' 등 비격식적인 문장부호가 공식 안내 메일답지 않습니다."},
                {"signal": "회신 차단", "explanation": "'회신하실 수 없습니다'로 발신자에게 직접 확인하는 것을 막습니다."},
            ],
            "difficulty_rationale": "도메인의 부자연스러운 단어, 본문에 노출된 URL, 과장된 위협 문구가 동시에 드러나 누구나 알아챌 수 있도록 구성했습니다.",
        },
        "intermediate": {
            "subject": "[중요] ACME 계정 비밀번호가 곧 만료됩니다",
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
            "difficulty_rationale": "긴급성+도메인 불일치라는 전형적인 신호를 쓰되 URL을 직접 노출하지 않고 버튼으로만 표시해, 도메인을 자세히 확인해야 알아챌 수 있도록 구성했습니다.",
        },
        "advanced": {
            "subject": "[알림] 비밀번호 정책 업데이트 안내 (Ticket #IT-58231)",
            "sender_display_name": "ACME IT Service Desk",
            "sender_domain": "acme-corp-support.example",
            "body": (
                "안녕하세요,\n\n"
                "ACME 정보보안팀 정책에 따라 전 직원의 비밀번호 유효기간이 90일로 단축 적용되어 순차 안내드리고 있습니다. "
                "회원님의 계정(마지막 로그인: 2026-09-08 14:22, 서울)은 이번 정책 적용 대상으로 확인되어, "
                "다음 로그인 전 비밀번호 갱신을 권장드립니다.\n\n"
                "[비밀번호 갱신 절차 안내]\n\n"
                "갱신 관련 문의는 IT Service Desk(내선 1544, itsupport@acme-corp-support.example)로 연락 주시면 "
                "안내해드리겠습니다.\n\n"
                "ACME IT Service Desk\n"
                "Ticket #IT-58231\n\n"
                "본 메일은 ACME 정보보안팀 검토 절차를 거쳐 발송되었으며, 수신자 외 공유를 금합니다."
            ),
            "cta_text": "비밀번호 갱신 절차 안내",
            "red_flags": [
                {"signal": "실제 도메인을 통째로 포함한 콤보스쿼팅", "explanation": "acme-corp-support.example은 실제 사내 도메인(acme-corp.example)을 그대로 포함하고 있어 얼핏 보면 진짜처럼 보이지만, 뒤에 '-support'가 붙은 완전히 다른 도메인입니다 — 이런 수법을 '콤보스쿼팅(combosquatting)'이라 부릅니다."},
                {"signal": "실제 시스템 로그를 흉내낸 구체적 정보", "explanation": "'마지막 로그인: 2026-09-08 14:22, 서울'처럼 실제 로그인 기록을 조회한 듯한 구체적인 정보로 신뢰도를 높였지만, 이 정보가 진짜 시스템에서 나온 것인지 이메일만으로는 확인할 수 없습니다."},
                {"signal": "가짜 티켓 번호·내선번호·기밀 유지 문구", "explanation": "티켓 번호와 내선번호에 더해 '수신자 외 공유 금지'라는 실제 기업 이메일 하단에서 흔히 보는 문구까지 붙여 공식성을 더했습니다."},
                {"signal": "위협 없이 '권장 사항'으로 서술", "explanation": "'권장드립니다'처럼 강제성 없는 부드러운 표현을 써서 피싱 메일 특유의 압박감이 느껴지지 않습니다."},
            ],
            "difficulty_rationale": "실제 사내 도메인을 그대로 포함하는 콤보스쿼팅 도메인, 가짜 로그인 기록, 티켓 번호, 기밀 유지 문구까지 실제 기업 IT 공지의 형식적 요소를 전부 갖춰 도메인을 문자 단위로 대조하지 않으면 알아채기 매우 어렵습니다.",
        },
    },
    "parcel_delivery": {
        "beginner": {
            "subject": "[긴급!!] 통관 미납금 즉시 결제 필요 (주문번호 KR-88213)",
            "sender_display_name": "택배안내",
            "sender_domain": "parcel-urgent-pay.example",
            "body": (
                "고객님!!\n\n"
                "상품이 통관 보류 중입니다. 아래 링크에서 지금 바로 미납 관세 2,500원을 결제하지 않으면 "
                "오늘 중으로 상품이 폐기됩니다.\n\n"
                "지금 결제: http://parcel-urgent-pay.example/pay?order=KR88213\n\n"
                "* 본 메일은 회신되지 않습니다."
            ),
            "cta_text": "지금 결제하기",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "'urgent-pay'처럼 결제를 재촉하는 단어가 도메인에 그대로 들어가 있습니다."},
                {"signal": "본문에 URL 원문 노출", "explanation": "링크 텍스트가 아닌 실제 URL이 그대로 노출되어 목적지를 바로 확인할 수 있습니다."},
                {"signal": "과장된 위협", "explanation": "'오늘 중 폐기'라는 극단적인 기한 압박은 실제 통관 절차에서 흔하지 않습니다."},
                {"signal": "구체적 택배사명 없음", "explanation": "발신 표시 이름이 '택배안내'로만 되어 있어 어느 업체인지 알 수 없습니다."},
                {"signal": "회신 차단", "explanation": "'회신되지 않습니다'로 발신자 확인을 막습니다."},
            ],
            "difficulty_rationale": "도메인·URL 노출·과장된 위협 문구가 한꺼번에 드러나 누구나 의심할 수 있도록 구성했습니다.",
        },
        "intermediate": {
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
            "difficulty_rationale": "결제 유도형 — 소액이라 경계심이 낮아지는 심리를 이용하고, URL을 직접 노출하지 않아 중급 신호로 분류.",
        },
        "advanced": {
            "subject": "[통관/배송 안내] 관세 정산이 필요합니다 (참조번호 KR-88213-7)",
            "sender_display_name": "종합물류 통관지원센터",
            "sender_domain": "customs-clearance-desk.example",
            "body": (
                "안녕하세요, 고객님.\n\n"
                "해외에서 발송된 상품(참조번호 KR-88213-7, 중량 0.8kg)의 통관 절차 중 일부 관세가 정산되지 않아 "
                "배송이 일시 보류된 상태입니다.\n\n"
                "아래에서 정산 내역을 확인하신 뒤 결제를 진행해주시면 통관이 재개됩니다. 정산 기한은 영업일 기준 "
                "5일이며, 기한 내 미정산 시 통상적인 반송 절차가 적용됩니다.\n\n"
                "[정산 내역 확인하기]\n\n"
                "통관지원센터 고객상담팀 (평일 09:00~18:00)\n\n"
                "* 본 메일은 제휴 물류사를 통해 발송되었습니다."
            ),
            "cta_text": "정산 내역 확인하기",
            "red_flags": [
                {"signal": "그럴듯하지만 무관한 발신 도메인", "explanation": "실제 통관·물류 서비스에서 쓸 법한 이름이지만 특정 업체의 공식 도메인은 아닙니다 — 자세히 보지 않으면 진짜처럼 느껴집니다."},
                {"signal": "여유로운 기한으로 경계심 완화", "explanation": "위협적 표현 없이 '영업일 기준 5일'이라는 여유로운 기한과 '통상적인 절차'라는 표현으로 오히려 신뢰를 유도합니다."},
                {"signal": "구체적 참조번호·중량으로 신뢰도 위장", "explanation": "참조번호(KR-88213-7)와 중량(0.8kg)처럼 실제 배송 시스템에서 나올 법한 세부 정보를 붙였지만, 실제로 조회할 수 있는 공식 채널은 이메일 어디에도 없습니다."},
                {"signal": "'제휴 물류사'로 책임 소재를 흐림", "explanation": "구체적으로 어느 업체와 제휴했는지는 밝히지 않은 채 '제휴'라는 표현만으로 공식성을 더해, 문제가 생겨도 책임을 특정하기 어렵게 만듭니다."},
            ],
            "difficulty_rationale": "실제 통관 절차 용어·참조번호·중량 같은 세부 정보를 자연스럽게 쓰고 위협적 표현을 배제해, 도메인을 직접 대조하지 않으면 진짜 안내처럼 느껴집니다.",
        },
    },
    "hr_payroll": {
        "beginner": {
            "subject": "[필독] ACME 급여명세서 미확인시 지급 보류!!",
            "sender_display_name": "ACME 인사팀",
            "sender_domain": "acme-payroll-alert.example",
            "body": (
                "ACME 직원님!!\n\n"
                "2026년 1월 급여명세서가 발행되었으나 아직 확인하지 않으셨습니다. 오늘 중 확인하지 않으면 "
                "급여 지급이 보류될 수 있습니다.\n\n"
                "지금 확인: http://acme-payroll-alert.example/login?emp=0231\n\n"
                "사번과 비밀번호를 입력해 로그인해주세요.\n\n"
                "ACME 인사팀"
            ),
            "cta_text": "급여명세서 확인하기",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "'payroll-alert'처럼 재촉하는 단어가 도메인에 그대로 들어가 있습니다."},
                {"signal": "본문에 URL 원문 노출", "explanation": "링크 텍스트가 아닌 실제 URL이 그대로 노출됩니다."},
                {"signal": "비정상적인 위협", "explanation": "실제 인사 프로세스에서 이메일 미확인만으로 급여 지급을 보류하는 경우는 없습니다."},
                {"signal": "느낌표 남용과 어색한 호칭", "explanation": "'ACME 직원님!!'처럼 실제 사내 공지에서 잘 쓰지 않는 어색한 표현입니다."},
                {"signal": "이메일에서 직접 사번+비밀번호 요구", "explanation": "정상적인 사내 시스템이라면 이메일 본문 자체에서 비밀번호를 입력하게 하지 않습니다."},
            ],
            "difficulty_rationale": "실무에서 있을 수 없는 위협(급여 보류)과 URL 노출·느낌표 남용이 겹쳐 명백하게 의심스럽도록 구성했습니다.",
        },
        "intermediate": {
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
            "difficulty_rationale": "급여라는 민감한 주제로 클릭을 유도하지만 위협적 표현은 없고, 도메인도 완전히 무관하지는 않아(hr-notice) 자세히 살펴봐야 알아챌 수 있습니다.",
        },
        "advanced": {
            "subject": "[인사공지] 2026년 1월 급여명세서 발행 및 복리후생 개편 안내",
            "sender_display_name": "ACME People Team",
            "sender_domain": "acme-corp-people.example",
            "body": (
                "안녕하세요,\n\n"
                "2026년 1월분 급여명세서가 사내 포털에 게시되었습니다. 아울러 이번 달부터 일부 복리후생 항목이 "
                "개편되어 명세서 항목 구성이 일부 달라졌으니 확인 부탁드립니다.\n\n"
                "평소 이용하시는 사내 포털에 로그인하시어 [급여/복리후생] 메뉴에서 확인하시거나, 포털 접속이 "
                "어려우신 경우 아래 링크로도 확인 가능합니다.\n\n"
                "[급여명세서 확인하기]\n\n"
                "문의: People Team (내선 2410, hr-help@acme-corp-people.example)\n\n"
                "ACME People Team\n"
                "본 메일은 인사팀 확인을 거쳐 발송되었습니다."
            ),
            "cta_text": "급여명세서 확인하기",
            "red_flags": [
                {"signal": "실제 도메인을 통째로 포함한 콤보스쿼팅", "explanation": "acme-corp-people.example은 실제 사내 도메인(acme-corp.example)을 그대로 포함하고 있어 언뜻 보면 진짜처럼 보이지만, 뒤에 '-people'이 붙은 완전히 다른 도메인입니다."},
                {"signal": "정상 절차를 먼저 언급", "explanation": "'평소 이용하시는 사내 포털'을 먼저 언급해 신뢰를 준 뒤, 실제로는 이메일의 별도 링크로 자연스럽게 유도합니다."},
                {"signal": "그럴듯한 이유(복리후생 개편)로 클릭 유도", "explanation": "'복리후생 개편'이라는 실제 있을 법한 사유를 붙여, 평소와 다른 명세서 형식이라도 의심하지 않고 클릭하게 만듭니다."},
                {"signal": "문의 이메일이 발신 도메인과 동일", "explanation": "문의처 이메일 주소가 사내 정식 도메인이 아닌 발신 도메인(acme-corp-people.example)과 같습니다 — 실제라면 별도의 검증된 사내 주소여야 합니다."},
            ],
            "difficulty_rationale": "실제 사내 도메인을 포함하는 콤보스쿼팅 도메인에 더해 '복리후생 개편'이라는 그럴듯한 사유까지 붙여, 정상적인 사내 공지와 형식·내용 모두 구분하기 매우 어렵습니다.",
        },
    },
    "ceo_fraud": {
        "beginner": {
            "subject": "긴급!! 지금 바로 연락주세요",
            "sender_display_name": "김대표",
            "sender_domain": "acme-ceo-urgent.example",
            "body": (
                "지금 급하게 처리할 일이 있어요!!\n\n"
                "구글기프트카드 50만원어치를 지금 바로 사서 코드를 사진찍어 이 메일로 보내주세요. "
                "급합니다!! 지금 통화는 어려우니 메일로만 답장해주세요.\n\n"
                "감사합니다."
            ),
            "cta_text": "(버튼 없음 — 회신 유도형)",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "'ceo-urgent'처럼 긴급함을 강조하는 단어가 도메인에 그대로 들어가 있습니다."},
                {"signal": "느낌표 남용과 급박한 어조", "explanation": "실제 경영진 이메일치고는 지나치게 격식 없는 어조입니다."},
                {"signal": "비정상적인 결제 수단", "explanation": "기프트카드 구매라는, 정상적인 업무 프로세스에는 없는 결제 방식을 아무 설명 없이 요구합니다."},
                {"signal": "전화 확인 원천 차단", "explanation": "'지금 통화는 어려우니'로 발신자 본인 확인 수단을 막습니다."},
                {"signal": "결재 절차 언급 없음", "explanation": "정식 결재/구매 프로세스를 전혀 언급하지 않습니다."},
            ],
            "difficulty_rationale": "비정상적인 결제 수단과 도메인·어조의 어색함이 동시에 드러나 실제 대표 이메일이라고 보기 어렵도록 구성했습니다.",
        },
        "intermediate": {
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
            "difficulty_rationale": "링크나 첨부파일 없이 회신만 유도해 스팸 필터에 걸리지 않을 가능성이 높고, 도메인도 언뜻 그럴듯해 자세히 봐야 부자연스러움을 느낄 수 있습니다.",
        },
        "advanced": {
            "subject": "빠른 확인 부탁드립니다 (건: 협력사 정산)",
            "sender_display_name": "김민석",
            "sender_domain": "acme-corp-office.example",
            "body": (
                "안녕하세요,\n\n"
                "오늘 오전 미팅이 연달아 있어 통화가 어려운데, 협력사 정산 건 때문에 잠깐 확인 부탁드립니다.\n\n"
                "재무팀에 바로 요청하기엔 시간이 촉박해서요 — 우선 제가 안내하는 방식으로 처리해주시고, "
                "나중에 재무팀과 정식으로 정리하겠습니다. 가능하실까요? 이 메일로 답장 주시거나, 급하시면 "
                "010-****-8827로 문자 주셔도 확인됩니다.\n\n"
                "답장 주시면 상세 내용 바로 보내드릴게요.\n\n"
                "감사합니다.\n"
                "김민석 드림"
            ),
            "cta_text": "(버튼 없음 — 회신 유도형)",
            "red_flags": [
                {"signal": "실제 도메인을 통째로 포함한 콤보스쿼팅", "explanation": "acme-corp-office.example은 실제 사내 도메인(acme-corp.example)을 그대로 포함하고 있어 얼핏 보면 진짜처럼 보이지만, 뒤에 '-office'가 붙은 완전히 다른 도메인입니다."},
                {"signal": "직위 대신 실명만 사용", "explanation": "'대표이사' 같은 직위를 명시하지 않고 실명만 써서 '아는 사람'처럼 신뢰를 유도합니다 — 실제 인물인지 별도 확인 없이는 판단할 수 없습니다."},
                {"signal": "가짜 확인 채널 추가 제공", "explanation": "이메일 회신뿐 아니라 개인 휴대전화 문자라는 대체 확인 수단까지 제시해 신뢰도를 높이지만, 이 번호 역시 공격자가 통제하는 채널일 뿐입니다 — 반드시 사내 전화번호부 등 별도로 검증된 경로로 본인 확인을 해야 합니다."},
                {"signal": "다단계 수법", "explanation": "구체적인 비정상 요구(기프트카드 등)를 첫 메일에 드러내지 않고 우선 회신만 유도한 뒤 다음 단계에서 실제 요구를 전달하는 방식이라, 이 메일 하나만으로는 의심하기 어렵습니다."},
            ],
            "difficulty_rationale": "실제 사내 도메인을 포함하는 콤보스쿼팅 도메인에 더해, 공격자가 통제하는 개인 휴대전화 번호를 '확인 채널'로 제시해 회신·문자 확인 양쪽 모두 신뢰하게 만드는 정교한 2단계 수법을 사용했습니다.",
        },
    },
    "cloud_share": {
        "beginner": {
            "subject": "[중요!!] 문서 공유됨 - 24시간 내 미확인시 삭제",
            "sender_display_name": "문서공유알림",
            "sender_domain": "docshare-free-view.example",
            "body": (
                "고객님!!\n\n"
                "'2026 예산안 최종.xlsx' 문서가 공유되었습니다. 24시간 내 확인하지 않으면 공유가 취소되고 "
                "문서가 삭제됩니다.\n\n"
                "지금 확인: http://docshare-free-view.example/view?id=7729\n\n"
                "계정으로 로그인해 확인해주세요."
            ),
            "cta_text": "문서 열람하기",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "'free-view'처럼 억지로 붙인 단어가 도메인에 그대로 들어가 있습니다."},
                {"signal": "본문에 URL 원문 노출", "explanation": "링크 텍스트가 아닌 실제 URL이 그대로 노출됩니다."},
                {"signal": "비정상적인 삭제 위협", "explanation": "'24시간 내 삭제'는 실제 클라우드 공유 서비스가 동작하는 방식이 아닙니다."},
                {"signal": "발신자 익명", "explanation": "'문서공유알림'이라는 익명 표시로 실제 누가 공유했는지 알 수 없습니다."},
                {"signal": "느낌표 남용", "explanation": "'고객님!!'처럼 공식 알림 메일답지 않은 격식 부족이 드러납니다."},
            ],
            "difficulty_rationale": "발신자 정보가 없고 URL 노출·비정상적 삭제 위협까지 겹쳐 실제 클라우드 서비스 알림과 형식이 크게 달라 알아채기 쉽습니다.",
        },
        "intermediate": {
            "subject": "박이사 님이 문서를 공유했습니다: 2026 예산안 최종.xlsx",
            "sender_display_name": "문서 공유 서비스",
            "sender_domain": "docshare-portal.example",
            "body": (
                "안녕하세요,\n\n"
                "박이사 님이 '2026 예산안 최종.xlsx' 문서를 회원님과 공유했습니다. 아래 버튼을 눌러 "
                "문서를 확인해주세요.\n\n"
                "[문서 열람하기]\n\n"
                "이 링크는 7일간 유효하며, 접근하시려면 계정으로 로그인이 필요할 수 있습니다."
            ),
            "cta_text": "문서 열람하기",
            "red_flags": [
                {"signal": "발신 도메인에 여전히 눈에 띄는 단어", "explanation": "실제 클라우드 서비스 도메인과 다른 docshare-portal.example — 완전히 무관한 이름은 아니라 놓치기 쉽습니다."},
                {"signal": "확인 불가능한 발신자", "explanation": "'박이사'라는 구체적 이름을 언급하지만 실제로 그런 인물이 있는지, 정말 공유했는지 이메일 안에서는 확인할 수 없습니다."},
                {"signal": "모호한 로그인 요구", "explanation": "'로그인이 필요할 수 있습니다'라는 모호한 표현으로 클라우드 계정 정보 입력을 유도할 여지를 남깁니다."},
            ],
            "difficulty_rationale": "실제 협업 알림과 유사한 형식을 쓰되 발신 도메인에 여전히 눈에 띄는 단어(portal)가 남아있어, 조금만 주의하면 알아챌 수 있는 중급 신호로 구성했습니다.",
        },
        "advanced": {
            "subject": "'2026 예산안 최종.xlsx' 문서가 공유되었습니다 (재무기획팀)",
            "sender_display_name": "클라우드 문서 공유 알림",
            "sender_domain": "docshare-notify.example",
            "body": (
                "박준호 상무(재무기획팀) 님이 회원님과 문서를 공유했습니다.\n\n"
                "'2026 예산안 최종.xlsx' (2.1MB · 스프레드시트)\n\n"
                "[문서 열람하기]\n\n"
                "이 링크는 7일간 유효하며, 조직의 공유 정책에 따라 로그인 후 열람 가능합니다.\n\n"
                "본 알림은 문서 공유 시스템에서 자동 발송되었습니다."
            ),
            "cta_text": "문서 열람하기",
            "red_flags": [
                {"signal": "구체적이지만 확인 불가능한 발신자", "explanation": "'박준호 상무(재무기획팀)'처럼 직급·부서까지 구체적으로 명시해 신뢰도를 높였지만, 실제로 그런 인물이 있는지·정말 공유했는지는 이메일 안에서 확인할 방법이 없습니다."},
                {"signal": "실제 서비스처럼 보이는 파일 메타데이터", "explanation": "파일 용량(2.1MB)·형식(스프레드시트)까지 표기해 실제 클라우드 서비스의 알림 메일 형식을 정교하게 흉내냈습니다."},
                {"signal": "호기심 유발형 파일명", "explanation": "'예산안 최종'처럼 누구나 열어보고 싶어할 만한 민감한 제목을 사용합니다."},
                {"signal": "'조직의 공유 정책'이라는 모호한 표현으로 로그인 요구 정당화", "explanation": "어느 조직의 어떤 정책인지 구체적으로 밝히지 않은 채 로그인을 자연스러운 절차처럼 보이게 만듭니다."},
                {"signal": "실제 클라우드 서비스 도메인이 아님", "explanation": "docshare-notify.example — 실제 사용 중인 클라우드 서비스(구글/MS 등)의 공식 도메인이 아닙니다."},
            ],
            "difficulty_rationale": "발신자의 직급·부서, 파일 용량·형식까지 실제 클라우드 알림 메일의 세부 요소를 재현하고 '공유 정책'이라는 모호하지만 그럴듯한 근거로 로그인을 요구해, 발신 도메인을 직접 확인하지 않으면 알아채기 매우 어렵습니다.",
        },
    },
    "security_alert": {
        "beginner": {
            "subject": "[경고!!] 계정 해킹 시도 감지 - 즉시 확인 필요",
            "sender_display_name": "보안알림",
            "sender_domain": "acme-security-warn.example",
            "body": (
                "위험!!\n\n"
                "회원님의 계정이 해외에서 해킹 시도를 당했습니다. 지금 즉시 비밀번호를 변경하지 않으면 "
                "계정이 탈취됩니다.\n\n"
                "지금 확인: http://acme-security-warn.example/alert?u=9931\n\n"
                "계정과 비밀번호를 입력해 본인 확인을 완료해주세요."
            ),
            "cta_text": "계정 보안 즉시 확인하기",
            "red_flags": [
                {"signal": "도메인에 부자연스러운 단어", "explanation": "'security-warn'처럼 경고를 강조하는 단어가 도메인에 그대로 들어가 있습니다."},
                {"signal": "본문에 URL 원문 노출", "explanation": "링크 텍스트가 아닌 실제 URL이 그대로 노출됩니다."},
                {"signal": "과도한 공포 조성", "explanation": "'위험!!', '계정 탈취' 등 이성적 판단을 어렵게 만드는 표현을 씁니다."},
                {"signal": "이메일에서 직접 비밀번호 요구", "explanation": "정상적인 보안팀은 이메일 본문에서 비밀번호를 직접 묻지 않습니다."},
                {"signal": "발신자 익명", "explanation": "'보안알림'이라는 익명 표시로 구체적 부서명이 없습니다."},
            ],
            "difficulty_rationale": "공포 유발 문구와 URL 노출, 이메일에서 직접 비밀번호를 요구하는 명백한 신호가 겹쳐 초급자도 알아챌 수 있도록 구성했습니다.",
        },
        "intermediate": {
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
            "difficulty_rationale": "보안 경고 자체가 방어 심리를 자극해 오히려 클릭을 유도하는 역설적 구조지만, 이메일에서 직접 비밀번호를 요구하지는 않아 중급 신호로 분류.",
        },
        "advanced": {
            "subject": "[알림] 최근 로그인 활동을 확인해주세요",
            "sender_display_name": "ACME Trust & Safety",
            "sender_domain": "acme-corp-safety.example",
            "body": (
                "안녕하세요,\n\n"
                "계정 보호를 위해 최근 로그인 활동을 정기적으로 안내드리고 있습니다. 최근 7일간 아래와 같이 "
                "평소와 다른 위치에서의 접속 기록이 있어 확인 부탁드립니다.\n\n"
                "· 기기: Chrome (Windows)\n"
                "· 위치: 국내 등록 위치 외 IP 대역으로 추정\n"
                "· 시각: 2026-09-09 03:17 (KST)\n\n"
                "본인의 활동이 맞다면 별도 조치가 필요하지 않으며, 확인되지 않는 접속이 있다면 아래에서 "
                "세션을 관리해주세요.\n\n"
                "[로그인 활동 확인하기]\n\n"
                "ACME Trust & Safety Team\n"
                "본 알림은 계정 보호 시스템에서 자동 발송되었습니다."
            ),
            "cta_text": "로그인 활동 확인하기",
            "red_flags": [
                {"signal": "실제 도메인을 통째로 포함한 콤보스쿼팅", "explanation": "acme-corp-safety.example은 실제 사내 도메인(acme-corp.example)을 그대로 포함하고 있어 얼핏 보면 진짜처럼 보이지만, 뒤에 '-safety'가 붙은 완전히 다른 도메인입니다."},
                {"signal": "위협 대신 신뢰 유도", "explanation": "'본인의 활동이 맞다면 조치가 필요 없다'는 여유로운 어조로 오히려 경계심을 낮춥니다."},
                {"signal": "실제 보안 시스템 로그처럼 보이는 세부 정보", "explanation": "기기·위치·정확한 시각(2026-09-09 03:17 KST)까지 표를 구성해 실제 계정 보호 시스템의 알림처럼 보이게 했지만, 이 정보가 진짜인지 이메일만으로는 확인할 수 없습니다."},
                {"signal": "자연스러운 링크 텍스트", "explanation": "'로그인 활동 확인하기'라는 문구가 자연스러워 실제 보안 공지와 구분하기 어렵습니다."},
            ],
            "difficulty_rationale": "실제 사내 도메인을 포함하는 콤보스쿼팅 도메인에 더해 기기·위치·시각까지 실제 보안 시스템 로그처럼 구체적으로 제시해, 위협적 표현 없이도 매우 신뢰감 있게 작성했습니다 — 도메인을 문자 단위로 대조하지 않으면 알아채기 매우 어렵습니다.",
        },
    },
}


def get_scenario_variant(scenario_type: str, difficulty: str) -> dict:
    """시나리오+난이도에 맞는 큐레이션 템플릿을 찾는다. 없는 조합이면 intermediate로,
    그마저 없으면 it_password_reset/intermediate로 안전하게 폴백한다."""
    scenario = MOCK_SCENARIOS.get(scenario_type, MOCK_SCENARIOS["it_password_reset"])
    variant = scenario.get(difficulty) or scenario.get("intermediate")
    return dict(variant)


def generate_mock_phishing_sim(scenario_type: str, difficulty: str, context: str) -> dict:
    result = get_scenario_variant(scenario_type, difficulty)
    result["scenario_type"] = scenario_type
    result["difficulty"] = difficulty
    result["context_note"] = (
        f"(Mock 모드에서는 입력하신 조직 컨텍스트('{context[:60]}...')가 실제 문구에 반영되지 않습니다 — "
        "Live 모드에서는 AI가 이를 반영해 맞춤 생성합니다."
        if context.strip() else "조직 컨텍스트가 입력되지 않아 일반적인 예시로 생성되었습니다."
    )
    return result
