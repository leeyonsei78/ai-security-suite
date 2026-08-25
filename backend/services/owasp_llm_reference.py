# OWASP Top 10 for LLM Applications (2025) 요약 참고자료.
# 분석 결과의 각 finding.owasp_llm 태그를 해석하는 데 쓰이며, 프론트에 항상 노출되는
# 참고 패널로도 쓰인다 (vuln_scenarios.py의 ctf_prep_guide, recon_guide.py와 동일한 성격).

OWASP_LLM_TOP10 = [
    {
        "id": "LLM01",
        "name": "프롬프트 인젝션 (Prompt Injection)",
        "description": "사용자 입력이나 AI가 처리하는 외부 콘텐츠에 숨겨진 지시로 모델의 원래 지시를 재정의하거나 우회시키는 공격.",
    },
    {
        "id": "LLM02",
        "name": "민감정보 노출 (Sensitive Information Disclosure)",
        "description": "모델 응답이나 시스템 프롬프트를 통해 API 키, PII, 내부 로직 등 민감한 정보가 유출되는 것.",
    },
    {
        "id": "LLM03",
        "name": "공급망 취약점 (Supply Chain)",
        "description": "서드파티 모델, 플러그인, 학습 데이터, 파인튜닝 소스 등 공급망 구성요소의 취약점이나 변조 위험.",
    },
    {
        "id": "LLM04",
        "name": "데이터/모델 포이즈닝 (Data and Model Poisoning)",
        "description": "학습 또는 파인튜닝 데이터에 악의적으로 조작된 데이터를 주입해 모델 행동을 왜곡시키는 공격.",
    },
    {
        "id": "LLM05",
        "name": "부적절한 출력 처리 (Improper Output Handling)",
        "description": "모델 출력을 검증·이스케이프 없이 그대로 DB·셸·브라우저 등 다운스트림 시스템에 전달해 인젝션·XSS·RCE로 이어지는 것.",
    },
    {
        "id": "LLM06",
        "name": "과도한 에이전시 (Excessive Agency)",
        "description": "모델(에이전트)에게 필요 이상의 권한·자율성·도구 접근을 부여해 의도치 않거나 위험한 행동으로 이어질 수 있는 상태.",
    },
    {
        "id": "LLM07",
        "name": "시스템 프롬프트 유출 (System Prompt Leakage)",
        "description": "시스템 프롬프트 자체가 탈취되어 내부 로직·보안 장치가 노출되고, 이를 우회하는 후속 공격에 악용되는 것.",
    },
    {
        "id": "LLM08",
        "name": "벡터·임베딩 취약점 (Vector and Embedding Weaknesses)",
        "description": "RAG 시스템에서 벡터DB·임베딩 파이프라인 조작으로 잘못된 정보 검색이나 데이터 유출이 발생하는 것.",
    },
    {
        "id": "LLM09",
        "name": "잘못된 정보 (Misinformation)",
        "description": "모델이 그럴듯하지만 틀린 정보(할루시네이션)를 생성해 사용자의 신뢰·의사결정에 피해를 주는 것.",
    },
    {
        "id": "LLM10",
        "name": "무제한 리소스 소비 (Unbounded Consumption)",
        "description": "요청 크기·빈도 제한 부재로 과도한 리소스 소비(DoS)나 예상치 못한 API 과금으로 이어지는 것.",
    },
]

OWASP_LLM_DISCLAIMER = (
    "OWASP Top 10 for LLM Applications는 주기적으로 개정됩니다. 위 목록은 2025년 개정판 기준 요약이며, "
    "정확한 최신 항목·설명은 OWASP GenAI Security Project 공식 자료를 확인하세요."
)
