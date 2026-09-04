"""컨테이너/Dockerfile 감사기용 정적 가이드 — App 16 firewall_audit_guide.py와
동일한 패턴. Dockerfile/docker-compose.yml을 어떻게 준비해 붙여넣거나 업로드할지 안내한다."""

SOURCE_TYPES = [
    {
        "id": "dockerfile",
        "label": "Dockerfile",
        "how_to_export": "프로젝트의 Dockerfile 내용을 그대로 복사해 붙여넣거나 파일로 업로드하세요.",
        "commands": ["cat Dockerfile", "docker history <이미지>:<태그>  # 이미 빌드된 이미지의 레이어 확인용"],
    },
    {
        "id": "compose",
        "label": "docker-compose.yml",
        "how_to_export": "docker-compose.yml(또는 compose.yaml) 내용을 그대로 복사해 붙여넣거나 파일로 업로드하세요.",
        "commands": ["cat docker-compose.yml", "docker compose config  # 여러 override 파일이 병합된 최종 설정 확인용"],
    },
]

DISCLAIMER = (
    "이 도구는 붙여넣거나 업로드한 Dockerfile/compose 텍스트만으로 AI가 분석합니다 — 실제 이미지를 빌드하거나 "
    "컨테이너를 실행하지 않습니다. 업로드한 파일도 서버에 저장되지 않고 텍스트 내용만 그대로 분석에 사용됩니다. "
    "결과는 참고용 초안이며, 실제 반영 전 반드시 담당자 검토와 스테이징 환경에서의 검증을 거치세요."
)
