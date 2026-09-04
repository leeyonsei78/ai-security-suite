"""클라우드 IAM 정책 감사기용 정적 가이드 — 각 클라우드에서 실제로 IAM 정책/사용자
정보를 어떻게 추출해 붙여넣거나 파일로 업로드할지 안내한다 (App 16 firewall_audit_guide.py와 동일한 패턴)."""

SOURCE_TYPES = [
    {
        "id": "aws_iam",
        "label": "AWS IAM",
        "how_to_export": "AWS CLI 결과 JSON을 붙여넣거나 파일로 저장해 업로드하세요. 정책 문서뿐 아니라 사용자/액세스 키 목록을 함께 붙이면 MFA·자격증명 관련 문제까지 더 정확하게 감사할 수 있습니다.",
        "commands": [
            "aws iam get-account-authorization-details --output json  # 사용자/역할/정책을 한 번에",
            "aws iam list-policies --scope Local --output json",
            "aws iam list-users --output json",
            "aws iam list-access-keys --user-name <사용자명>",
            "aws iam get-credential-report  # MFA·키 사용 이력 요약",
        ],
    },
    {
        "id": "azure_rbac",
        "label": "Azure RBAC",
        "how_to_export": "Azure CLI 결과 JSON을 붙여넣거나 파일로 저장해 업로드하세요.",
        "commands": [
            "az role assignment list --all --output json",
            "az role definition list --custom-role-only true --output json",
            "az ad sp list --output json  # 서비스 프린시펄/자격증명 만료일 확인용",
        ],
    },
    {
        "id": "gcp_iam",
        "label": "GCP IAM",
        "how_to_export": "gcloud CLI 결과 JSON을 붙여넣거나 파일로 저장해 업로드하세요.",
        "commands": [
            "gcloud projects get-iam-policy <프로젝트ID> --format=json",
            "gcloud iam service-accounts list --format=json",
            "gcloud iam service-accounts keys list --iam-account=<서비스계정> --format=json",
        ],
    },
]

DISCLAIMER = (
    "이 도구는 붙여넣거나 업로드한 IAM 정책/사용자 정보 텍스트만으로 AI가 분석합니다 — 실제 클라우드 계정에 연결하거나 "
    "권한을 변경하지 않습니다. 업로드한 파일도 서버에 저장되지 않고 텍스트 내용만 그대로 분석에 사용됩니다. "
    "결과는 참고용 초안이며, 실제 반영 전 반드시 담당자 검토와 최소 권한 원칙에 따른 검증을 거치세요."
)
