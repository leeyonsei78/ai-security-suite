"""클라우드 IAM 정책 감사기 Mock 데이터. App 16(방화벽 정책 감사기)이 "네트워크 규칙"을
감사한다면, 이 앱은 "누가 무엇에 접근할 수 있는가(권한)"를 감사한다 — 방화벽 규칙에는
없는 MFA·자격증명 수명주기·권한 상승 경로 같은 IAM 고유 문제를 다룬다.
"""

_TEMPLATES = {
    "aws_iam": {
        "summary": "관리자급 권한이 그룹이 아닌 개별 사용자에게 직접 부여되어 있고, 그 사용자가 자기 자신에게 정책을 추가로 붙일 수 있는 권한 상승 경로까지 열려 있습니다. MFA와 액세스 키 순환도 지켜지지 않고 있습니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "User: deploy-bot — inline policy \"AdminAccess\": {\"Action\": \"*\", \"Resource\": \"*\", \"Effect\": \"Allow\"}",
                "issue_type": "excessive_privilege",
                "severity": "CRITICAL",
                "description": "IAM 사용자에게 모든 서비스·모든 리소스에 대한 권한(`*:*`)이 그룹/역할을 거치지 않고 인라인 정책으로 직접 부여되어 있습니다. 이 사용자의 자격증명이 유출되면 계정 전체가 장악됩니다.",
                "recommendation": "실제로 필요한 서비스·액션만 나열한 관리형 정책으로 교체하고, 사용자에게 직접 붙이는 대신 역할(Role)이나 그룹을 통해 부여하세요. IAM Access Analyzer로 실제 사용된 액션만 추려 최소 권한 정책을 생성할 수 있습니다.",
            },
            {
                "rule_reference": "User: jkim — MFADevices: [] (콘솔 로그인 활성화 상태)",
                "issue_type": "missing_mfa",
                "severity": "CRITICAL",
                "description": "콘솔 로그인이 가능한 사용자에게 MFA 장치가 등록되어 있지 않습니다. 비밀번호만 유출돼도 콘솔 전체 접근이 가능합니다.",
                "recommendation": "가상 MFA 또는 하드웨어 보안키를 등록하도록 하고, IAM 정책의 Condition에 `aws:MultiFactorAuthPresent: true`를 요구하는 조건을 추가해 MFA 없이는 민감 작업을 못 하도록 강제하세요.",
            },
            {
                "rule_reference": "AccessKeyId: AKIA...N4F2 (User: legacy-svc) — CreateDate: 2024-02-11, LastUsedDate: 2024-03-02",
                "issue_type": "stale_credential",
                "severity": "HIGH",
                "description": "액세스 키가 생성된 지 1년 넘게 지났고 실제 마지막 사용일도 오래전입니다. 회전되지 않은 오래된 키는 유출 시 탐지가 늦고, 이미 용도를 다한 키일 가능성이 높습니다.",
                "recommendation": "credential report로 미사용 키를 정기 점검해 90일 이상 미사용 키는 비활성화 후 삭제하고, 사용 중인 키는 정기 순환 정책(예: 90일)을 적용하세요. 가능하면 장기 액세스 키 대신 IAM Role(임시 자격증명)로 전환하세요.",
            },
            {
                "rule_reference": "User: dev-lead — policy allows iam:PutUserPolicy, iam:AttachUserPolicy on Resource \"arn:aws:iam::*:user/${aws:username}\"",
                "issue_type": "privilege_escalation_path",
                "severity": "CRITICAL",
                "description": "이 사용자는 자기 자신에게 원하는 정책을 얼마든지 추가로 붙일 수 있습니다. 초기 권한이 낮아 보여도, 결과적으로는 관리자 권한을 스스로에게 부여할 수 있는 것과 같습니다(잘 알려진 AWS 권한 상승 패턴).",
                "recommendation": "iam:PutUserPolicy/iam:AttachUserPolicy/iam:CreatePolicyVersion 등 자기 권한 변경이 가능한 액션은 자기 자신(`${aws:username}`)을 Resource로 허용하지 마세요. 필요하다면 별도 승인 프로세스가 있는 파이프라인을 통해서만 정책 변경이 이뤄지게 하세요.",
            },
            {
                "rule_reference": "Role: cross-account-readonly — AssumeRolePolicyDocument Principal: \"*\"",
                "issue_type": "misconfigured_trust",
                "severity": "HIGH",
                "description": "역할의 신뢰 정책이 모든 AWS 계정(Principal \"*\")에서 AssumeRole을 허용합니다. 제한이 없으면 다른 어떤 AWS 계정에서도 이 역할을 가정(assume)할 수 있습니다.",
                "recommendation": "Principal을 실제로 신뢰하는 계정 ID로 한정하고, `sts:ExternalId` 조건을 추가해 의도한 파트너만 역할을 가정할 수 있도록 제한하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.5.1(사용자 계정 관리)·2.5.3(사용자 인증)에서 요구하는 최소 권한 원칙과 MFA가 지켜지지 않고 있습니다."},
            {"framework": "PCI-DSS", "note": "요구사항 7(최소 권한에 따른 접근 제한)·8.4.2(다중 인증)를 위반할 소지가 있습니다."},
        ],
    },
    "azure_rbac": {
        "summary": "구독 범위의 Owner 역할이 일반 업무용 계정에 상시 부여되어 있고 MFA도 등록되지 않았습니다. 커스텀 역할 하나는 역할 할당 자체를 스스로 부여할 수 있는 권한을 포함하고 있어 권한 상승 경로로 악용될 수 있습니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "roleAssignment: principalName=jane.dev@company.com, roleDefinitionName=Owner, scope=/subscriptions/<sub-id>",
                "issue_type": "excessive_privilege",
                "severity": "CRITICAL",
                "description": "일반 개발자 계정에 구독 전체 범위의 Owner 역할이 상시 부여되어 있습니다. Owner는 권한 할당 자체를 포함한 모든 작업이 가능해 사실상 무제한 권한입니다.",
                "recommendation": "실제 업무에 필요한 최소 역할(예: Contributor, 필요하면 리소스 그룹 단위)로 낮추고, 꼭 Owner가 필요한 작업만 Azure PIM(Privileged Identity Management)으로 필요할 때만 임시 승격하도록 구성하세요.",
            },
            {
                "rule_reference": "user: jane.dev@company.com — strongAuthenticationMethods: []",
                "issue_type": "missing_mfa",
                "severity": "CRITICAL",
                "description": "Owner 권한을 가진 계정에 MFA가 전혀 등록되어 있지 않습니다. 비밀번호 유출만으로 구독 전체가 위험해집니다.",
                "recommendation": "Azure AD Conditional Access 정책으로 관리자/특권 역할 계정에 MFA를 강제하고, 등록된 방법이 없는 계정은 로그인을 차단하도록 설정하세요.",
            },
            {
                "rule_reference": "guest user: contractor-ext@partner.com — roleDefinitionName=Contributor (프로젝트 종료 1년 경과)",
                "issue_type": "stale_credential",
                "severity": "MEDIUM",
                "description": "외부 협력사 게스트 계정이 프로젝트가 끝난 지 1년이 지났는데도 Contributor 권한을 그대로 유지하고 있습니다. 더 이상 필요 없는 접근 권한이 방치된 상태입니다.",
                "recommendation": "Azure AD Access Reviews로 게스트 계정 권한을 정기 검토(예: 분기별)하도록 설정하고, 프로젝트 종료 시 즉시 역할 할당을 제거하는 오프보딩 절차를 만드세요.",
            },
            {
                "rule_reference": "customRole: \"SelfServiceOps\" — actions: [\"Microsoft.Authorization/roleAssignments/write\"], assignableScopes: [\"/\"]",
                "issue_type": "privilege_escalation_path",
                "severity": "CRITICAL",
                "description": "이 커스텀 역할은 테넌트 전체 범위(`/`)에서 역할 할당(roleAssignments/write)을 스스로 수행할 수 있습니다. 즉, 이 역할을 가진 사람은 자기 자신이나 다른 누구에게든 원하는 역할을 부여할 수 있어 사실상 Owner와 동급입니다.",
                "recommendation": "roleAssignments/write 권한은 정말 필요한 최소 범위(특정 리소스 그룹 등)로 좁히고, 테넌트 루트(`/`) 범위로는 절대 할당하지 마세요. 역할 할당 권한 자체는 PIM 승인 워크플로우를 거치도록 구성하는 것을 권장합니다.",
            },
            {
                "rule_reference": "servicePrincipal: \"ci-pipeline-sp\" — passwordCredentials[0].endDateTime: 2099-01-01",
                "issue_type": "stale_credential",
                "severity": "HIGH",
                "description": "서비스 프린시펄의 클라이언트 시크릿 만료일이 사실상 무기한(2099년)으로 설정되어 있습니다. 유출되어도 스스로 만료되지 않아 위험이 영구적으로 남습니다.",
                "recommendation": "시크릿 만료 기간을 짧게(예: 6~12개월) 설정하고 자동 순환 프로세스를 구성하세요. 가능하면 클라이언트 시크릿 대신 Workload Identity Federation(OIDC)으로 전환해 장기 시크릿 자체를 없애는 것을 권장합니다.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.5.1(사용자 계정 관리)에서 요구하는 계정별 최소 권한과 정기 검토가 이뤄지지 않고 있습니다."},
        ],
    },
    "gcp_iam": {
        "summary": "프로젝트 IAM 정책에 공개 접근(allUsers) 바인딩이 남아 있고, roles/owner가 여러 인적 계정에 직접 부여되어 있습니다. 서비스 계정 키도 순환 없이 오래 방치되어 있어 종합적으로 위험도가 높습니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "bindings: {role: \"roles/storage.objectViewer\", members: [\"allUsers\"]}",
                "issue_type": "misconfigured_trust",
                "severity": "CRITICAL",
                "description": "`allUsers`는 인증 여부와 무관하게 인터넷의 누구나를 의미합니다. 이 바인딩이 남아있는 리소스는 사실상 공개 상태이며, 사내 문서용 버킷 등 민감 데이터가 포함돼 있다면 그대로 외부에 노출됩니다.",
                "recommendation": "정말 공개가 의도된 리소스(정적 웹사이트 자산 등)가 아니라면 `allUsers`/`allAuthenticatedUsers` 바인딩을 즉시 제거하고, Organization Policy로 공개 IAM 바인딩 자체를 조직 차원에서 차단(Domain Restricted Sharing)하는 것을 권장합니다.",
            },
            {
                "rule_reference": "bindings: {role: \"roles/owner\", members: [\"user:alice@company.com\", \"user:bob@company.com\"]}",
                "issue_type": "excessive_privilege",
                "severity": "CRITICAL",
                "description": "여러 인적 계정에 프로젝트 전체를 제어할 수 있는 `roles/owner`가 직접 부여되어 있습니다. Owner는 IAM 정책 자체도 변경할 수 있어 사실상 제한이 없습니다.",
                "recommendation": "업무에 필요한 세분화된 사전 정의 역할(예: roles/editor의 일부 권한만 담은 커스텀 역할)로 낮추고, Owner는 소수의 break-glass 계정에만 남기고 평상시엔 그룹을 통해 임시로만 부여하세요.",
            },
            {
                "rule_reference": "serviceAccount: ci-deployer@project.iam.gserviceaccount.com — key created 2023-01-15, no rotation since",
                "issue_type": "stale_credential",
                "severity": "HIGH",
                "description": "서비스 계정 JSON 키가 순환 없이 1년 넘게 그대로 사용되고 있습니다. 다운로드된 키 파일은 유출 경로를 추적하기 어렵고, 오래된 키일수록 유출 가능성이 누적됩니다.",
                "recommendation": "가능하면 다운로드형 키 대신 Workload Identity Federation으로 전환해 장기 키 자체를 없애고, 불가피하게 키를 써야 한다면 정기 순환(예: 90일)과 미사용 키 자동 삭제 정책을 적용하세요.",
            },
            {
                "rule_reference": "user: contractor@company.com — roles/iam.serviceAccountUser + roles/iam.serviceAccountTokenCreator (동일 서비스 계정 대상)",
                "issue_type": "privilege_escalation_path",
                "severity": "HIGH",
                "description": "이 두 역할을 함께 가지면 해당 서비스 계정을 가장(impersonate)해 액세스 토큰을 직접 발급받을 수 있습니다. 서비스 계정이 더 높은 권한(예: roles/owner)을 가지고 있다면, 이 사용자는 실질적으로 그 권한까지 획득하는 셈입니다.",
                "recommendation": "두 역할을 동시에 부여하는 조합을 지양하고, 꼭 필요하다면 대상 서비스 계정의 권한 자체를 최소화하세요. IAM Recommender로 이런 위험한 역할 조합을 주기적으로 점검하는 것을 권장합니다.",
            },
            {
                "rule_reference": "user account \"deploy-bot@company.com\" — 여러 CI 파이프라인과 팀원이 동일 비밀번호로 공유 사용 중(사내 위키 기록)",
                "issue_type": "shared_credential",
                "severity": "MEDIUM",
                "description": "개인별로 분리되지 않은 공용 계정을 여러 사람과 시스템이 함께 사용하고 있어, 문제 발생 시 누가 실제로 수행했는지 추적할 수 없습니다.",
                "recommendation": "사람에게는 개인별 계정을, 자동화 파이프라인에는 전용 서비스 계정을 각각 발급하고, 기존 공용 계정은 사용 이력을 확인한 뒤 폐기하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.6.1(네트워크 접근)·2.5.1(사용자 계정 관리)에서 요구하는 개별 계정 관리와 공개 노출 통제가 지켜지지 않고 있습니다."},
            {"framework": "PCI-DSS", "note": "요구사항 7(최소 권한)·8(사용자 식별 및 인증)을 위반할 소지가 있습니다."},
        ],
    },
}

_DEFAULT_KEY = "aws_iam"


def generate_mock_audit(source_type: str, content: str, context: str) -> dict:
    template = _TEMPLATES.get(source_type, _TEMPLATES[_DEFAULT_KEY])
    # 얕은 복사 — 여러 요청이 같은 dict 객체를 공유해 서로 오염시키지 않도록
    return {
        "summary": template["summary"],
        "overall_risk": template["overall_risk"],
        "findings": [dict(f) for f in template["findings"]],
        "compliance_notes": [dict(c) for c in template["compliance_notes"]],
    }
