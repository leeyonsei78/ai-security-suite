# 보안 정책을 "생성하기 전/생성한 후"에 실제로 무엇을 해야 하는지에 대한 정적(고정) 가이드.
# AI 생성 결과(priority_order, validation)는 policy_service._enrich()가 담당하고,
# 여기 있는 내용은 도구 사용 여부와 무관하게 항상 참고할 수 있는 방법론이다.

POLICY_PREP_GUIDE = {
    "getting_started": [
        {
            "step": 1,
            "title": "보호 대상 자산 식별",
            "detail": "어떤 서버·서비스·데이터가 있는지 목록화하고, 그중 가장 중요한 것(예: 고객 개인정보 DB, 결제 시스템)을 먼저 표시하세요. 무엇을 지킬지 모르면 정책의 우선순위도 정할 수 없습니다.",
        },
        {
            "step": 2,
            "title": "현재 상태(As-Is) 파악",
            "detail": "추측하지 말고 실제로 확인하세요: 현재 어떤 포트가 열려 있는지(nmap), 방화벽 규칙이 무엇인지, 어떤 계정이 어떤 권한을 갖고 있는지. 이 앱의 취약점 스캐너 '정보 수집 가이드'로 실제 조사할 수 있습니다.",
        },
        {
            "step": 3,
            "title": "위협/리스크 파악",
            "detail": "무엇으로부터 보호해야 하는지 정의하세요 — 외부 공격자? 내부자 유출? 랜섬웨어? 대상이 다르면 우선순위도 달라집니다.",
        },
        {
            "step": 4,
            "title": "적용 대상 컴플라이언스 확인",
            "detail": "취급하는 데이터/업종에 따라 PCI-DSS(카드정보), 개인정보보호법(개인정보), ISMS-P(정보통신서비스), GDPR/HIPAA(해외/의료) 등 의무 적용 여부가 다릅니다. 정확한 적용 여부는 법무/컴플라이언스 담당자와 함께 확인하세요.",
        },
        {
            "step": 5,
            "title": "이 도구로 초안(To-Be) 생성",
            "detail": "위에서 파악한 내용을 최대한 구체적으로 환경 설명에 입력하세요 (예: '웹서버는 nginx, SSH 22번 포트가 0.0.0.0에 열려있음, DB는 같은 서버에 설치됨'). 구체적일수록 더 실질적인 방화벽 규칙/정책이 생성됩니다.",
        },
        {
            "step": 6,
            "title": "이해관계자 검토",
            "detail": "생성된 초안은 반드시 인프라/개발/법무 담당자와 함께 검토하세요. AI 초안은 출발점이지 완성본이 아닙니다 — 실제 운영 환경과 맞지 않는 규칙(예: 실제로 필요한 포트를 차단)이 있을 수 있습니다.",
        },
        {
            "step": 7,
            "title": "테스트 환경에서 먼저 적용",
            "detail": "운영에 바로 반영하지 말고 스테이징/테스트 환경에서 먼저 적용해 정상 동작을 확인하세요. 아래 '적용 검증 방법론' 참고.",
        },
        {
            "step": 8,
            "title": "단계적 반영 + 지속적 재점검",
            "detail": "한 번에 전부 적용하지 말고 아래 우선순위 순서대로 반영하세요. 정책은 한 번 만들고 끝이 아니라 정기적으로(예: 분기 1회) 재점검·갱신해야 합니다.",
        },
    ],
    "priority_framework": {
        "principle": "영향도(뚫렸을 때 피해 규모) × 발생 가능성(현재 얼마나 쉽게 뚫리는가)이 높은 항목부터 처리하세요. 특히 '인터넷에 그대로 노출된 관리 포트·기본 계정'처럼 지금 당장 악용 가능한 항목이 최우선입니다.",
        "general_order": [
            "1. 접근 통제 (관리자 인증 — SSH/RDP/DB/콘솔 접근)",
            "2. 네트워크 분리 및 방화벽 (불필요한 노출 차단)",
            "3. 데이터 보호 (암호화 — 위 통제가 뚫렸을 때의 최후 방어선)",
            "4. 로깅 및 모니터링 (위 조치가 실제로 작동하는지, 뚫렸을 때 알아챌 수 있는지)",
            "5. 패치 및 취약점 관리",
            "6. 사고 대응 체계",
            "7. 백업 및 복구",
        ],
        "caveat": "이는 일반적인 기본 순서이며, 실제 우선순위는 환경 설명에 따라 조정됩니다 (예: 알려진 미패치 CVE가 있다면 패치가 최우선으로 올라갈 수 있음). 생성 결과의 '우선순위' 섹션을 확인하세요.",
    },
    "validation_methodology": [
        {
            "phase": "적용 전 (스테이징)",
            "steps": [
                "방화벽 규칙은 운영 반영 전 테스트 환경에 먼저 적용하고, nmap/curl로 의도한 포트만 열려 있는지 직접 확인합니다",
                "접근 통제는 '허용되어야 할 접근'과 '차단되어야 할 접근'을 모두 실제로 시도해보세요 (positive/negative test)",
                "변경 내용과 문제 발생 시 되돌릴 롤백 계획을 사전에 문서화합니다",
            ],
        },
        {
            "phase": "적용 시",
            "steps": [
                "변경관리 절차(승인·기록)를 거쳐 반영하고, 트래픽이 적은 시간대에 적용합니다",
                "적용 직후 실제 서비스가 정상 동작하는지 헬스체크로 확인합니다 (의도치 않게 필요한 트래픽까지 막혔는지 확인)",
            ],
        },
        {
            "phase": "적용 후 (지속 검증)",
            "steps": [
                "정기적으로(예: 분기 1회) 동일한 검증을 반복해 설정 드리프트(누군가 규칙을 임의로 완화)가 없는지 확인합니다",
                "가능하면 외부 취약점 스캐너나 모의해킹으로 실제 우회 가능 여부를 주기적으로 재확인합니다",
                "로깅/알림은 실제 이벤트를 의도적으로 발생시켜(예: 로그인 5회 실패) 알림이 실제로 도착하는지까지 end-to-end로 확인합니다 — 로그만 쌓이고 알림이 안 오는 경우가 흔한 실패 지점입니다",
            ],
        },
    ],
    "disclaimer": "이 가이드와 아래 생성 결과는 보안 정책 수립의 출발점(초안)입니다. 실제 조직에 적용하기 전 반드시 인프라/보안/법무 담당자의 검토를 거치세요.",
}


# "As-Is 파악"(준비 2단계)을 환경 유형별로 실행 가능하게 채운 것 — 어디를 봐야 하는지(where)와
# 실제 명령어(commands)를 함께 제공한다. environment_type 값(web_server/cloud/internal_network/
# container/database)을 키로 사용해 프론트에서 선택된 환경에 맞춰 동적으로 보여준다.
ENVIRONMENT_RECON = {
    "web_server": {
        "label": "웹 서버",
        "note": "설정 파일만 보지 말고, 반드시 외부(인터넷)에서도 별도로 확인하세요 — 로컬 설정과 실제 도달 가능 여부가 다를 수 있습니다.",
        "checks": [
            {
                "category": "열려있는 포트 / 리스닝 프로세스",
                "where": "서버에 SSH로 접속해 로컬에서 확인 + 외부에서 실제 도달 가능 여부 별도 검증",
                "commands": [
                    "sudo ss -tulnp                      # 로컬에서 열려있는 포트와 프로세스",
                    "nmap -p- -T4 <서버 공인 IP>          # 외부 관점에서 실제 도달 가능한 포트 확인",
                ],
            },
            {
                "category": "방화벽 / iptables 규칙",
                "where": "서버 자체 (배포판에 따라 도구가 다름)",
                "commands": [
                    "sudo iptables -L -n -v --line-numbers   # iptables 직접 사용 시",
                    "sudo ufw status verbose                 # Ubuntu/Debian (ufw)",
                    "sudo firewall-cmd --list-all             # RHEL/CentOS (firewalld)",
                ],
            },
            {
                "category": "웹서버 / 리버스 프록시 설정",
                "where": "nginx 또는 Apache 설정 파일",
                "commands": [
                    "sudo nginx -T                        # 병합된 전체 설정 출력",
                    "sudo apachectl -S                    # Apache VirtualHost 목록",
                ],
            },
            {
                "category": "TLS/HTTPS 설정",
                "where": "외부에서 실제 접속해 협상 결과로 검증 (서버 설정 파일만으로는 부족)",
                "commands": [
                    "openssl s_client -connect <도메인>:443 -tls1_2 -brief",
                    "curl -sI https://<도메인> | grep -i 'strict-transport-security\\|server'",
                ],
            },
            {
                "category": "SSH 접근 설정",
                "where": "sshd 설정 파일",
                "commands": [
                    "grep -E 'PasswordAuthentication|PermitRootLogin|Port|AllowUsers' /etc/ssh/sshd_config",
                ],
            },
            {
                "category": "DB가 외부에 노출돼 있는지",
                "where": "웹 서버와 DB가 같은 호스트에 있는 구성인 경우 특히 확인",
                "commands": [
                    "sudo ss -tulnp | grep -E '3306|5432'",
                    "nmap -p 3306,5432 <서버 공인 IP>",
                ],
            },
        ],
    },
    "cloud": {
        "label": "클라우드 인프라",
        "note": "아래는 AWS CLI 기준 예시입니다. Azure는 az, GCP는 gcloud 명령으로 대응하는 조회가 있습니다 (예: az network nsg list, gcloud compute firewall-rules list).",
        "checks": [
            {
                "category": "보안그룹 / 네트워크 ACL",
                "where": "클라우드 콘솔의 VPC/EC2 보안그룹 화면, 또는 CLI",
                "commands": [
                    "aws ec2 describe-security-groups --query \"SecurityGroups[].[GroupId,IpPermissions]\"",
                    "aws ec2 describe-network-acls",
                ],
            },
            {
                "category": "IAM 정책 (과도한 권한 탐지)",
                "where": "IAM 콘솔 또는 CLI — 특히 Action:\"*\", Resource:\"*\" 같은 와일드카드 정책",
                "commands": [
                    "aws iam list-users",
                    "aws iam list-attached-user-policies --user-name <사용자명>",
                    "aws iam get-account-authorization-details | grep -B5 '\"Action\": \"\\*\"'",
                ],
            },
            {
                "category": "스토리지 퍼블릭 노출",
                "where": "S3 버킷 (또는 Azure Blob / GCS 버킷)",
                "commands": [
                    "aws s3api get-bucket-acl --bucket <버킷명>",
                    "aws s3api get-public-access-block --bucket <버킷명>",
                ],
            },
            {
                "category": "감사 로그(CloudTrail) 활성화 여부",
                "where": "CloudTrail 콘솔 또는 CLI",
                "commands": [
                    "aws cloudtrail describe-trails",
                    "aws cloudtrail get-trail-status --name <트레일명>",
                ],
            },
            {
                "category": "액세스 키 노출 / 사용 현황",
                "where": "IAM 자격증명 보고서",
                "commands": [
                    "aws iam list-access-keys --user-name <사용자명>",
                    "aws iam generate-credential-report && aws iam get-credential-report",
                ],
            },
        ],
    },
    "internal_network": {
        "label": "사내 네트워크",
        "note": "스위치/AD 관련 명령은 관리자 권한이 필요합니다. 게스트 Wi-Fi 분리처럼 '분리되어 있다고 알고 있는' 것은 실제로 그 네트워크에 접속해 검증하세요.",
        "checks": [
            {
                "category": "연결된 장치 / 서브넷 파악",
                "where": "네트워크 관리용 PC에서",
                "commands": [
                    "nmap -sn 192.168.1.0/24    # 핑 스윕으로 살아있는 호스트 목록 (대역은 실제 환경에 맞게 변경)",
                    "arp -a                      # 로컬 ARP 테이블",
                ],
            },
            {
                "category": "VLAN / 스위치 설정",
                "where": "스위치 관리 콘솔 (Cisco 계열 예시)",
                "commands": [
                    "show vlan brief",
                    "show interfaces trunk",
                ],
            },
            {
                "category": "방화벽 / 방화벽 규칙",
                "where": "Windows PC·서버 또는 Linux 게이트웨이",
                "commands": [
                    "Get-NetFirewallRule -Enabled True | Select DisplayName,Direction,Action   # Windows (PowerShell)",
                    "sudo iptables -L -n -v                                                     # Linux 게이트웨이",
                ],
            },
            {
                "category": "Active Directory 계정/그룹 권한 (AD 환경인 경우)",
                "where": "도메인 컨트롤러 또는 RSAT 설치된 관리 PC",
                "commands": [
                    "Get-ADUser -Filter * -Properties MemberOf",
                    "Get-ADGroupMember 'Domain Admins'",
                ],
            },
            {
                "category": "게스트 Wi-Fi 분리 여부 실제 검증",
                "where": "게스트 Wi-Fi에 실제로 접속한 상태에서",
                "commands": [
                    "nmap -sn <사내망 대역>   # 내부 호스트가 보이면 분리가 안 된 것",
                ],
            },
        ],
    },
    "container": {
        "label": "컨테이너 (Docker/K8s)",
        "note": "클러스터에 대한 조회 권한(get/list)이 있는 kubectl 컨텍스트가 필요합니다.",
        "checks": [
            {
                "category": "현재 네트워크 정책",
                "where": "네임스페이스별 NetworkPolicy",
                "commands": [
                    "kubectl get networkpolicy -A",
                    "kubectl describe networkpolicy <이름> -n <네임스페이스>",
                ],
            },
            {
                "category": "Pod 권한 (privileged / root 여부)",
                "where": "Pod spec의 securityContext",
                "commands": [
                    "kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'",
                    "kubectl get pod <이름> -n <네임스페이스> -o yaml | grep -A5 securityContext",
                ],
            },
            {
                "category": "RBAC 과다 권한",
                "where": "ClusterRoleBinding / ServiceAccount 권한",
                "commands": [
                    "kubectl auth can-i --list --as=system:serviceaccount:<네임스페이스>:<서비스어카운트>",
                    "kubectl get clusterrolebindings -o wide | grep cluster-admin",
                ],
            },
            {
                "category": "이미지 취약점",
                "where": "실제 배포 중인 이미지",
                "commands": [
                    "trivy image <이미지>:<태그>",
                ],
            },
            {
                "category": "시크릿 하드코딩 여부",
                "where": "Pod 환경변수 / 이미지 레이어",
                "commands": [
                    "kubectl get pods -A -o yaml | grep -i 'password\\|secret\\|key'",
                    "docker history --no-trunc <이미지> | grep -i pass",
                ],
            },
        ],
    },
    "database": {
        "label": "데이터베이스",
        "note": "아래는 MySQL/PostgreSQL 기준 예시입니다. 실제 사용 중인 DBMS 문서의 동등 명령으로 대체하세요.",
        "checks": [
            {
                "category": "실제로 외부에 열려있는지",
                "where": "DB 서버 자체 + 외부에서 별도 검증",
                "commands": [
                    "sudo ss -tulnp | grep -E '3306|5432|1433'   # DB 서버에서 로컬 확인",
                    "nmap -p 3306,5432,1433 <DB 서버 IP>          # 외부에서 실제 도달 가능 여부",
                ],
            },
            {
                "category": "bind-address 설정",
                "where": "DB 설정 파일 — 0.0.0.0이면 모든 인터페이스에 열려있는 것",
                "commands": [
                    "grep bind-address /etc/mysql/my.cnf         # MySQL",
                    "grep listen_addresses /etc/postgresql/*/main/postgresql.conf   # PostgreSQL",
                ],
            },
            {
                "category": "계정 및 권한",
                "where": "DB 접속 후 시스템 카탈로그 조회",
                "commands": [
                    "SELECT user, host FROM mysql.user;  SHOW GRANTS FOR 'appuser'@'%';   -- MySQL",
                    "\\du   -- PostgreSQL (psql 내에서), 또는 SELECT * FROM pg_hba_file_rules;",
                ],
            },
            {
                "category": "TLS 강제 여부",
                "where": "DB 접속 후 관련 변수 조회",
                "commands": [
                    "SHOW VARIABLES LIKE 'require_secure_transport';  -- MySQL",
                    "SHOW ssl;                                         -- PostgreSQL",
                ],
            },
            {
                "category": "백업 존재 / 암호화 여부",
                "where": "백업 저장 위치 (로컬 디스크 또는 클라우드 스토리지)",
                "commands": [
                    "ls -la /backup                        # 로컬 백업 위치 예시",
                    "# 클라우드 스토리지에 저장된다면 위 '클라우드' 환경의 스토리지 점검 명령을 함께 사용하세요",
                ],
            },
        ],
    },
}
