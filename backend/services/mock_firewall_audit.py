"""방화벽 정책 감사기 Mock 데이터. App 11(정책 생성기)이 '새 정책을 생성'하는 반대
방향으로, 이미 존재하는 방화벽 규칙을 붙여넣으면 무엇이 잘못됐는지 감사한다.
소스 타입(iptables/AWS 보안그룹/Windows 방화벽/기타)별로 실제로 자주 나오는
문제 패턴(과도허용, 미사용, 중복/충돌, 컴플라이언스 위반)을 큐레이션했다.
"""

_TEMPLATES = {
    "iptables": {
        "summary": "SSH·DB 포트가 전역 공개되어 있고, 아웃바운드 정책이 없어 침해 시 데이터 유출 통제가 어려운 상태입니다. 인바운드 최소화와 아웃바운드 화이트리스트가 시급합니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "-A INPUT -p tcp --dport 22 -j ACCEPT",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "SSH(22)가 출발지 제한 없이(0.0.0.0/0) 전체 공개되어 있습니다. 인터넷 전체에서 브루트포스 공격 대상이 됩니다.",
                "recommendation": "-A INPUT -p tcp -s <관리자 대역>/24 --dport 22 -j ACCEPT 로 출발지를 VPN/관리자 IP 대역으로 제한하세요.",
            },
            {
                "rule_reference": "-A INPUT -p tcp --dport 3306 -j ACCEPT",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "MySQL(3306)이 전역 공개되어 있습니다. DB는 원칙적으로 인터넷에서 직접 도달 가능해서는 안 됩니다.",
                "recommendation": "해당 규칙을 삭제하고, 같은 호스트 또는 내부망(WAS 서버 IP)에서만 접근하도록 -s <WAS 내부 IP> 로 제한하세요.",
            },
            {
                "rule_reference": "-A INPUT -p tcp --dport 8081 -j ACCEPT  (# 2024-01 임시 디버그용)",
                "issue_type": "unused",
                "severity": "MEDIUM",
                "description": "주석상 '임시 디버그용'으로 추가된 규칙이 정리되지 않고 남아있습니다. 실제 서비스 포트가 아니라면 공격 표면만 늘립니다.",
                "recommendation": "해당 규칙이 현재도 필요한지 담당자에게 확인 후, 불필요하면 즉시 삭제하세요.",
            },
            {
                "rule_reference": "OUTPUT 체인에 명시적 규칙 없음 (기본 정책 ACCEPT)",
                "issue_type": "missing_control",
                "severity": "HIGH",
                "description": "아웃바운드 트래픽에 대한 제한이 전혀 없습니다. 침해가 발생하면 C2 통신이나 데이터 유출을 막을 방법이 없습니다.",
                "recommendation": "OUTPUT 체인 기본 정책을 DROP으로 바꾸고, 업데이트 서버·API 등 실제로 필요한 목적지만 화이트리스트로 허용하세요.",
            },
            {
                "rule_reference": "-A INPUT -p tcp --dport 443 -j ACCEPT (뒤에 동일 규칙 2회 중복)",
                "issue_type": "redundant",
                "severity": "LOW",
                "description": "443 포트를 허용하는 동일한 규칙이 두 번 등록되어 있습니다. 동작에는 영향 없지만 규칙셋을 읽기 어렵게 만듭니다.",
                "recommendation": "중복 규칙을 정리해 규칙셋을 단순화하면 이후 감사·변경 시 실수를 줄일 수 있습니다.",
            },
        ],
        "compliance_notes": [
            {"framework": "PCI-DSS", "note": "요구사항 1.2.1(인바운드/아웃바운드 트래픽을 카드소지자 데이터 환경에 필요한 것으로 제한)에 대한 아웃바운드 통제가 없어 위반 소지가 있습니다."},
        ],
    },
    "aws_sg": {
        "summary": "관리 포트(SSH/RDP)가 0.0.0.0/0으로 열려 있고, 보안그룹 간 참조 없이 CIDR로만 규칙이 구성되어 있어 인스턴스가 늘어날 때마다 관리가 어려워지는 구조입니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "Inbound: TCP 22, Source 0.0.0.0/0",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "SSH가 전체 인터넷에 공개되어 있습니다. AWS에서 가장 흔하게 스캔·공격당하는 설정입니다.",
                "recommendation": "Source를 사내 VPN CIDR 또는 특정 관리자 IP/32로 좁히거나, AWS Systems Manager Session Manager로 전환해 22번 포트 자체를 닫는 것을 권장합니다.",
            },
            {
                "rule_reference": "Inbound: TCP 3389, Source 0.0.0.0/0",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "RDP(3389)가 전체 공개되어 있습니다. RDP는 무차별 대입 공격과 알려진 원격 코드 실행 취약점(BlueKeep 등)의 단골 대상입니다.",
                "recommendation": "Source를 관리자 대역으로 제한하고, 가능하면 VPN 경유 접속만 허용하도록 재구성하세요.",
            },
            {
                "rule_reference": "Inbound: ALL TRAFFIC, Source sg-0a1b2c3d (자기 자신 참조)",
                "issue_type": "overly_permissive",
                "severity": "HIGH",
                "description": "같은 보안그룹에 속한 인스턴스 간 전체 포트/프로토콜이 허용되어 있습니다. 한 인스턴스가 침해되면 그룹 내 다른 인스턴스로 제한 없이 확산될 수 있습니다.",
                "recommendation": "실제로 인스턴스 간 통신이 필요한 포트만(예: 애플리케이션 포트) 명시적으로 허용하도록 좁히세요.",
            },
            {
                "rule_reference": "Outbound: ALL TRAFFIC, Destination 0.0.0.0/0 (기본값 유지)",
                "issue_type": "missing_control",
                "severity": "MEDIUM",
                "description": "아웃바운드가 기본값(전체 허용)으로 방치되어 있습니다. 필수는 아니지만 침해 시 탐지·통제 여지를 줄입니다.",
                "recommendation": "최소한 알려진 목적지(패키지 저장소, API 엔드포인트 등)로 좁히는 것을 검토하세요. 즉시 조치가 어렵다면 VPC Flow Logs로 아웃바운드 모니터링을 우선 확보하세요.",
            },
            {
                "rule_reference": "Inbound: TCP 5432, Source 0.0.0.0/0",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "PostgreSQL(5432)이 전체 공개되어 있습니다. RDS를 쓴다면 보안그룹으로 VPC 내부만 허용해야 합니다.",
                "recommendation": "Source를 애플리케이션 서버의 보안그룹 ID로 지정(sg-xxxx 참조)하고 CIDR 0.0.0.0/0 규칙은 삭제하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.10.1(네트워크 접근 통제)에서 요구하는 최소 권한 원칙에 위배되는 전역 공개 규칙이 다수 발견되었습니다."},
        ],
    },
    "azure_nsg": {
        "summary": "우선순위(Priority) 숫자가 낮은 광범위 허용 규칙이 앞쪽에 있어 뒤의 세부 규칙을 가리고 있고, 관리 포트가 인터넷에 그대로 열려 있습니다. 우선순위 재정렬과 소스 범위 축소가 필요합니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "Priority 100 'Allow-SSH' — Source: * (Any), Destination Port: 22, Access: Allow",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "SSH(22) 인바운드가 소스 제한 없이(Any) 허용되어 있습니다. Azure NSG는 낮은 우선순위 번호부터 평가하므로 이 규칙이 가장 먼저 적용됩니다.",
                "recommendation": "az network nsg rule update --nsg-name <NSG> --name Allow-SSH --source-address-prefixes <관리자 IP>/32 로 소스를 좁히거나, Azure Bastion으로 전환해 22번 포트 자체를 인터넷에 노출하지 마세요.",
            },
            {
                "rule_reference": "Priority 110 'Allow-RDP' — Source: * (Any), Destination Port: 3389, Access: Allow",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "RDP(3389) 인바운드가 인터넷 전체에 열려 있습니다. 무차별 대입 공격의 최우선 표적입니다.",
                "recommendation": "Source를 관리자 대역으로 제한하거나, JIT(Just-In-Time) VM Access를 활성화해 필요할 때만 임시로 열리도록 구성하세요.",
            },
            {
                "rule_reference": "Priority 120 'Allow-Any-Any' — Source: *, Destination: *, Port: *, Access: Allow",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "모든 소스/목적지/포트를 허용하는 규칙이 우선순위 120으로 매우 앞쪽에 있습니다. Azure NSG는 낮은 우선순위 번호가 먼저 적용되므로, 이 규칙이 매치되는 트래픽은 이후 규칙까지 도달하지 않습니다.",
                "recommendation": "이 규칙을 삭제하거나 우선순위 번호를 크게 올려(예: 4096에 가깝게) 다른 세부 규칙들 뒤로 밀어내세요.",
            },
            {
                "rule_reference": "Priority 200 'Deny-DB-External' (Priority 120 규칙에 가려짐)",
                "issue_type": "shadowed",
                "severity": "HIGH",
                "description": "DB 포트 외부 차단을 의도한 규칙이지만, 우선순위 120의 Allow-Any-Any가 먼저 매치되어 실제로는 한 번도 적용되지 않습니다.",
                "recommendation": "Allow-Any-Any 규칙을 정리한 후, Azure Portal의 'Effective security rules'로 이 규칙이 실제로 평가되는지 재확인하세요.",
            },
            {
                "rule_reference": "Priority 65001 'AllowInternetOutBound' (기본 규칙, 수정 안 됨)",
                "issue_type": "missing_control",
                "severity": "MEDIUM",
                "description": "아웃바운드가 Azure 기본 규칙(인터넷 전체 허용) 그대로 방치되어 있습니다. 침해 시 데이터 유출이나 C2 통신을 막을 통제가 없습니다.",
                "recommendation": "명시적인 낮은 우선순위 번호로 필요한 목적지(업데이트 서버, API 등)만 허용하는 아웃바운드 규칙을 추가하고, 그 외는 Deny로 마무리하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.10.1(네트워크 접근 통제)에서 요구하는 최소 권한 원칙에 위배되는 Any-Any 허용 규칙과 관리 포트 전역 공개가 발견되었습니다."},
        ],
    },
    "gcp_fw": {
        "summary": "기본 생성되는 SSH/RDP 허용 규칙이 0.0.0.0/0로 그대로 남아 있고, 대상 태그(targetTags)가 없는 규칙은 VPC 내 모든 인스턴스에 적용되어 의도보다 훨씬 넓은 범위에 영향을 줍니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "default-allow-ssh — direction: INGRESS, sourceRanges: [0.0.0.0/0], allowed: tcp:22",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "기본 VPC 생성 시 자동으로 만들어지는 규칙이 그대로 남아 SSH가 인터넷 전체에 열려 있습니다.",
                "recommendation": "gcloud compute firewall-rules update default-allow-ssh --source-ranges=<관리자 CIDR> 로 소스를 좁히거나, IAP(Identity-Aware Proxy) TCP 포워딩으로 전환해 22번 포트를 외부에 직접 노출하지 마세요.",
            },
            {
                "rule_reference": "default-allow-rdp — direction: INGRESS, sourceRanges: [0.0.0.0/0], allowed: tcp:3389",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "기본 RDP 허용 규칙도 마찬가지로 인터넷 전체에 열려 있습니다.",
                "recommendation": "사용하지 않는 Windows 인스턴스가 없다면 규칙 자체를 비활성화(disable)하고, 필요한 경우에도 소스를 특정 IP로 제한하세요.",
            },
            {
                "rule_reference": "allow-internal-legacy — targetTags: (없음), allowed: all protocols, sourceRanges: [10.0.0.0/8]",
                "issue_type": "overly_permissive",
                "severity": "HIGH",
                "description": "대상 태그(targetTags)가 지정되지 않아 이 규칙이 VPC 내 모든 인스턴스에 적용됩니다. 원래 특정 서버군 간 통신만 허용할 의도였다면 범위가 의도보다 훨씬 넓습니다.",
                "recommendation": "--target-tags 옵션으로 실제로 필요한 인스턴스(태그)만 대상으로 좁히고, 나머지 인스턴스는 이 규칙의 영향을 받지 않게 하세요.",
            },
            {
                "rule_reference": "default-allow-icmp — sourceRanges: [0.0.0.0/0], allowed: icmp",
                "issue_type": "overly_permissive",
                "severity": "LOW",
                "description": "ICMP(ping)가 인터넷 전체에 열려 있어 외부에서 살아있는 호스트를 쉽게 정찰할 수 있습니다. 심각도는 낮지만 정찰 표면을 늘립니다.",
                "recommendation": "굳이 인터넷에서 ping 응답이 필요하지 않다면 소스를 내부 대역이나 모니터링 시스템 IP로 제한하세요.",
            },
            {
                "rule_reference": "아웃바운드(EGRESS) 방향 규칙 없음 — GCP 기본값(전체 허용) 그대로 사용 중",
                "issue_type": "missing_control",
                "severity": "MEDIUM",
                "description": "명시적인 egress 규칙이 없어 GCP 기본 동작인 아웃바운드 전체 허용이 그대로 적용됩니다. 침해 시 외부로의 데이터 유출을 막을 통제가 없습니다.",
                "recommendation": "priority가 낮은(우선 적용되는) deny-all egress 규칙을 추가한 뒤, 실제로 필요한 목적지만 허용하는 규칙을 그보다 높은 priority로 추가하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "PCI-DSS", "note": "요구사항 1.2.1(인바운드/아웃바운드 트래픽을 필요한 것으로 제한)에 대한 아웃바운드 통제가 없고, 관리 포트가 전역 공개되어 위반 소지가 있습니다."},
        ],
    },
    "router_switch": {
        "summary": "관리 프로토콜이 암호화되지 않은 채(Telnet, SNMP 기본 커뮤니티스트링) 열려 있고, 특권 모드 비밀번호도 가역적으로 암호화되어 있어 공격자가 설정을 탈취하면 장비를 완전히 장악할 수 있는 상태입니다.",
        "overall_risk": "CRITICAL",
        "findings": [
            {
                "rule_reference": "line vty 0 4 — transport input telnet",
                "issue_type": "insecure_management",
                "severity": "CRITICAL",
                "description": "VTY(원격 관리) 회선이 평문 프로토콜인 Telnet을 허용합니다. 관리 세션의 비밀번호와 명령이 네트워크상에서 그대로 노출됩니다.",
                "recommendation": "line vty 0 4 / transport input ssh 로 SSH만 허용하도록 바꾸고, ip ssh version 2 로 SSHv2를 강제하세요.",
            },
            {
                "rule_reference": "snmp-server community public RW",
                "issue_type": "insecure_management",
                "severity": "CRITICAL",
                "description": "SNMP 커뮤니티스트링이 기본값 'public'으로 설정되어 있고 쓰기(RW) 권한까지 있습니다. 이 값을 아는 누구나 장비 설정을 원격으로 읽고 변경할 수 있습니다.",
                "recommendation": "SNMPv1/v2c community를 즉시 삭제하고 SNMPv3(인증+암호화)로 전환하거나, 최소한 커뮤니티스트링을 예측 불가능한 값으로 바꾸고 access-list로 조회 가능 IP를 제한하세요.",
            },
            {
                "rule_reference": "enable password 7 0822455D0A16",
                "issue_type": "weak_authentication",
                "severity": "HIGH",
                "description": "특권 모드 비밀번호가 가역적인 Cisco Type 7 암호화('enable password')로 저장되어 있습니다. Type 7은 공개된 알고리즘이라 설정 파일만 확보하면 즉시 평문 복호화가 가능합니다.",
                "recommendation": "enable password 대신 enable secret(Type 8/9, bcrypt/scrypt 기반)을 사용하고, 실행 중인 설정에서 Type 7 항목을 모두 제거하세요.",
            },
            {
                "rule_reference": "interface GigabitEthernet0/1 — switchport trunk native vlan 1",
                "issue_type": "missing_control",
                "severity": "MEDIUM",
                "description": "트렁크 포트의 네이티브 VLAN이 기본값인 VLAN 1로 방치되어 있습니다. VLAN 1은 CDP/STP 등 관리 트래픽이 기본으로 흐르고 VLAN 호핑 공격의 대표적 경로입니다.",
                "recommendation": "네이티브 VLAN을 사용하지 않는 별도 VLAN(예: VLAN 999)으로 바꾸고, 액세스 포트에는 switchport port-security로 연결 가능한 MAC 수를 제한하세요.",
            },
            {
                "rule_reference": "AAA/TACACS+ 설정 없음 — 로컬 계정만 존재, 관리자별 계정 분리 안 됨",
                "issue_type": "weak_authentication",
                "severity": "MEDIUM",
                "description": "aaa new-model이 설정되어 있지 않아 중앙 인증(TACACS+/RADIUS) 없이 로컬 공용 계정으로만 관리자가 접근합니다. 누가 언제 무엇을 변경했는지 추적할 수 없습니다.",
                "recommendation": "aaa new-model을 활성화하고 TACACS+/RADIUS 서버와 연동해 관리자별 개별 계정+로깅을 구성하세요. 최소한 로컬 계정이라도 관리자별로 분리하고 공용 계정은 폐기하세요.",
            },
        ],
        "compliance_notes": [
            {"framework": "ISMS-P", "note": "2.5.1(사용자 계정 관리)·2.6.1(네트워크 접근)에서 요구하는 개별 계정 관리와 안전한 인증 수단이 지켜지지 않고 있습니다."},
        ],
    },
    "windows_fw": {
        "summary": "인바운드 규칙 상당수가 프로필 제한(Public/Private/Domain) 없이 'Any'로 설정되어 있어, 노트북이 공용 Wi-Fi에 연결될 때도 사내망과 동일한 서비스가 노출됩니다.",
        "overall_risk": "HIGH",
        "findings": [
            {
                "rule_reference": "Rule 'File and Printer Sharing (SMB-In)' — Profile: Any, Action: Allow",
                "issue_type": "overly_permissive",
                "severity": "HIGH",
                "description": "SMB 공유 규칙이 Public 프로필에서도 허용되어 있습니다. 공용 네트워크에서 SMB는 대표적인 랜섬웨어 확산 경로입니다.",
                "recommendation": "프로필을 Domain, Private로만 제한하세요: Set-NetFirewallRule -DisplayName 'File and Printer Sharing (SMB-In)' -Profile Domain,Private",
            },
            {
                "rule_reference": "Rule 'RemoteDesktop-UserMode-In-TCP' — Profile: Any, Action: Allow",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "원격 데스크톱(3389) 인바운드가 모든 프로필에서 허용되어 있습니다.",
                "recommendation": "Domain/Private 프로필로 제한하고, 사내 정책상 필요하지 않다면 규칙 자체를 비활성화(Disable-NetFirewallRule)하세요.",
            },
            {
                "rule_reference": "Rule 'CustomApp-Debug-5000' — Enabled: True, 마지막 사용 확인 불가",
                "issue_type": "unused",
                "severity": "LOW",
                "description": "이름으로 보아 특정 개발용 커스텀 규칙으로 보이나, 현재도 사용 중인지 확인할 근거가 규칙 자체에는 없습니다.",
                "recommendation": "담당자에게 실사용 여부를 확인하고, 더 이상 쓰지 않는 애플리케이션이면 규칙을 삭제하세요.",
            },
            {
                "rule_reference": "인바운드 로깅(Windows Defender Firewall 로깅) 비활성화 상태",
                "issue_type": "missing_control",
                "severity": "MEDIUM",
                "description": "방화벽 차단/허용 이벤트에 대한 로깅이 꺼져 있어, 이상 트래픽이 있어도 사후 조사가 불가능합니다.",
                "recommendation": "netsh advfirewall set allprofiles logging droppedconnections enable 로 최소한 차단된 연결만이라도 로깅을 켜세요.",
            },
        ],
        "compliance_notes": [],
    },
    "other": {
        "summary": "정책 전반에 'any-any' 형태의 광범위 허용 규칙이 상단에 위치해, 그 아래 있는 세부 차단 규칙들이 실제로는 적용되지 않는(shadowed) 구조입니다.",
        "overall_risk": "HIGH",
        "findings": [
            {
                "rule_reference": "정책 #3: any any any any allow (정책 목록 최상단 근처)",
                "issue_type": "overly_permissive",
                "severity": "CRITICAL",
                "description": "출발지·목적지·서비스·포트를 모두 any로 허용하는 규칙이 순서상 앞쪽에 있습니다. 대부분의 방화벽은 첫 매치 규칙을 적용하므로, 이 규칙 이후의 세부 차단 규칙들은 도달하지 못하고 무시됩니다(shadowed rule).",
                "recommendation": "이 규칙을 삭제하거나 정책 맨 아래(기본 거부 직전)로 옮기고, 실제로 필요한 서비스/포트만 개별 허용 규칙으로 명시하세요.",
            },
            {
                "rule_reference": "정책 #3 이후의 정책 #7~#12 (내부망→DMZ 차단 규칙들)",
                "issue_type": "shadowed",
                "severity": "HIGH",
                "description": "위 any-any 규칙에 가려져 실제로는 한 번도 매치되지 않는(트래픽이 도달하지 않는) 차단 규칙들입니다.",
                "recommendation": "any-any 규칙을 고친 후 이 규칙들의 히트 카운트(hit count)를 확인해 실제로 트래픽에 적용되는지 검증하세요.",
            },
            {
                "rule_reference": "정책 #20: TCP 8080 permit, 마지막 수정일 2년 전, 설명 없음",
                "issue_type": "unused",
                "severity": "LOW",
                "description": "설명이 없고 오래 수정되지 않은 규칙입니다. 어떤 서비스를 위한 것인지 알 수 없어 안전하게 제거하기도, 유지할 근거를 대기도 어렵습니다.",
                "recommendation": "규칙 소유자/목적을 문서화하는 태깅 정책을 도입하고, 확인되지 않는 규칙은 담당자 확인 후 정리하세요.",
            },
        ],
        "compliance_notes": [],
    },
}

_DEFAULT_KEY = "other"


def generate_mock_audit(source_type: str, content: str, context: str) -> dict:
    template = _TEMPLATES.get(source_type, _TEMPLATES[_DEFAULT_KEY])
    # 얕은 복사 — 여러 요청이 같은 dict 객체를 공유해 서로 오염시키지 않도록
    return {
        "summary": template["summary"],
        "overall_risk": template["overall_risk"],
        "findings": [dict(f) for f in template["findings"]],
        "compliance_notes": [dict(c) for c in template["compliance_notes"]],
    }
