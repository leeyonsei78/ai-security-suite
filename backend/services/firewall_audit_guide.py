"""방화벽 정책 감사기용 정적 가이드 — 각 플랫폼에서 실제로 규칙을 어떻게 추출해
붙여넣거나 파일로 업로드할지 안내한다 (App 3의 recon_guide.py, App 11의 policy_guide.py와 동일한 패턴)."""

SOURCE_TYPES = [
    {
        "id": "iptables",
        "label": "Linux iptables/nftables",
        "how_to_export": "대상 서버에 SSH로 접속해 아래 명령 결과를 그대로 복사해 붙여넣거나, 파일로 저장해(`> rules.txt`) 업로드하세요.",
        "commands": ["iptables-save", "iptables -L -n -v --line-numbers", "nft list ruleset  # nftables를 쓰는 경우"],
    },
    {
        "id": "aws_sg",
        "label": "AWS 보안그룹(Security Group)",
        "how_to_export": "AWS CLI 결과 JSON을 붙여넣거나 파일로 저장해(`--output json > sg.json`) 업로드하세요. 콘솔의 인바운드/아웃바운드 규칙 표를 그대로 복사해도 됩니다.",
        "commands": ["aws ec2 describe-security-groups --group-ids sg-xxxxxxxx", "aws ec2 describe-security-groups --filters Name=vpc-id,Values=vpc-xxxxxxxx"],
    },
    {
        "id": "azure_nsg",
        "label": "Azure NSG(네트워크 보안 그룹)",
        "how_to_export": "Azure CLI 결과 JSON을 붙여넣거나 파일로 저장해(`--output json > nsg.json`) 업로드하세요. 포털에서는 NSG 리소스의 '자동화 > 템플릿 내보내기(Export template)'로도 JSON을 받을 수 있습니다.",
        "commands": ["az network nsg rule list --nsg-name <NSG이름> --resource-group <리소스그룹> --output json", "az network nsg show --name <NSG이름> --resource-group <리소스그룹>"],
    },
    {
        "id": "gcp_fw",
        "label": "GCP 방화벽 규칙(Firewall Rules)",
        "how_to_export": "gcloud CLI 결과 JSON을 붙여넣거나 파일로 저장해(`--format=json > fw.json`) 업로드하세요. 콘솔의 VPC 네트워크 > 방화벽 화면 표를 그대로 복사해도 됩니다.",
        "commands": ["gcloud compute firewall-rules list --format=json", "gcloud compute firewall-rules list --format='table(name,direction,sourceRanges.list(),allowed[].map().firewall_rule().list(),targetTags.list())'"],
    },
    {
        "id": "router_switch",
        "label": "라우터/스위치 (Cisco IOS 등)",
        "how_to_export": "SSH/콘솔로 접속해 `terminal length 0`으로 페이징을 끈 뒤 `show running-config` 결과를 터미널 로그(PuTTY/SecureCRT 등의 세션 로깅)로 저장하거나, `show running-config | redirect flash:running-config.txt` 등으로 장비에서 직접 파일로 뽑아 업로드하세요. 장비가 여러 대라면 장비별로 파일을 나눠 저장해두고 한 번에 하나씩 업로드해 감사하는 것을 권장합니다.",
        "commands": ["terminal length 0", "show running-config", "show version", "show vlan brief", "show cdp neighbors detail  # 인접 장비 정보 노출 확인용"],
    },
    {
        "id": "vpn_gateway",
        "label": "VPN/원격접속 게이트웨이 (FortiGate/Cisco AnyConnect 등)",
        "how_to_export": "SSH/콘솔로 접속해 SSL-VPN·IPsec 관련 설정 결과를 붙여넣거나 파일로 저장해 업로드하세요. FortiGate는 `show vpn ssl settings` 등, Cisco ASA/AnyConnect는 `show running-config webvpn` 등을 사용합니다. 사전공유키·비밀번호가 평문으로 포함될 수 있으니 업로드 전 실제로 사용 중인 값인지 확인하고, 필요하면 마스킹 후 업로드하세요.",
        "commands": [
            "show vpn ssl settings  # FortiGate",
            "show vpn ssl web portal",
            "show user local",
            "show running-config webvpn  # Cisco ASA/AnyConnect",
            "show running-config tunnel-group",
        ],
    },
    {
        "id": "windows_fw",
        "label": "Windows 방화벽",
        "how_to_export": "PowerShell(관리자 권한) 또는 netsh 명령 결과를 붙여넣거나, 텍스트 파일로 저장해(`> rules.txt`) 업로드하세요. GUI의 '정책 내보내기'(.wfw)는 바이너리 형식이라 지원하지 않습니다.",
        "commands": [
            "Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object DisplayName,Direction,Action,Profile | Format-Table -AutoSize",
            "netsh advfirewall firewall show rule name=all",
        ],
    },
    {
        "id": "other",
        "label": "기타 (Fortinet/Palo Alto/Cisco ASA 등 벤더 장비)",
        "how_to_export": "장비 관리 콘솔의 정책 export 기능을 쓰거나, CLI에서 아래와 유사한 명령으로 얻은 설정/정책 텍스트를 붙여넣거나 파일로 업로드하세요. 텍스트/XML 형식만 지원하며 벤더 고유 바이너리 백업 파일은 지원하지 않습니다.",
        "commands": ["show running-config firewall policy  # Fortinet 예시", "show running-config security-policy  # Palo Alto 예시", "show access-list  # Cisco ASA 예시"],
    },
]

DISCLAIMER = (
    "이 도구는 붙여넣거나 업로드한 규칙 텍스트만으로 AI가 분석합니다 — 실제 방화벽에 연결하거나 규칙을 변경하지 않습니다. "
    "업로드한 파일도 서버에 저장되지 않고 텍스트 내용만 그대로 분석에 사용됩니다. "
    "결과는 참고용 초안이며, 실제 반영 전 반드시 담당자 검토와 스테이징 환경에서의 검증을 거치세요."
)
