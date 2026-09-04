"""방화벽 정책 감사기용 정적 가이드 — 각 플랫폼에서 실제로 규칙을 어떻게 추출해
붙여넣을지 안내한다 (App 3의 recon_guide.py, App 11의 policy_guide.py와 동일한 패턴)."""

SOURCE_TYPES = [
    {
        "id": "iptables",
        "label": "Linux iptables/nftables",
        "how_to_export": "대상 서버에 SSH로 접속해 아래 명령 결과를 그대로 복사해 붙여넣으세요.",
        "commands": ["iptables -L -n -v --line-numbers", "iptables -t nat -L -n -v", "nft list ruleset  # nftables를 쓰는 경우"],
    },
    {
        "id": "aws_sg",
        "label": "AWS 보안그룹(Security Group)",
        "how_to_export": "AWS CLI 결과 JSON을 붙여넣거나, 콘솔의 인바운드/아웃바운드 규칙 표를 그대로 복사해 붙여넣으세요.",
        "commands": ["aws ec2 describe-security-groups --group-ids sg-xxxxxxxx", "aws ec2 describe-security-groups --filters Name=vpc-id,Values=vpc-xxxxxxxx"],
    },
    {
        "id": "windows_fw",
        "label": "Windows 방화벽",
        "how_to_export": "PowerShell(관리자 권한) 또는 netsh 명령 결과를 붙여넣으세요.",
        "commands": [
            "Get-NetFirewallRule | Where-Object Enabled -eq True | Select-Object DisplayName,Direction,Action,Profile | Format-Table -AutoSize",
            "netsh advfirewall firewall show rule name=all",
        ],
    },
    {
        "id": "other",
        "label": "기타 (Fortinet/Palo Alto/Cisco ASA 등 벤더 장비)",
        "how_to_export": "장비 관리 콘솔의 정책 export 기능을 쓰거나, CLI에서 아래와 유사한 명령으로 얻은 설정/정책 텍스트를 붙여넣으세요.",
        "commands": ["show running-config firewall policy  # Fortinet 예시", "show running-config security-policy  # Palo Alto 예시", "show access-list  # Cisco ASA 예시"],
    },
]

DISCLAIMER = (
    "이 도구는 붙여넣은 규칙 텍스트만으로 AI가 분석합니다 — 실제 방화벽에 연결하거나 규칙을 변경하지 않습니다. "
    "결과는 참고용 초안이며, 실제 반영 전 반드시 담당자 검토와 스테이징 환경에서의 검증을 거치세요."
)
