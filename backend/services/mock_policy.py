_COMPLIANCE_ITEMS = {
    "PCI-DSS": [
        "요구사항 1: 카드소지자 데이터 환경을 보호하는 방화벽/라우터 구성 표준 수립 → 아래 방화벽 규칙 세트가 대응",
        "요구사항 7-8: 업무상 필요한 자만 접근 가능하도록 최소 권한 원칙 적용 → '접근 통제' 정책 참고",
        "요구사항 10: 네트워크 자원 및 카드소지자 데이터 접근에 대한 모든 로그 기록 → '로깅 및 모니터링' 정책 참고",
    ],
    "ISMS-P": [
        "2.6 접근통제: 정보시스템 접근권한을 업무상 필요한 최소한으로 부여",
        "2.9 시스템 및 서비스 운영관리: 변경관리, 성능·장애 모니터링 절차 수립",
        "2.10 시스템 및 서비스 보안관리: 네트워크 보안, 서버 보안, 정보전송 보안 조치",
        "2.11 사고 예방 및 대응: 침해사고 대응체계 수립 및 훈련",
    ],
    "개인정보보호법": [
        "제29조(안전조치의무): 개인정보 처리시스템에 대한 접근 통제 및 접근권한 관리",
        "개인정보의 안전성 확보조치 기준: 개인정보 암호화(비밀번호, 고유식별정보 등)",
        "접속기록의 보관 및 위·변조 방지 조치",
    ],
    "GDPR": [
        "Art. 32 (Security of processing): 개인데이터 처리에 적합한 기술적·관리적 보호조치",
        "Art. 25 (Data protection by design and by default): 설계 단계부터 최소 수집·기본 보호 적용",
        "Art. 33 (침해 통지): 침해 인지 후 72시간 이내 감독기관 통지 절차 마련",
    ],
    "HIPAA": [
        "Security Rule §164.312: 접근 통제, 감사 로그, 무결성 보호, 전송 보안 기술적 안전조치",
        "Security Rule §164.308: 위험 분석 및 관리 절차 수립",
    ],
}

_TEMPLATES = {
    "web_server": {
        "summary": "인터넷에 공개된 웹 서버(리버스 프록시+WAS) 환경으로, 외부 공격 표면이 넓어 DMZ 분리·TLS 강제·SSH 접근 제한이 우선 과제입니다.",
        "firewall_rules": [
            {"id": "FW-001", "action": "ALLOW", "protocol": "TCP", "port": "443", "source": "0.0.0.0/0", "destination": "웹 서버(DMZ)", "description": "HTTPS 트래픽만 외부에 공개"},
            {"id": "FW-002", "action": "DENY", "protocol": "TCP", "port": "80", "source": "0.0.0.0/0", "destination": "웹 서버(DMZ)", "description": "HTTP는 443으로 강제 리다이렉트 후 차단(평문 전송 금지)"},
            {"id": "FW-003", "action": "ALLOW", "protocol": "TCP", "port": "22", "source": "VPN 대역 (10.10.0.0/24)", "destination": "웹 서버(DMZ)", "description": "SSH는 사내 VPN 경유 접속만 허용"},
            {"id": "FW-004", "action": "DENY", "protocol": "TCP", "port": "22", "source": "0.0.0.0/0", "destination": "웹 서버(DMZ)", "description": "SSH 전역 공개 차단 (기본 정책)"},
            {"id": "FW-005", "action": "ALLOW", "protocol": "TCP", "port": "3306/5432", "source": "웹 서버(DMZ)", "destination": "DB 서버(내부망)", "description": "WAS→DB만 허용, 역방향 및 외부 직접 접근 불가"},
            {"id": "FW-006", "action": "DENY", "protocol": "ANY", "port": "ALL", "source": "0.0.0.0/0", "destination": "DB 서버(내부망)", "description": "DB는 인터넷에서 직접 도달 불가능해야 함"},
        ],
        "policies": [
            {
                "category": "네트워크 분리",
                "title": "DMZ / 내부망 분리",
                "rules": [
                    "인터넷에 노출되는 웹 서버는 DMZ에 배치하고 내부망(DB, 관리 시스템)과 별도 세그먼트로 분리한다",
                    "DMZ→내부망 통신은 WAS→DB 등 명시적으로 필요한 경로만 허용한다",
                    "내부망→DMZ 역방향 연결은 원칙적으로 차단한다",
                ],
                "rationale": "웹 서버가 침해되어도 공격자가 곧바로 내부 자산에 접근하지 못하도록 확산 반경을 제한한다.",
            },
            {
                "category": "접근 통제",
                "title": "관리 접근(SSH) 최소화",
                "rules": [
                    "SSH는 비밀번호 인증을 비활성화하고 키 기반 인증만 허용한다",
                    "SSH 접속은 사내 VPN 대역에서만 허용하고, 소스 IP 전역 공개(0.0.0.0/0)를 금지한다",
                    "관리자 계정에 대해 가능한 경우 MFA를 적용한다",
                ],
                "rationale": "SSH 브루트포스·자격증명 탈취는 웹 서버 침해의 가장 흔한 경로 중 하나다.",
            },
            {
                "category": "데이터 보호",
                "title": "전송 구간 암호화",
                "rules": [
                    "모든 외부 트래픽은 TLS 1.2 이상을 강제하고 HTTP는 HTTPS로 리다이렉트한다",
                    "HSTS 헤더를 적용해 평문 접속 자체를 브라우저 단에서 차단한다",
                    "만료 임박 인증서에 대한 자동 갱신(예: Let's Encrypt certbot)을 구성한다",
                ],
                "rationale": "평문 HTTP는 중간자 공격(MITM)과 세션 탈취에 취약하다.",
            },
            {
                "category": "로깅 및 모니터링",
                "title": "접근/에러 로그 수집",
                "rules": [
                    "웹 서버 access log, error log를 중앙 로그 시스템으로 수집한다",
                    "비정상 요청 패턴(다량의 4xx/5xx, SQLi·XSS 시그니처)에 대한 알림을 설정한다",
                    "가능하면 WAF(웹 방화벽)를 프록시 앞단에 배치해 알려진 공격 패턴을 1차 차단한다",
                ],
                "rationale": "실시간 로그 없이는 침해를 사후에조차 파악할 수 없다.",
            },
            {
                "category": "패치 및 취약점 관리",
                "title": "정기 패치 주기",
                "rules": [
                    "OS 및 웹서버(nginx/Apache)·WAS·의존성 패키지의 보안 패치를 월 1회 이상 점검·적용한다",
                    "CVE 공표 후 심각도 HIGH 이상은 72시간 이내 임시 조치 또는 패치를 적용한다",
                ],
                "rationale": "공개된 CVE는 패치 지연 시간 자체가 공격 성공 확률을 높인다.",
            },
            {
                "category": "사고 대응",
                "title": "웹셸/침해 탐지 시 대응",
                "rules": [
                    "웹 루트 디렉토리에 대한 파일 무결성 모니터링(FIM)을 적용해 미승인 파일 생성을 탐지한다",
                    "침해 의심 시 해당 서버를 네트워크에서 즉시 격리하고 스냅샷을 보존한 뒤 조사한다",
                    "사고 발생 시 연락 체계와 1차 대응 담당자를 사전에 지정해둔다",
                ],
                "rationale": "웹 서버는 초기 침투 지점이 되는 경우가 많아 탐지·격리 속도가 피해 규모를 좌우한다.",
            },
        ],
        "risk_notes": [
            "설명에 SSH(22번 포트)가 전체 공개(0.0.0.0/0)로 운영 중이라는 내용이 포함되어 있다면 최우선으로 VPN 경유 접속으로 전환하세요.",
            "DB가 웹 서버와 같은 네트워크 대역에 있고 외부에서 직접 접근 가능하다면 즉시 내부망으로 분리하세요.",
        ],
    },
    "cloud": {
        "summary": "퍼블릭 클라우드(AWS/Azure/GCP류) 인프라 환경으로, IAM 최소 권한과 스토리지 퍼블릭 노출 방지, 클라우드 활동 로그 확보가 핵심입니다.",
        "firewall_rules": [
            {"id": "SG-001", "action": "ALLOW", "protocol": "TCP", "port": "443", "source": "0.0.0.0/0", "destination": "퍼블릭 서브넷 (ALB/LB)", "description": "로드밸런서를 통한 HTTPS만 공개"},
            {"id": "SG-002", "action": "DENY", "protocol": "TCP", "port": "3389/22", "source": "0.0.0.0/0", "destination": "전체 인스턴스", "description": "RDP/SSH 전역 공개 금지, Bastion/SSM 경유만 허용"},
            {"id": "SG-003", "action": "ALLOW", "protocol": "TCP", "port": "22", "source": "Bastion Host SG", "destination": "프라이빗 서브넷 인스턴스", "description": "Bastion을 통한 SSH만 허용"},
            {"id": "SG-004", "action": "DENY", "protocol": "ANY", "port": "ALL", "source": "0.0.0.0/0", "destination": "프라이빗 서브넷", "description": "프라이빗 서브넷은 인터넷 게이트웨이로부터 직접 도달 불가"},
        ],
        "policies": [
            {
                "category": "계정 및 인증 관리 (IAM)",
                "title": "최소 권한 IAM 정책",
                "rules": [
                    "루트 계정은 일상 업무에 사용하지 않고 MFA를 반드시 적용한다",
                    "IAM 사용자/역할은 필요한 최소 권한만 부여하고 와일드카드(*) 권한 정책을 지양한다",
                    "액세스 키는 정기적으로(예: 90일) 로테이션하고 미사용 키는 즉시 폐기한다",
                ],
                "rationale": "클라우드 침해의 상당수는 과도한 IAM 권한 또는 유출된 액세스 키에서 시작된다.",
            },
            {
                "category": "데이터 보호",
                "title": "스토리지 퍼블릭 노출 차단",
                "rules": [
                    "오브젝트 스토리지(S3 등) 버킷은 기본적으로 퍼블릭 액세스를 차단한다",
                    "저장 데이터는 기본 암호화(SSE-KMS 등)를 활성화한다",
                    "버킷/디스크 정책 변경 시 승인 절차를 거치도록 한다",
                ],
                "rationale": "설정 실수로 인한 스토리지 퍼블릭 노출은 클라우드 환경에서 가장 흔한 개인정보 유출 원인이다.",
            },
            {
                "category": "네트워크 분리",
                "title": "퍼블릭/프라이빗 서브넷 분리",
                "rules": [
                    "로드밸런서 등 외부 노출이 필요한 리소스만 퍼블릭 서브넷에 배치한다",
                    "애플리케이션·DB 인스턴스는 프라이빗 서브넷에 배치하고 NAT를 통해서만 아웃바운드를 허용한다",
                    "관리 접속(SSH/RDP)은 Bastion Host 또는 SSM Session Manager를 통해서만 허용한다",
                ],
                "rationale": "인스턴스를 퍼블릭 IP로 직접 노출하지 않는 것만으로 공격 표면이 크게 줄어든다.",
            },
            {
                "category": "로깅 및 모니터링",
                "title": "클라우드 활동 로그 확보",
                "rules": [
                    "계정 단위로 API 호출 감사 로그(CloudTrail 등)를 활성화하고 별도 계정/버킷에 보관한다",
                    "IAM 정책 변경, 보안 그룹 변경, 루트 로그인 등 민감 이벤트에 실시간 알림을 구성한다",
                    "로그 보관 기간은 컴플라이언스 요구사항에 맞춰 최소 1년 이상 유지한다",
                ],
                "rationale": "활동 로그 없이는 계정 침해 여부와 피해 범위를 사후 재구성할 수 없다.",
            },
            {
                "category": "사고 대응",
                "title": "계정/키 침해 대응",
                "rules": [
                    "액세스 키 유출 의심 시 즉시 비활성화하고 관련 세션을 강제 종료한다",
                    "비정상 리전에서의 리소스 생성, 급격한 권한 상승 시도를 탐지 대상으로 정의한다",
                    "침해 계정으로 생성된 리소스(신규 IAM 사용자, 스냅샷 공유 등)를 전수 점검한다",
                ],
                "rationale": "클라우드는 자동화로 인해 계정 침해 시 피해가 수 분 내 확산될 수 있다.",
            },
        ],
        "risk_notes": [
            "설명에 스토리지 버킷이 '퍼블릭 읽기 허용' 등으로 명시되어 있다면 개인정보 유출 여부를 즉시 확인하세요.",
            "IAM 정책에 Action: '*', Resource: '*' 형태의 광범위한 권한이 있다면 최소 권한으로 즉시 재설계하세요.",
        ],
    },
    "internal_network": {
        "summary": "사내 업무망 환경으로, 부서/용도별 네트워크 분리(VLAN)와 단말 통제, 내부자 위협 대응이 핵심 과제입니다.",
        "firewall_rules": [
            {"id": "FW-101", "action": "ALLOW", "protocol": "TCP", "port": "80/443", "source": "업무망 VLAN10", "destination": "인터넷", "description": "일반 업무용 웹 접속 허용(프록시 경유 권장)"},
            {"id": "FW-102", "action": "DENY", "protocol": "ANY", "port": "ALL", "source": "게스트 VLAN30", "destination": "업무망 VLAN10 / 서버망 VLAN20", "description": "게스트 네트워크는 내부 자원에 접근 불가, 인터넷만 허용"},
            {"id": "FW-103", "action": "ALLOW", "protocol": "TCP", "port": "445/3389", "source": "IT 관리 VLAN40", "destination": "업무망 VLAN10", "description": "PC 원격 관리는 IT망에서만 허용"},
            {"id": "FW-104", "action": "DENY", "protocol": "TCP", "port": "445/3389", "source": "업무망 VLAN10", "destination": "업무망 VLAN10", "description": "동일 VLAN 내 단말 간 SMB/RDP 직접 통신 차단(랜섬웨어 확산 방지)"},
            {"id": "FW-105", "action": "ALLOW", "protocol": "TCP", "port": "1433/3306", "source": "서버망 VLAN20 (특정 애플리케이션 서버만)", "destination": "서버망 VLAN20 (DB)", "description": "DB는 지정된 애플리케이션 서버에서만 접근"},
        ],
        "policies": [
            {
                "category": "네트워크 분리",
                "title": "VLAN 기반 망 분리",
                "rules": [
                    "업무망, 서버망, 게스트망, IT 관리망을 별도 VLAN으로 분리한다",
                    "VLAN 간 통신은 방화벽/L3 스위치 ACL로 명시적으로 허용된 경로만 통과시킨다",
                    "게스트 네트워크는 내부 자원에 대한 접근을 전면 차단하고 인터넷 접속만 허용한다",
                ],
                "rationale": "망 분리는 랜섬웨어 등 위협의 수평 이동(lateral movement)을 차단하는 가장 기본적인 방어선이다.",
            },
            {
                "category": "접근 통제",
                "title": "단말 및 매체 통제",
                "rules": [
                    "NAC(Network Access Control)로 등록되지 않은 단말의 사내망 접속을 차단한다",
                    "업무상 불필요한 USB 저장매체 사용을 원칙적으로 제한한다",
                    "퇴사/직무변경 시 계정·VPN·VLAN 접근권한을 즉시 회수한다",
                ],
                "rationale": "내부자 위협과 관리되지 않는 단말은 외부 침입 못지않은 유출 경로가 된다.",
            },
            {
                "category": "패치 및 취약점 관리",
                "title": "내부 자산 취약점 관리",
                "rules": [
                    "사내 서버/PC에 대해 정기적인 자산 인벤토리와 취약점 스캔을 수행한다",
                    "SMB1 등 알려진 취약 프로토콜은 비활성화한다",
                    "백신/EDR을 전 단말에 배포하고 탐지 정책을 중앙 관리한다",
                ],
                "rationale": "내부망은 외부 대비 방어가 느슨해지기 쉬워 침투 후 확산의 주 무대가 된다.",
            },
            {
                "category": "백업 및 복구",
                "title": "오프라인/불변 백업",
                "rules": [
                    "핵심 서버는 정기 백업을 수행하고 최소 1개 사본은 네트워크와 분리 보관한다",
                    "백업 복구 절차를 주기적으로(예: 반기 1회) 실제 테스트한다",
                ],
                "rationale": "랜섬웨어 피해 시 몸값 지불 없이 복구할 수 있는 유일한 방법은 격리된 백업이다.",
            },
            {
                "category": "사고 대응",
                "title": "내부 확산 탐지 및 격리",
                "rules": [
                    "짧은 시간 내 다수 단말에서 반복되는 SMB/RDP 연결 시도를 랜섬웨어 확산 징후로 정의하고 알림을 설정한다",
                    "감염 의심 단말은 네트워크 포트/Wi-Fi 접속을 즉시 차단하여 격리한다",
                ],
                "rationale": "내부망 위협은 탐지가 늦을수록 감염 범위가 기하급수적으로 커진다.",
            },
        ],
        "risk_notes": [
            "설명에 전 사원이 동일한 대역에서 서버망에 직접 접근 가능하다는 내용이 있다면 VLAN 분리를 최우선 과제로 삼으세요.",
            "게스트 Wi-Fi가 사내망과 분리되어 있지 않다면 즉시 별도 VLAN/SSID로 분리하세요.",
        ],
    },
    "container": {
        "summary": "Docker/Kubernetes 기반 컨테이너 환경으로, 이미지 신뢰성·런타임 격리·시크릿 관리가 전통적 네트워크 방화벽보다 우선하는 과제입니다.",
        "firewall_rules": [
            {"id": "NP-001", "action": "DENY", "protocol": "ANY", "port": "ALL", "source": "전체 Pod (기본값)", "destination": "전체 Pod", "description": "기본 Deny-All NetworkPolicy로 시작, 필요한 통신만 명시적으로 허용"},
            {"id": "NP-002", "action": "ALLOW", "protocol": "TCP", "port": "8080", "source": "frontend 네임스페이스", "destination": "backend 네임스페이스", "description": "프론트→백엔드 API 통신만 허용"},
            {"id": "NP-003", "action": "ALLOW", "protocol": "TCP", "port": "5432", "source": "backend 네임스페이스", "destination": "database 네임스페이스", "description": "백엔드→DB 통신만 허용, 다른 네임스페이스의 DB 직접 접근 차단"},
            {"id": "NP-004", "action": "DENY", "protocol": "TCP", "port": "6443", "source": "0.0.0.0/0", "destination": "Kubernetes API 서버", "description": "API 서버는 관리 네트워크(VPN/사설망)에서만 접근 허용"},
        ],
        "policies": [
            {
                "category": "이미지 및 공급망 보안",
                "title": "신뢰할 수 있는 이미지만 배포",
                "rules": [
                    "베이스 이미지는 공식/사내 승인된 레지스트리에서만 가져오고 latest 태그 사용을 금지한다",
                    "CI 파이프라인에 이미지 취약점 스캔(예: Trivy)을 통합하고 HIGH/CRITICAL 발견 시 배포를 차단한다",
                    "사용하지 않는 오래된 이미지는 레지스트리에서 정기적으로 정리한다",
                ],
                "rationale": "컨테이너는 이미지 자체가 공격 벡터가 될 수 있어 빌드 단계 검증이 필수적이다.",
            },
            {
                "category": "런타임 격리",
                "title": "최소 권한 컨테이너 실행",
                "rules": [
                    "컨테이너는 root가 아닌 전용 사용자로 실행한다(runAsNonRoot)",
                    "불필요한 Linux capability를 제거하고 privileged 컨테이너 실행을 금지한다",
                    "호스트 경로(hostPath) 마운트는 반드시 필요한 경우로 제한한다",
                ],
                "rationale": "컨테이너 탈출(escape) 공격의 상당수는 과도한 권한(root, privileged)에서 비롯된다.",
            },
            {
                "category": "네트워크 분리",
                "title": "네임스페이스 기반 NetworkPolicy",
                "rules": [
                    "네임스페이스별 기본 Deny-All NetworkPolicy를 적용한 뒤 필요한 통신만 화이트리스트로 허용한다",
                    "Kubernetes API 서버(6443)는 관리망에서만 접근 가능하도록 제한한다",
                ],
                "rationale": "클러스터 내부는 기본적으로 모든 Pod가 통신 가능해 세그멘테이션이 없으면 확산이 매우 빠르다.",
            },
            {
                "category": "계정 및 인증 관리 (RBAC)",
                "title": "네임스페이스별 최소 권한 RBAC",
                "rules": [
                    "cluster-admin 역할 부여를 최소화하고 네임스페이스 단위 Role/RoleBinding을 사용한다",
                    "서비스 계정 토큰 자동 마운트는 필요한 Pod에만 허용한다",
                ],
                "rationale": "과도한 RBAC 권한은 침해된 단일 Pod로부터 클러스터 전체 장악으로 이어질 수 있다.",
            },
            {
                "category": "데이터 보호",
                "title": "시크릿 관리",
                "rules": [
                    "DB 비밀번호, API 키 등은 환경변수 하드코딩 대신 Secret 오브젝트 또는 외부 시크릿 매니저를 사용한다",
                    "Secret은 etcd 저장 시 암호화(encryption at rest)를 활성화한다",
                ],
                "rationale": "컨테이너 이미지/매니페스트에 하드코딩된 시크릿은 흔한 노출 원인이다.",
            },
            {
                "category": "로깅 및 모니터링",
                "title": "클러스터 감사 로그",
                "rules": [
                    "Kubernetes 감사 로그(Audit Log)를 활성화하고 exec/RBAC 변경 등 민감 이벤트를 별도 보관한다",
                    "컨테이너 표준 출력 로그를 중앙 수집(EFK/Loki 등)한다",
                ],
                "rationale": "컨테이너는 수명이 짧아 로그를 실시간으로 외부화하지 않으면 사고 조사가 불가능하다.",
            },
        ],
        "risk_notes": [
            "설명에 privileged 컨테이너 또는 hostPath 마운트가 언급되어 있다면 컨테이너 탈출 위험을 우선 점검하세요.",
            "NetworkPolicy가 전혀 없는 클러스터라면(기본 all-allow) 위 Deny-All 기본 정책 도입을 최우선으로 권장합니다.",
        ],
    },
    "database": {
        "summary": "데이터베이스 서버 환경으로, 네트워크 접근 최소화·저장/전송 암호화·계정별 최소 권한이 핵심 과제입니다.",
        "firewall_rules": [
            {"id": "FW-201", "action": "ALLOW", "protocol": "TCP", "port": "3306/5432", "source": "애플리케이션 서버 (지정 IP만)", "destination": "DB 서버", "description": "지정된 애플리케이션 서버 IP에서만 DB 포트 접근 허용"},
            {"id": "FW-202", "action": "DENY", "protocol": "TCP", "port": "3306/5432", "source": "0.0.0.0/0", "destination": "DB 서버", "description": "DB 포트 전역 공개 차단 (기본 정책)"},
            {"id": "FW-203", "action": "ALLOW", "protocol": "TCP", "port": "22", "source": "관리 서브넷/Bastion", "destination": "DB 서버", "description": "DB 서버 관리 접속은 Bastion 경유만 허용"},
            {"id": "FW-204", "action": "DENY", "protocol": "ANY", "port": "ALL", "source": "DB 서버", "destination": "인터넷 (0.0.0.0/0)", "description": "DB 서버의 아웃바운드 인터넷 접속을 원칙적으로 차단(데이터 유출 경로 차단)"},
        ],
        "policies": [
            {
                "category": "네트워크 분리",
                "title": "DB 접근 경로 최소화",
                "rules": [
                    "DB는 사설 네트워크에 배치하고 퍼블릭 IP를 부여하지 않는다",
                    "허용된 애플리케이션 서버 IP 외의 접근은 방화벽에서 기본 차단한다",
                    "가능하면 DB 프록시/커넥션 풀러를 경유하여 접근 경로를 단일화한다",
                ],
                "rationale": "DB 직접 노출은 크리덴셜 유출 시 즉시 전체 데이터 탈취로 이어진다.",
            },
            {
                "category": "데이터 보호",
                "title": "저장 및 전송 구간 암호화",
                "rules": [
                    "주민등록번호, 비밀번호, 카드번호 등 민감 컬럼은 애플리케이션/컬럼 단위로 암호화한다",
                    "DB 커넥션은 TLS를 사용하고 평문 커넥션을 비활성화한다",
                    "백업 파일도 저장 시 암호화를 적용한다",
                ],
                "rationale": "네트워크 통제가 뚫리더라도 암호화된 데이터는 실질 피해를 크게 낮춘다.",
            },
            {
                "category": "계정 및 인증 관리",
                "title": "DB 계정 최소 권한",
                "rules": [
                    "애플리케이션 전용 계정은 필요한 테이블/操작에 한정된 권한만 부여하고 관리자(root/sa) 계정 사용을 금지한다",
                    "DB 계정 비밀번호는 정기적으로 교체하고 애플리케이션 코드에 하드코딩하지 않는다",
                    "가능한 경우 DB 접속에도 MFA 또는 IP 화이트리스트를 병행한다",
                ],
                "rationale": "SQL 인젝션 등으로 계정이 탈취되어도 권한이 제한적이면 피해 범위가 줄어든다.",
            },
            {
                "category": "로깅 및 모니터링",
                "title": "쿼리/접속 감사",
                "rules": [
                    "DB 접속 로그와 주요 DML(SELECT 대량 조회 포함) 감사 로그를 활성화한다",
                    "평소와 다른 대량 데이터 조회(예: 전체 테이블 SELECT)에 대한 알림을 설정한다",
                ],
                "rationale": "대량 유출은 사전 탐지 없이는 사고 후에야 규모를 파악하게 된다.",
            },
            {
                "category": "백업 및 복구",
                "title": "정기 백업 및 복구 검증",
                "rules": [
                    "일 단위 전체 백업 + 시간 단위 증분 백업 등 RPO 목표에 맞는 백업 주기를 수립한다",
                    "백업 데이터도 원본과 동일한 수준의 접근 통제·암호화를 적용한다",
                    "분기 1회 이상 복구 테스트를 수행해 백업의 실효성을 검증한다",
                ],
                "rationale": "백업이 있어도 복구가 검증되지 않으면 실제 사고 시 무용지물이 될 수 있다.",
            },
        ],
        "risk_notes": [
            "설명에 DB가 공인 IP로 직접 개방되어 있거나 기본 계정(root/admin)을 그대로 사용 중이라면 최우선 조치 대상입니다.",
            "주민등록번호·카드번호 등 고유식별정보가 평문으로 저장된다고 서술되어 있다면 즉시 암호화 적용이 필요합니다.",
        ],
    },
}


def generate_mock_policy(environment_type: str, compliance: list[str], description: str) -> dict:
    template = _TEMPLATES.get(environment_type, _TEMPLATES["web_server"])
    frameworks = compliance if compliance else list(_COMPLIANCE_ITEMS.keys())
    compliance_mapping = [
        {"framework": fw, "items": _COMPLIANCE_ITEMS[fw]}
        for fw in frameworks
        if fw in _COMPLIANCE_ITEMS
    ]
    return {
        "summary": template["summary"],
        "firewall_rules": template["firewall_rules"],
        "policies": template["policies"],
        "risk_notes": template["risk_notes"],
        "compliance_mapping": compliance_mapping,
        "_mock": True,
    }
