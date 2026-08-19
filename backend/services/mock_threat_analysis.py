MOCK_RESULTS = {
    "malware": {
        "analysis_type": "malware",
        "malware_type": "Remote Access Trojan (RAT) + InfoStealer",
        "threat_level": "HIGH",
        "confidence": 89,
        "summary": (
            "분석된 샘플은 PowerShell 기반 RAT으로, C2 서버와 암호화 채널로 통신하며 "
            "키로깅·스크린샷·자격증명 탈취 기능을 갖고 있습니다. "
            "Persistence를 위해 레지스트리 Run 키와 예약 작업을 동시에 등록하며, "
            "AV 회피를 위해 AMSI 우회 기법을 사용합니다."
        ),
        "capabilities": [
            "원격 명령 실행 (cmd/PowerShell)",
            "키로깅 및 클립보드 탈취",
            "화면 캡처 (30초 주기)",
            "브라우저 저장 자격증명 덤프",
            "파일 업로드/다운로드",
            "AMSI 우회 및 ETW 패치",
        ],
        "iocs": [
            {"type": "domain",  "value": "update-service[.]net",        "description": "C2 서버 도메인 (DGA 패턴)"},
            {"type": "ip",      "value": "185.220.101[.]47",            "description": "C2 IP (Tor 출구 노드 대역)"},
            {"type": "url",     "value": "hxxps://update-service[.]net/api/beacon", "description": "비콘 엔드포인트"},
            {"type": "hash_md5","value": "a3f2c8b1d4e5f6a7b8c9d0e1f2a3b4c5", "description": "드로퍼 MD5"},
            {"type": "hash_sha256","value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "description": "페이로드 SHA-256"},
            {"type": "registry","value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender", "description": "지속성 레지스트리 키"},
            {"type": "file",    "value": "%APPDATA%\\Microsoft\\Windows\\wmiprvse32.exe", "description": "드롭된 악성 실행 파일"},
            {"type": "mutex",   "value": "Global\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}", "description": "중복 실행 방지 뮤텍스"},
        ],
        "mitre_techniques": [
            {"id": "T1059.001", "name": "PowerShell",                    "tactic": "Execution",           "color": "orange"},
            {"id": "T1547.001", "name": "Registry Run Keys / Startup",   "tactic": "Persistence",         "color": "yellow"},
            {"id": "T1053.005", "name": "Scheduled Task",                "tactic": "Persistence",         "color": "yellow"},
            {"id": "T1562.001", "name": "Disable or Modify Tools (AMSI)","tactic": "Defense Evasion",     "color": "purple"},
            {"id": "T1055.002", "name": "Portable Executable Injection", "tactic": "Defense Evasion",     "color": "purple"},
            {"id": "T1056.001", "name": "Keylogging",                    "tactic": "Credential Access",   "color": "pink"},
            {"id": "T1555.003", "name": "Credentials from Web Browsers", "tactic": "Credential Access",   "color": "pink"},
            {"id": "T1113",     "name": "Screen Capture",                "tactic": "Collection",          "color": "teal"},
            {"id": "T1071.001", "name": "Web Protocols (HTTPS C2)",      "tactic": "Command and Control", "color": "violet"},
            {"id": "T1041",     "name": "Exfiltration Over C2 Channel",  "tactic": "Exfiltration",        "color": "amber"},
        ],
        "behavior": {
            "network":      "C2 서버(update-service[.]net)와 HTTPS/443으로 30초마다 비콘 통신. 데이터 전송 시 AES-256 암호화.",
            "file_system":  "%APPDATA%\\Microsoft\\Windows\\에 wmiprvse32.exe 드롭. %TEMP%에 임시 로그 파일 생성 후 삭제.",
            "registry":     "HKCU\\Run에 자동 시작 등록. HKCU\\Software\\{GUID} 에 설정값·수집 데이터 저장.",
            "processes":    "explorer.exe에 PE 인젝션으로 은폐. WMI를 통해 프로세스 생성하여 부모-자식 관계 난독화.",
        },
        "recommendations": [
            "탐지된 C2 도메인/IP를 방화벽 및 DNS 싱크홀에 즉시 등록",
            "레지스트리 Run 키 및 예약 작업 전체 감사 실시",
            "AMSI 정책 및 PowerShell 제한 모드(Constrained Language Mode) 활성화",
            "EDR으로 프로세스 인젝션 탐지 규칙 추가",
            "감염 시스템은 치료 대신 재설치 권장",
            "탈취된 자격증명을 가정하고 전체 계정 비밀번호 초기화",
        ],
        "_mock": True,
    },
    "forensics": {
        "analysis_type": "forensics",
        "threat_level": "CRITICAL",
        "confidence": 92,
        "summary": (
            "Windows 이벤트 로그 및 파일 시스템 아티팩트 분석 결과, 2024년 1월 15일 오전 9시 23분을 "
            "기점으로 외부 공격자가 스피어피싱 이메일을 통해 초기 침투에 성공했습니다. "
            "이후 권한 상승 → 횡적 이동 → 데이터 스테이징 순으로 공격이 진행됐으며, "
            "약 14.3GB의 데이터가 외부로 유출된 것으로 추정됩니다."
        ),
        "timeline": [
            {"time": "2024-01-15 09:23:14", "event": "악성 첨부파일(Invoice_Jan.xlsx) 열기 — Excel 매크로 실행",        "severity": "HIGH"},
            {"time": "2024-01-15 09:23:19", "event": "mshta.exe를 통해 원격 HTA 페이로드 다운로드 및 실행",            "severity": "CRITICAL"},
            {"time": "2024-01-15 09:24:02", "event": "PowerShell로 Mimikatz 변형 도구 메모리 로드 (LSASS 덤프)",       "severity": "CRITICAL"},
            {"time": "2024-01-15 09:31:47", "event": "PsExec으로 파일 서버(192.168.1.50)에 횡적 이동",                "severity": "HIGH"},
            {"time": "2024-01-15 10:15:33", "event": "robocopy로 문서 폴더 데이터 %TEMP%\\staging\\ 에 집결",          "severity": "HIGH"},
            {"time": "2024-01-15 10:58:21", "event": "7zip으로 데이터 암호화 압축 (14.3GB) → 외부 서버로 전송 시작",  "severity": "CRITICAL"},
            {"time": "2024-01-15 11:42:09", "event": "이벤트 로그 일괄 삭제 (wevtutil cl 명령 실행)",                  "severity": "HIGH"},
            {"time": "2024-01-15 11:44:31", "event": "VSS(볼륨 섀도 복사본) 전체 삭제",                               "severity": "HIGH"},
        ],
        "artifacts": [
            {"type": "file",     "value": "C:\\Users\\user01\\AppData\\Local\\Temp\\staging\\",             "suspicious": True,  "description": "데이터 스테이징 디렉토리 (14.3GB)"},
            {"type": "file",     "value": "C:\\Windows\\Temp\\mshta32.exe",                                 "suspicious": True,  "description": "정상 mshta.exe를 위장한 악성 실행 파일"},
            {"type": "file",     "value": "C:\\Users\\user01\\Downloads\\Invoice_Jan.xlsx",                 "suspicious": True,  "description": "스피어피싱 첨부파일 (최초 침투 벡터)"},
            {"type": "registry", "value": "HKCU\\Environment\\ComSpec",                                    "suspicious": True,  "description": "ComSpec 변조로 cmd.exe 대체"},
            {"type": "process",  "value": "PID 4821: powershell.exe (parent: excel.exe)",                  "suspicious": True,  "description": "Excel에서 직접 PowerShell 실행 — 의심"},
            {"type": "network",  "value": "TCP 192.168.1.10:49823 → 94.102.49[.]190:443 (ESTABLISHED)",   "suspicious": True,  "description": "외부 데이터 유출 연결"},
            {"type": "log",      "value": "Security EventID 4624 (Logon) — 새벽 2-4시 반복",              "suspicious": True,  "description": "업무 외 시간대 로그인 — 공격자 지속 접근"},
            {"type": "file",     "value": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx (0 bytes)",  "suspicious": True,  "description": "보안 이벤트 로그 삭제됨"},
        ],
        "findings": [
            "최초 침투 벡터: 스피어피싱 이메일 첨부 매크로 문서 (Excel)",
            "자격증명 탈취: LSASS 메모리 덤프로 도메인 관리자 계정 확보",
            "횡적 이동: PsExec 활용, 파일 서버 2대 추가 침해 확인",
            "데이터 유출: 약 14.3GB 압축 후 외부 서버(94.102.49.190)로 전송",
            "흔적 삭제: 이벤트 로그 및 VSS 삭제로 포렌식 방해 시도",
            "침해 지속 기간: 최소 72시간 이상 (이벤트 로그 부재로 추가 확인 필요)",
        ],
        "recommendations": [
            "전체 도메인 계정 비밀번호 즉시 초기화 (도메인 관리자 포함)",
            "침해된 파일 서버 네트워크 격리 및 포렌식 이미징",
            "유출 IP(94.102.49.190) 방화벽 차단 및 추가 통신 이력 수집",
            "잔존 백도어 계정 확인: 신규 생성 계정 전수 조사",
            "이벤트 로그 포워딩(SIEM) 설정으로 향후 실시간 탐지 강화",
            "개인정보보호위원회 신고 의무 검토 (개인정보 유출 여부 확인)",
        ],
        "_mock": True,
    },
    "memory": {
        "analysis_type": "memory",
        "threat_level": "HIGH",
        "confidence": 84,
        "summary": (
            "메모리 덤프 분석 결과 3개의 악성 프로세스 인젝션과 2개의 숨김 프로세스가 탐지됐습니다. "
            "winword.exe에서 powershell.exe 실행, explorer.exe 내 코드 인젝션이 확인됐으며 "
            "C2와 활성 연결이 유지 중입니다. Process Hollowing 기법이 사용된 것으로 판단됩니다."
        ),
        "suspicious_processes": [
            {"pid": 4212, "name": "powershell.exe", "parent_pid": 3840, "parent_name": "winword.exe",   "risk": "CRITICAL", "issue": "Word에서 PowerShell 직접 실행 (매크로 악용)"},
            {"pid": 5524, "name": "svchost.exe",    "parent_pid": 4212, "parent_name": "powershell.exe","risk": "HIGH",     "issue": "PowerShell이 svchost 생성 — Process Hollowing 의심"},
            {"pid": 6841, "name": "explorer.exe",   "parent_pid": 5524, "parent_name": "svchost.exe",   "risk": "HIGH",     "issue": "비정상 부모 프로세스, 외부 DLL 로드 탐지"},
            {"pid": 7723, "name": "cmd.exe",        "parent_pid": 6841, "parent_name": "explorer.exe",  "risk": "MEDIUM",   "issue": "업무시간 외 cmd 실행, 인수에 인코딩된 명령 포함"},
            {"pid": 2201, "name": "lsass.exe",      "parent_pid": 1,    "parent_name": "wininit.exe",    "risk": "HIGH",     "issue": "외부 프로세스의 PROCESS_VM_READ 접근 탐지 — 자격증명 덤프 시도"},
        ],
        "injected_code": [
            {"target_process": "explorer.exe (PID 6841)", "technique": "Process Hollowing",   "size_bytes": 245760, "description": "PE 헤더 감지 — 악성 PE가 explorer.exe 영역에 로드됨"},
            {"target_process": "svchost.exe (PID 5524)",  "technique": "Reflective DLL Load", "size_bytes": 98304,  "description": "디스크에 없는 DLL이 메모리에서 직접 로드됨 (fileless)"},
        ],
        "network_artifacts": [
            {"local": "192.168.1.15:54932", "remote": "185.220.101[.]47:443", "state": "ESTABLISHED", "process": "svchost.exe (PID 5524)", "suspicious": True},
            {"local": "192.168.1.15:55021", "remote": "8.8.8.8:53",           "state": "ESTABLISHED", "process": "powershell.exe (PID 4212)", "suspicious": False},
            {"local": "192.168.1.15:55198", "remote": "94.102.49[.]190:8080", "state": "CLOSE_WAIT",  "process": "explorer.exe (PID 6841)", "suspicious": True},
        ],
        "strings_of_interest": [
            "MiniDumpWriteDump — LSASS 덤프 API 사용 흔적",
            "sekurlsa::logonpasswords — Mimikatz 명령 문자열",
            "powershell -enc SQBFAFgA... — Base64 인코딩 명령",
            "IEX (New-Object Net.WebClient).DownloadString — 원격 코드 실행",
        ],
        "recommendations": [
            "svchost.exe (PID 5524) 및 explorer.exe (PID 6841) 즉시 종료 후 시스템 격리",
            "C2 IP (185.220.101.47, 94.102.49.190) 방화벽 차단",
            "LSASS 접근 시도 감지 — 전체 자격증명 교체 필요",
            "메모리 포렌식 전체 이미지 보존 (법적 증거)",
            "EDR Credential Guard 활성화로 향후 LSASS 보호",
            "PowerShell Script Block Logging 활성화",
        ],
        "_mock": True,
    },
    "threat_intel": {
        "analysis_type": "threat_intel",
        "threat_level": "HIGH",
        "confidence": 78,
        "summary": (
            "제공된 IoC 및 TTP 패턴 분석 결과, 해당 공격은 금전적 동기를 가진 eCrime 그룹 "
            "\"SCATTERED SPIDER\"(UNC3944)의 캠페인과 높은 유사성을 보입니다. "
            "소셜 엔지니어링 기반 MFA 피로 공격과 SIM 스와핑을 조합한 초기 침투 방식이 특징적입니다."
        ),
        "threat_actor": {
            "name": "SCATTERED SPIDER (UNC3944)",
            "aliases": ["Oktapus", "Scatter Swine", "0ktapus"],
            "origin": "영어권 (미국·영국 중심, 18-25세 해커 집단)",
            "motivation": "금전적 (랜섬웨어 배포, 데이터 갈취)",
            "active_since": "2022년",
            "targets": ["클라우드 서비스 기업", "통신사", "BPO 업체", "카지노·호텔 산업"],
            "sophistication": "중간-높음 (기술+소셜 엔지니어링 조합)",
        },
        "mitre_techniques": [
            {"id": "T1566.002", "name": "Spearphishing Link",              "tactic": "Initial Access",      "color": "red"},
            {"id": "T1621",     "name": "MFA Request Generation (Fatigue)", "tactic": "Credential Access",   "color": "pink"},
            {"id": "T1539",     "name": "Steal Web Session Cookie",         "tactic": "Credential Access",   "color": "pink"},
            {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",   "tactic": "Defense Evasion",     "color": "purple"},
            {"id": "T1199",     "name": "Trusted Relationship (Helpdesk)",  "tactic": "Initial Access",      "color": "red"},
            {"id": "T1486",     "name": "Data Encrypted for Impact",        "tactic": "Impact",              "color": "rose"},
            {"id": "T1657",     "name": "Financial Theft",                  "tactic": "Impact",              "color": "rose"},
            {"id": "T1584.001", "name": "Domains",                          "tactic": "Resource Development","color": "gray"},
        ],
        "similar_campaigns": [
            {"name": "MGM Resorts 침해 (2023.09)", "overlap": "95%", "description": "동일 MFA 피로 + IT 헬프데스크 사회공학 수법"},
            {"name": "Caesars Entertainment 침해 (2023.08)", "overlap": "88%", "description": "동일 그룹, 랜섬 지불 ($15M) 사례"},
            {"name": "Twilio·Cloudflare SMS 피싱 (2022.08)", "overlap": "72%", "description": "Oktapus 캠페인, 130개 조직 대상"},
        ],
        "detection_opportunities": [
            "불가능한 이동(Impossible Travel): 단시간 내 다른 국가 로그인 탐지",
            "MFA 인증 요청 폭탄: 10분 내 5회 이상 푸시 알림 트리거 경보",
            "헬프데스크 요청 패턴: 업무시간 외 MFA 리셋 요청 모니터링",
            "새 디바이스 등록: 기존 디바이스와 다른 지역·OS 탐지",
            "SIM 스왑 감지: 통신사와 협력해 번호 이동 실시간 알림",
        ],
        "recommendations": [
            "MFA 방식을 피싱 저항형으로 전환 (FIDO2/패스키)",
            "IT 헬프데스크의 신원 확인 절차 강화 (영상 통화 + 관리자 승인)",
            "클라우드 환경 Conditional Access 정책으로 비정상 로그인 차단",
            "직원 대상 MFA 피로 공격 인식 교육 즉시 실시",
            "통신사와 SIM 잠금(SIM Lock) 계약 체결",
        ],
        "_mock": True,
    },
}


def generate_mock_analysis(analysis_type: str, _input: str, _context: str) -> dict:
    return MOCK_RESULTS.get(analysis_type, MOCK_RESULTS["malware"]).copy()


MOCK_CHAT = {
    "malware": [
        "해당 악성코드는 파일리스 기법을 사용하므로 기존 AV 탐지가 어렵습니다. PowerShell Script Block Logging과 AMSI를 활성화하면 메모리 내 악성 코드를 탐지할 수 있습니다.",
        "C2 통신은 HTTPS를 사용하므로 트래픽 내용 분석은 어렵지만, JA3/JA3S 핑거프린팅으로 비정상 TLS 클라이언트를 탐지할 수 있습니다.",
        "Mutex 값으로 감염 시스템 전체 스캔이 가능합니다. EDR 콘솔에서 해당 mutex 이름으로 헌팅하세요.",
    ],
    "forensics": [
        "이벤트 로그가 삭제됐더라도 $MFT(Master File Table)와 Windows Prefetch 파일에서 실행 이력을 복원할 수 있습니다. Autopsy나 Plaso를 활용하세요.",
        "스테이징 디렉토리(%TEMP%\\staging\\)가 여전히 존재한다면 즉시 이미징하여 보존하세요. 유출된 데이터 종류를 특정하는 데 핵심입니다.",
        "robocopy 사용으로 NTFS 타임스탬프가 변조됐을 수 있습니다. $STANDARD_INFORMATION과 $FILE_NAME 시간을 비교해 안티포렌식 여부를 확인하세요.",
    ],
    "memory": [
        "Process Hollowing 탐지를 위해 메모리의 PE 헤더와 디스크의 실제 파일을 비교(Hollows Hunter 도구 활용)하면 인젝션된 코드를 추출할 수 있습니다.",
        "fileless 악성코드는 재부팅 후 사라지므로, 현재 상태의 전체 메모리 이미지를 WinPmem으로 즉시 덤프하여 보존하세요.",
        "LSASS에 접근한 프로세스 목록을 확인하려면 Volatility의 dlllist·handles 플러그인을 사용하세요. 접근 권한(PROCESS_VM_READ)이 있는 프로세스가 핵심입니다.",
    ],
    "threat_intel": [
        "SCATTERED SPIDER는 주로 영어 구사 능력을 활용해 IT 헬프데스크를 직접 전화로 속입니다. 직원들이 이 수법을 인지하도록 교육하는 것이 가장 효과적인 방어입니다.",
        "이 그룹은 피해자 조직의 내부 문서(조직도, 직원 연락처)를 LinkedIn·GitHub에서 사전 수집합니다. OSINT 노출 최소화 정책을 검토하세요.",
        "랜섬웨어 배포 전 단계에서 클라우드 스토리지(SharePoint·OneDrive·Box)의 대량 다운로드를 탐지하면 조기 차단이 가능합니다.",
    ],
}

_DEFAULT_CHAT = "해당 질문은 구체적인 환경과 샘플에 따라 다릅니다. 실제 샘플을 DFIR 전문 업체에 제출하거나 샌드박스(Any.run, Joe Sandbox)에서 동적 분석을 실행하는 것을 권장합니다."


def generate_mock_chat(analysis_type: str, message: str) -> str:
    replies = MOCK_CHAT.get(analysis_type, [_DEFAULT_CHAT])
    return replies[len(message) % len(replies)]
