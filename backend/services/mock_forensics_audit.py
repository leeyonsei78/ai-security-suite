"""포렌식 아티팩트 감사기 Mock 데이터. App 16/18/20의 mock 패턴과 동일 — 아티팩트
유형별로 실제 사고 조사에서 자주 나오는 패턴(지속성 확보, 안티포렌식, 데이터 유출
흔적)을 큐레이션했다."""

_TEMPLATES = {
    "event_log": {
        "summary": "짧은 시간에 반복된 로그온 실패 뒤 성공, 이어서 인코딩된 PowerShell 프로세스 생성과 보안 로그 삭제(1102) 이벤트까지 이어지는 전형적인 침해 후 흔적 지우기 패턴이 확인됩니다.",
        "overall_severity": "CRITICAL",
        "timeline": [
            {"timestamp": "2026-09-01 02:14:03", "event": "관리자 계정(admin)에 대해 40여 회의 로그온 실패(Event ID 4625) 발생", "significance": "브루트포스/자격증명 스터핑 공격 시도로 추정"},
            {"timestamp": "2026-09-01 02:21:47", "event": "동일 계정 로그온 성공(Event ID 4624, LogonType 3 - 네트워크)", "significance": "공격이 성공해 원격으로 계정이 탈취됨"},
            {"timestamp": "2026-09-01 02:23:10", "event": "powershell.exe -enc <Base64> 형태의 프로세스 생성(Event ID 4688)", "significance": "인코딩된 명령으로 페이로드 실행 — 탐지 우회 목적"},
            {"timestamp": "2026-09-01 02:40:55", "event": "보안 이벤트 로그 지우기(Event ID 1102)", "significance": "공격자가 직접 자신의 흔적을 삭제 — 안티포렌식 행위"},
        ],
        "findings": [
            {
                "artifact_reference": "Event ID 4625 x40+ (02:14:03~02:21:40, 계정: admin)",
                "issue_type": "evidence_of_compromise",
                "severity": "HIGH",
                "mitre_technique": "T1110 - Brute Force",
                "description": "짧은 시간에 동일 계정으로 다수의 로그온 실패가 발생했습니다 — 브루트포스 또는 자격증명 스터핑 공격의 전형적인 패턴입니다.",
                "recommendation": "해당 계정 비밀번호를 즉시 재설정하고, 계정 잠금 정책(Account Lockout Policy)과 MFA를 적용하세요.",
            },
            {
                "artifact_reference": "Event ID 4688, powershell.exe -enc <Base64>",
                "issue_type": "evidence_of_compromise",
                "severity": "CRITICAL",
                "mitre_technique": "T1059.001 - PowerShell",
                "description": "Base64로 인코딩된 명령을 실행하는 PowerShell 프로세스가 생성됐습니다 — 정상 관리 작업에서는 드문 패턴이며 탐지 우회 목적의 페이로드 실행일 가능성이 높습니다.",
                "recommendation": "해당 인코딩 문자열을 디코딩해 실제 실행 내용을 확인하고, 해당 호스트를 격리해 추가 분석(메모리 덤프 포함)을 진행하세요.",
            },
            {
                "artifact_reference": "Event ID 1102 (02:40:55)",
                "issue_type": "anti_forensic_technique",
                "severity": "CRITICAL",
                "mitre_technique": "T1070.001 - Clear Windows Event Logs",
                "description": "보안 이벤트 로그가 삭제됐습니다 — 공격자가 자신의 흔적을 지우려 시도한 명백한 안티포렌식 행위입니다. 이 이벤트 자체가 지워지지 않고 남은 것은 Windows가 로그 삭제 행위 자체를 별도로 기록하기 때문입니다.",
                "recommendation": "중앙 로그 수집(SIEM)으로 로그를 실시간 백업해 로컬 삭제로부터 보호하고, 1102 이벤트 발생 시 즉시 알림이 가도록 설정하세요.",
            },
        ],
        "iocs": ["Event ID 4688 커맨드라인의 Base64 페이로드(디코딩 필요)", "계정: admin (탈취 의심)"],
    },
    "browser_history": {
        "summary": "정상 업무 사이트 방문 기록 사이에, 처음 보는 도메인으로 대용량 POST 요청을 보낸 흔적이 섞여 있어 데이터 유출 가능성이 있습니다.",
        "overall_severity": "HIGH",
        "timeline": [
            {"timestamp": "2026-09-02 14:02:11", "event": "정상 업무용 사이트(사내 그룹웨어, 클라우드 드라이브) 다수 방문", "significance": "평상시 업무 패턴"},
            {"timestamp": "2026-09-02 14:55:30", "event": "낯선 도메인(file-share-backup-cdn.net)으로 POST 요청 기록", "significance": "직전까지 방문 이력이 전혀 없던 도메인에 대한 갑작스러운 접근"},
            {"timestamp": "2026-09-02 14:56:02", "event": "동일 도메인으로 연속 3회 추가 요청", "significance": "대용량 파일을 분할 전송했을 가능성"},
        ],
        "findings": [
            {
                "artifact_reference": "https://file-share-backup-cdn.net/upload (14:55~14:56, 총 4건)",
                "issue_type": "data_exfiltration_evidence",
                "severity": "HIGH",
                "mitre_technique": "T1567 - Exfiltration Over Web Service",
                "description": "직전 방문 이력이 전혀 없던 도메인으로 짧은 시간에 연속 업로드 요청이 발생했습니다 — 정상적인 클라우드 저장소가 아닌 임의 도메인이라는 점이 의심스럽습니다.",
                "recommendation": "해당 도메인의 평판을 IoC 분석기 등으로 확인하고, 프록시/방화벽 로그에서 실제 전송량과 목적지를 대조 확인하세요.",
            },
        ],
        "iocs": ["file-share-backup-cdn.net"],
    },
    "persistence_artifacts": {
        "summary": "Run 키에 사용자가 설치하지 않은 인코딩된 PowerShell 실행 항목이 등록되어 있어, 재부팅 시마다 자동 실행되는 지속성(persistence) 메커니즘으로 확인됩니다.",
        "overall_severity": "CRITICAL",
        "timeline": [
            {"timestamp": "확인 불가 (레지스트리 값 자체에는 생성 시각이 없음)", "event": "HKCU Run 키에 'WindowsUpdateHelper' 항목 등록", "significance": "정상 Windows 업데이트 관련 구성요소가 아닌 이름으로 위장"},
        ],
        "findings": [
            {
                "artifact_reference": "HKCU\\...\\Run\\WindowsUpdateHelper = powershell -w hidden -enc <Base64>",
                "issue_type": "persistence_mechanism",
                "severity": "CRITICAL",
                "mitre_technique": "T1547.001 - Registry Run Keys / Startup Folder",
                "description": "정상 Windows 구성요소로 위장한 이름(WindowsUpdateHelper)의 Run 키가 로그온 시마다 숨겨진 창으로 인코딩된 PowerShell을 실행하도록 등록되어 있습니다.",
                "recommendation": "해당 Run 키 값을 즉시 삭제하고, 인코딩된 명령을 디코딩해 실제 페이로드(다운로드 대상, C2 주소 등)를 분석하세요. 삭제 전 증거 보존을 위해 값을 먼저 export해두세요.",
            },
            {
                "artifact_reference": "HKCU\\...\\Run\\WindowsUpdateHelper",
                "issue_type": "evidence_of_compromise",
                "severity": "HIGH",
                "mitre_technique": "T1036 - Masquerading",
                "description": "실제 Windows 업데이트 관련 프로세스는 이런 이름으로 Run 키에 등록되지 않습니다 — 정상 구성요소로 위장한 것으로 보입니다.",
                "recommendation": "동일한 명명 패턴이 스케줄된 작업(Task Scheduler)이나 서비스에도 등록되어 있지 않은지 함께 확인하세요.",
            },
        ],
        "iocs": ["레지스트리 값 이름: WindowsUpdateHelper"],
    },
    "filesystem_timeline": {
        "summary": "사용자 AppData 폴더에 실행 파일이 생성된 직후 삭제되고, 이어서 문서 폴더의 다수 파일이 짧은 시간 안에 수정된 흔적이 있어 랜섬웨어 유사 행위 또는 파일 조작이 의심됩니다.",
        "overall_severity": "HIGH",
        "timeline": [
            {"timestamp": "2026-08-28 03:10:02", "event": "%AppData%\\Local\\Temp\\update.exe 생성", "significance": "사용자 임시 폴더에 실행 파일 드롭 — 흔한 초기 침투 지점"},
            {"timestamp": "2026-08-28 03:10:45", "event": "문서 폴더 내 212개 파일의 LastWriteTime이 43초 사이에 모두 변경됨", "significance": "자동화된 대량 파일 수정 — 랜섬웨어의 전형적 특징"},
            {"timestamp": "2026-08-28 03:11:03", "event": "update.exe 파일 삭제됨", "significance": "실행 후 자기 자신을 삭제해 흔적을 줄이는 행위"},
        ],
        "findings": [
            {
                "artifact_reference": "문서 폴더 212개 파일, LastWriteTime 03:10:45~03:11:28 (43초 이내)",
                "issue_type": "evidence_of_compromise",
                "severity": "HIGH",
                "mitre_technique": "T1486 - Data Encrypted for Impact",
                "description": "212개 파일이 43초라는 짧은 시간 안에 모두 수정됐습니다 — 사람이 직접 한 작업이 아니라 자동화된 스크립트/랜섬웨어에 의한 대량 처리로 보입니다.",
                "recommendation": "영향받은 파일 몇 개를 직접 열어 실제 암호화 여부를 확인하고, 백업에서 즉시 복구 가능한지 점검하세요. 네트워크 격리를 우선 조치하세요.",
            },
            {
                "artifact_reference": "%AppData%\\Local\\Temp\\update.exe (03:10:02 생성, 03:11:03 삭제)",
                "issue_type": "anti_forensic_technique",
                "severity": "MEDIUM",
                "mitre_technique": "T1070.004 - File Deletion",
                "description": "실행 파일이 생성 61초 만에 스스로 삭제됐습니다 — 실행 후 흔적을 남기지 않으려는 자기 삭제(self-deletion) 패턴입니다.",
                "recommendation": "디스크 미할당 영역에서 삭제된 파일 복구를 시도하거나(Autopsy 등), 안티바이러스/EDR의 격리 보관함에 동일 파일이 남아있는지 확인하세요.",
            },
        ],
        "iocs": ["파일명: update.exe"],
    },
    "process_list": {
        "summary": "정상 시스템 프로세스 이름을 그대로 사용하면서 실행 경로가 시스템 폴더가 아닌 사용자 폴더인 프로세스가 발견되어, 프로세스 마스커레이딩(위장)이 의심됩니다.",
        "overall_severity": "HIGH",
        "timeline": [],
        "findings": [
            {
                "artifact_reference": "PID 4821, ProcessName: svchost.exe, Path: C:\\Users\\Public\\svchost.exe",
                "issue_type": "evidence_of_compromise",
                "severity": "HIGH",
                "mitre_technique": "T1036.005 - Match Legitimate Name or Location",
                "description": "정상 Windows 시스템 프로세스와 동일한 이름(svchost.exe)이지만, 실제 정상 경로(C:\\Windows\\System32)가 아닌 C:\\Users\\Public에서 실행되고 있습니다 — 전형적인 프로세스 마스커레이딩입니다.",
                "recommendation": "해당 프로세스를 즉시 종료하고 실행 파일을 격리·해시 확인(VirusTotal 등)한 뒤, 동일 위치에서 실행 중인 다른 프로세스가 없는지 전체 목록을 재점검하세요.",
            },
        ],
        "iocs": ["파일 경로: C:\\Users\\Public\\svchost.exe"],
    },
    "cloud_audit_log": {
        "summary": "평소 사용하지 않던 루트 계정으로 IAM 정책이 변경되고 곧이어 새 액세스 키가 발급된 흔적이 있어, 계정 탈취 후 지속적인 접근권을 확보하려는 시도로 보입니다.",
        "overall_severity": "CRITICAL",
        "timeline": [
            {"timestamp": "2026-09-03 04:11:02 UTC", "event": "루트 계정으로 콘솔 로그인 성공(ConsoleLogin, MFA 미사용)", "significance": "평소 루트 계정을 쓰지 않는 조직에서 루트 로그인 자체가 강한 위험 신호"},
            {"timestamp": "2026-09-03 04:13:47 UTC", "event": "PutUserPolicy 호출로 IAM 사용자 'svc-backup'에 AdministratorAccess 인라인 정책 부여", "significance": "낮은 권한 서비스 계정에 전체 관리자 권한 부여 — 권한 상승"},
            {"timestamp": "2026-09-03 04:15:20 UTC", "event": "CreateAccessKey 호출로 'svc-backup' 계정의 새 액세스 키 발급", "significance": "콘솔 세션이 끊겨도 API로 계속 접근할 수 있는 지속성 확보"},
        ],
        "findings": [
            {
                "artifact_reference": "ConsoleLogin, userIdentity.type=Root, MFAUsed=No (04:11:02 UTC)",
                "issue_type": "evidence_of_compromise",
                "severity": "CRITICAL",
                "mitre_technique": "T1078.004 - Valid Accounts: Cloud Accounts",
                "description": "MFA 없이 루트 계정으로 로그인한 이벤트가 발견됐습니다 — 루트 계정 자격증명이 탈취됐을 가능성이 높습니다.",
                "recommendation": "루트 계정 비밀번호를 즉시 재설정하고 MFA를 강제 적용하세요. 이후 루트 계정은 비상시에만 사용하고 일상 관리에는 IAM 역할을 사용하세요.",
            },
            {
                "artifact_reference": "PutUserPolicy(UserName=svc-backup, PolicyDocument 포함 \"Action\":\"*\",\"Resource\":\"*\")",
                "issue_type": "persistence_mechanism",
                "severity": "CRITICAL",
                "mitre_technique": "T1098 - Account Manipulation",
                "description": "백업 용도의 서비스 계정에 모든 리소스에 대한 전체 권한(AdministratorAccess 수준)이 인라인 정책으로 부여됐습니다 — 루트 계정이 잠기더라도 이 계정으로 계속 관리자 권한을 유지할 수 있습니다.",
                "recommendation": "해당 인라인 정책을 즉시 제거하고, svc-backup 계정에 실제 필요한 최소 권한만 재부여하세요.",
            },
            {
                "artifact_reference": "CreateAccessKey(UserName=svc-backup) (04:15:20 UTC)",
                "issue_type": "persistence_mechanism",
                "severity": "HIGH",
                "mitre_technique": "T1098.001 - Additional Cloud Credentials",
                "description": "권한이 상승된 직후 새 액세스 키가 발급됐습니다 — 콘솔 세션 종료 후에도 API를 통해 접근을 유지하려는 전형적인 패턴입니다.",
                "recommendation": "새로 발급된 액세스 키를 즉시 비활성화하고, svc-backup 계정의 모든 활성 키를 재발급하세요.",
            },
        ],
        "iocs": ["계정: svc-backup", "이벤트: PutUserPolicy, CreateAccessKey"],
    },
    "network_device_log": {
        "summary": "업무 시간 외에 알 수 없는 관리자 계정으로 장비 설정이 변경되고, 직후 특정 목적지로의 아웃바운드 트래픽을 허용하는 규칙이 추가된 흔적이 있어 방화벽을 통한 데이터 유출 경로 확보가 의심됩니다.",
        "overall_severity": "HIGH",
        "timeline": [
            {"timestamp": "2026-09-04 02:31:10", "event": "%SYS-5-CONFIG_I: Configured from console by netadmin_temp on vty0", "significance": "업무 시간 외(새벽 2시) + 평소 쓰지 않던 계정명으로 설정 변경"},
            {"timestamp": "2026-09-04 02:32:05", "event": "access-list OUTBOUND 규칙에 203.0.113.77 목적지 허용 추가", "significance": "낯선 외부 IP로의 아웃바운드 트래픽을 새로 허용"},
        ],
        "findings": [
            {
                "artifact_reference": "%SYS-5-CONFIG_I: Configured from console by netadmin_temp on vty0 (02:31:10)",
                "issue_type": "evidence_of_compromise",
                "severity": "HIGH",
                "mitre_technique": "T1078 - Valid Accounts",
                "description": "업무 시간 외에 평소 쓰지 않던 계정(netadmin_temp)으로 장비 설정 변경이 발생했습니다 — 계정 탈취 또는 미승인 변경 가능성이 있습니다.",
                "recommendation": "해당 계정의 소유자와 실제 변경 승인 여부를 담당자에게 확인하고, 미승인 변경이면 계정 비밀번호를 즉시 재설정하세요.",
            },
            {
                "artifact_reference": "access-list OUTBOUND permit ip any host 203.0.113.77 (02:32:05)",
                "issue_type": "data_exfiltration_evidence",
                "severity": "HIGH",
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
                "description": "설정 변경 직후 낯선 외부 IP로의 아웃바운드 트래픽을 허용하는 규칙이 추가됐습니다 — 데이터 유출 경로를 마련한 것으로 의심됩니다.",
                "recommendation": "해당 규칙을 즉시 제거하고, 203.0.113.77과의 실제 트래픽 발생 여부를 트래픽 로그에서 확인하세요.",
            },
        ],
        "iocs": ["계정: netadmin_temp", "IP: 203.0.113.77"],
    },
}

_DEFAULT_KEY = "process_list"


def generate_mock_audit(artifact_type: str, content: str, context: str) -> dict:
    template = _TEMPLATES.get(artifact_type, _TEMPLATES[_DEFAULT_KEY])
    return {
        "summary": template["summary"],
        "overall_severity": template["overall_severity"],
        "timeline": [dict(t) for t in template["timeline"]],
        "findings": [dict(f) for f in template["findings"]],
        "iocs": list(template["iocs"]),
    }
