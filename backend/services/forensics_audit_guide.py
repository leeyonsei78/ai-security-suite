"""포렌식 아티팩트 감사기(App 25 '아티팩트 감사기' 탭)용 정적 가이드.

2026-09-06 확장: "OS/클라우드/방화벽·스위치마다 명령어가 다른데 하나로 뭉뚱그려져
있다"는 사용자 지적으로, 기존에 아티팩트 유형당 Windows PowerShell 명령 하나만
있던 것을 실제 운영 환경의 다양성(OS 3종, 클라우드 3종, 네트워크 장비 4종)에 맞춰
`variants` 배열로 확장했다. 각 variant는 App3/24에서 얻은 교훈(COMMAND_USAGE_NOTE
패턴 — "어디에 입력하는지"와 "실행 가능한 완성된 예시"를 항상 함께 제공해야 함)을
반영해 `where`(어느 터미널/콘솔에서)를 명시하고, 자리표시자(<계정명> 등)를 최소화한
바로 실행 가능한 명령을 우선한다.

`registry_export`는 Windows에만 있는 개념이라 Linux(cron/systemd)·macOS
(LaunchAgents)까지 포괄하도록 `persistence_artifacts`로 개념을 넓혔다(id 자체도
변경 — 이 앱은 아직 실사용 히스토리가 없어 하위호환 이슈 없음). 클라우드 감사
로그(`cloud_audit_log`)와 네트워크 장비 로그(`network_device_log`)는 기존에
전혀 없던 아티팩트 유형으로 신규 추가했다."""

ARTIFACT_TYPES = [
    {
        "id": "event_log",
        "label": "시스템/보안 이벤트 로그",
        "why": (
            "로그온 성공/실패, 프로세스 생성, 로그 삭제 같은 이벤트는 공격자가 언제 침투해 "
            "어떤 행동을 했는지 시간 순서로 보여주는 가장 기본적인 증거입니다. 대부분의 조사는 "
            "이 로그를 확인하는 것에서 시작합니다."
        ),
        "variants": [
            {
                "platform": "windows",
                "platform_label": "Windows",
                "where": "대상 Windows PC/서버에서 PowerShell (관리자 권한 권장)",
                "commands": [
                    "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4688,1102} -MaxEvents 100 | Format-List",
                    "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 50 | Select-Object TimeCreated,Message | Format-List",
                ],
                "note": "프로세스 생성 감사(4688)는 기본적으로 꺼져 있는 경우가 많습니다 — 켜려면: auditpol /set /subcategory:\"프로세스 생성\" /success:enable",
            },
            {
                "platform": "linux",
                "platform_label": "Linux",
                "where": "대상 Linux 서버에서 bash (일부 명령은 sudo 필요)",
                "commands": [
                    "sudo grep -E 'Failed password|Accepted password' /var/log/auth.log | tail -100   # Debian/Ubuntu",
                    "sudo grep -E 'Failed password|Accepted password' /var/log/secure | tail -100   # RHEL/CentOS",
                    "sudo journalctl -u sshd --since '-1 day' | grep -iE 'fail|accepted'",
                ],
                "note": "systemd 저널이 변조/삭제됐는지 확인하려면(서명이 설정된 경우): journalctl --verify",
            },
            {
                "platform": "macos",
                "platform_label": "macOS",
                "where": "대상 Mac에서 터미널(Terminal.app)",
                "commands": [
                    "last -100   # 로그온 이력",
                    "log show --predicate 'process == \"sshd\"' --last 1d",
                    "sudo log show --predicate 'eventMessage contains \"authentication\"' --last 1d",
                ],
                "note": "macOS는 Windows 이벤트 ID 같은 표준 코드가 없어 predicate(검색어) 방식으로 필터링합니다.",
            },
        ],
    },
    {
        "id": "browser_history",
        "label": "브라우저 히스토리 / 다운로드 기록",
        "why": (
            "사용자가 방문한 URL과 다운로드한 파일은 피싱 링크 클릭, C2 서버 접속, 데이터 유출 "
            "경로를 보여주는 직접적인 증거입니다."
        ),
        "variants": [
            {
                "platform": "windows",
                "platform_label": "Windows (Chrome)",
                "where": "대상 PC에서 PowerShell — Chrome이 실행 중이면 History 파일이 잠겨 있어 먼저 복사해야 합니다",
                "commands": [
                    "Copy-Item \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\History\" -Destination History_copy.db",
                    "python -c \"import sqlite3; [print(r) for r in sqlite3.connect('History_copy.db').execute('SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100')]\"",
                ],
                "note": "Edge는 %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History 로 경로만 바꾸면 동일합니다.",
            },
            {
                "platform": "linux",
                "platform_label": "Linux (Chrome)",
                "where": "대상 Linux 데스크톱에서 bash",
                "commands": [
                    "cp ~/.config/google-chrome/Default/History /tmp/History_copy.db",
                    "python3 -c \"import sqlite3; [print(r) for r in sqlite3.connect('/tmp/History_copy.db').execute('SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100')]\"",
                ],
                "note": "Firefox는 ~/.mozilla/firefox/<프로필>/places.sqlite 의 moz_places 테이블을 대신 조회하세요.",
            },
            {
                "platform": "macos",
                "platform_label": "macOS (Chrome)",
                "where": "대상 Mac에서 터미널",
                "commands": [
                    "cp ~/Library/Application\\ Support/Google/Chrome/Default/History /tmp/History_copy.db",
                    "python3 -c \"import sqlite3; [print(r) for r in sqlite3.connect('/tmp/History_copy.db').execute('SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100')]\"",
                ],
                "note": "Safari는 ~/Library/Safari/History.db 의 history_items/history_visits 테이블 구조가 달라 별도 쿼리가 필요합니다.",
            },
        ],
    },
    {
        "id": "persistence_artifacts",
        "label": "지속성 메커니즘 (자동 실행 등록)",
        "why": (
            "공격자는 재부팅·로그아웃 이후에도 접근을 유지하기 위해 자동 실행 항목을 등록합니다. "
            "정상 소프트웨어 목록과 대조하면 낯선 항목을 빠르게 찾을 수 있습니다."
        ),
        "variants": [
            {
                "platform": "windows",
                "platform_label": "Windows (레지스트리 Run 키 / 예약 작업)",
                "where": "대상 PC에서 PowerShell",
                "commands": [
                    "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                    "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                    "Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName,TaskPath",
                ],
                "note": "값을 그대로 파일로 남기려면: reg export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run run_keys.txt /y",
            },
            {
                "platform": "linux",
                "platform_label": "Linux (cron / systemd)",
                "where": "대상 Linux 서버에서 bash",
                "commands": [
                    "crontab -l",
                    "sudo cat /etc/crontab /etc/cron.d/* 2>/dev/null",
                    "systemctl list-unit-files --type=service --state=enabled",
                    "cat ~/.bashrc ~/.profile /etc/rc.local 2>/dev/null",
                ],
                "note": "systemd 타이머(systemctl list-timers)도 cron과 같은 목적으로 악용될 수 있어 함께 확인하는 것을 권장합니다.",
            },
            {
                "platform": "macos",
                "platform_label": "macOS (LaunchAgents/LaunchDaemons)",
                "where": "대상 Mac에서 터미널",
                "commands": [
                    "ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons",
                    "launchctl list | grep -v com.apple",
                ],
                "note": "정상 macOS 구성요소는 대부분 com.apple.* 이름을 쓰므로, 그 외 이름은 우선 확인 대상입니다.",
            },
        ],
    },
    {
        "id": "filesystem_timeline",
        "label": "파일시스템 타임라인",
        "why": (
            "파일이 언제 생성·수정·삭제됐는지의 시간 순서는 공격자가 언제 침투해 무엇을 건드렸는지 "
            "재구성하는 핵심 단서입니다."
        ),
        "variants": [
            {
                "platform": "windows",
                "platform_label": "Windows",
                "where": "대상 PC에서 PowerShell",
                "commands": [
                    "Get-ChildItem -Path C:\\Users\\<사용자명>\\AppData -Recurse -File | Select-Object FullName,CreationTime,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 200",
                ],
            },
            {
                "platform": "linux",
                "platform_label": "Linux",
                "where": "대상 Linux 서버에서 bash",
                "commands": [
                    "find /home /tmp /var/tmp -type f -newermt '2026-09-01' ! -newermt '2026-09-03' -printf '%T@ %p\\n' 2>/dev/null | sort -n",
                    "stat --format='%Y %n' /path/to/의심파일   # 개별 파일의 정확한 수정 시각(Unix epoch)",
                ],
            },
            {
                "platform": "macos",
                "platform_label": "macOS",
                "where": "대상 Mac에서 터미널",
                "commands": [
                    "find /Users /tmp -type f -newermt '2026-09-01' ! -newerct '2026-09-03' 2>/dev/null",
                    "mdls -name kMDItemFSCreationDate -name kMDItemContentModificationDate /path/to/의심파일",
                ],
            },
        ],
    },
    {
        "id": "process_list",
        "label": "실행 중인 프로세스 목록",
        "why": (
            "현재 실행 중인 프로세스 이름과 실행 경로는 정상 시스템 프로세스로 위장한 악성코드"
            "(프로세스 마스커레이딩)를 찾는 데 유용합니다."
        ),
        "variants": [
            {
                "platform": "windows",
                "platform_label": "Windows",
                "where": "대상 PC에서 PowerShell",
                "commands": [
                    "Get-Process | Select-Object Id,ProcessName,Path,StartTime | Format-Table -AutoSize",
                    "tasklist /v",
                ],
            },
            {
                "platform": "linux",
                "platform_label": "Linux",
                "where": "대상 Linux 서버에서 bash",
                "commands": [
                    "ps aux --sort=-%cpu | head -30",
                    "ls -la /proc/<PID>/exe   # 실행 파일의 실제 경로 확인(이름 위장 탐지)",
                    "sudo lsof -p <PID>   # 해당 프로세스가 연 파일/네트워크 소켓",
                ],
            },
            {
                "platform": "macos",
                "platform_label": "macOS",
                "where": "대상 Mac에서 터미널",
                "commands": [
                    "ps aux | head -30",
                    "sudo lsof -p <PID>",
                ],
            },
        ],
    },
    {
        "id": "cloud_audit_log",
        "label": "클라우드 감사 로그",
        "why": (
            "클라우드 환경에서는 서버에 직접 로그인하지 않아도 API 호출만으로 리소스를 생성·삭제·"
            "유출할 수 있어, 관리 콘솔/CLI/API 호출 이력(감사 로그)이 사실상 유일한 증거인 경우가 "
            "많습니다."
        ),
        "variants": [
            {
                "platform": "aws",
                "platform_label": "AWS (CloudTrail)",
                "where": "AWS CLI가 설치되고 인증된 터미널에서",
                "commands": [
                    "aws cloudtrail lookup-events --max-results 50",
                    "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<의심계정> --max-results 50",
                ],
                "note": "루트 계정(userIdentity.type이 \"Root\")의 API 호출이 있다면 최우선으로 확인하세요 — 평소 루트 계정을 쓰지 않는 조직에서는 그 자체가 강한 위험 신호입니다.",
            },
            {
                "platform": "azure",
                "platform_label": "Azure (Activity Log)",
                "where": "Azure CLI가 설치되고 로그인된 터미널에서",
                "commands": [
                    "az monitor activity-log list --start-time 2026-09-01T00:00:00Z --end-time 2026-09-02T00:00:00Z --output table",
                    "az monitor activity-log list --caller <의심계정> --output table",
                ],
            },
            {
                "platform": "gcp",
                "platform_label": "GCP (Cloud Audit Logs)",
                "where": "gcloud CLI가 설치되고 인증된 터미널에서",
                "commands": [
                    "gcloud logging read \"logName=projects/<프로젝트ID>/logs/cloudaudit.googleapis.com%2Factivity\" --limit 50 --format json",
                    "gcloud logging read \"protoPayload.authenticationInfo.principalEmail=<의심계정>\" --limit 50",
                ],
            },
        ],
    },
    {
        "id": "network_device_log",
        "label": "방화벽/스위치 로그",
        "why": (
            "네트워크 장비의 로그는 어떤 트래픽이 실제로 차단·허용됐는지, 그리고 장비 설정 자체가 "
            "언제 누구에 의해 바뀌었는지를 보여줘 침투 경로 확인과 내부망 이동 조사에 필요합니다."
        ),
        "variants": [
            {
                "platform": "cisco_ios",
                "platform_label": "Cisco IOS (라우터/스위치)",
                "where": "SSH/콘솔로 접속 후 enable 모드에서",
                "commands": [
                    "terminal length 0",
                    "show logging | include %SYS-5-CONFIG_I",
                    "show logging | last 200",
                ],
                "note": "\"show logging | include %SYS-5-CONFIG_I\"는 누가 언제 configure 모드에 진입해 설정을 바꿨는지 보여줍니다.",
            },
            {
                "platform": "fortinet",
                "platform_label": "Fortinet FortiGate",
                "where": "SSH 또는 웹 GUI의 CLI 콘솔에서",
                "commands": [
                    "execute log filter category traffic",
                    "execute log display",
                ],
            },
            {
                "platform": "palo_alto",
                "platform_label": "Palo Alto Networks (PAN-OS)",
                "where": "SSH 또는 CLI에서",
                "commands": [
                    "show log traffic direction equal backward",
                    "show log system direction equal backward | match commit",
                ],
                "note": "\"| match commit\"으로 설정 변경(commit) 이력만 골라볼 수 있습니다.",
            },
            {
                "platform": "juniper",
                "platform_label": "Juniper (Junos)",
                "where": "SSH 또는 콘솔, operational mode에서",
                "commands": [
                    "show log messages | last 200",
                    "show system commit",
                ],
                "note": "\"show system commit\"은 설정 변경 이력과 담당 계정을 함께 보여줍니다.",
            },
        ],
    },
]

COMMAND_USAGE_NOTE = (
    "위 명령어는 이 앱이 대신 실행하지 않습니다 — 해당 시스템/클라우드/장비에 접근 권한이 있는 "
    "곳에서 직접 실행한 뒤, 그 결과를 복사해 아래 입력창에 붙여넣거나 텍스트 파일로 저장해 "
    "업로드하세요. 파일을 업로드하면 자동으로 분석까지 실행됩니다."
)

DISCLAIMER = (
    "이 도구는 붙여넣거나 업로드한 아티팩트 텍스트만으로 AI가 사건을 재구성합니다 — 실제 시스템에 "
    "접속하거나 증거를 수집하지 않습니다(이 PC의 실제 증거를 자동으로 수집하려면 '증거 수집 도구' "
    "탭을 이용하세요). 업로드한 파일도 서버에 저장되지 않고 텍스트 내용만 분석에 사용됩니다. "
    "결과는 조사를 돕는 참고 자료이며, 법적 절차에 사용할 공식 포렌식 보고서를 대체하지 않습니다 — "
    "반드시 자격을 갖춘 포렌식 담당자의 검토를 거치세요."
)
