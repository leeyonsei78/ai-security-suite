"""위협 분석 랩(App 7)의 정적 정보 수집 가이드 — 4개 분석 유형(악성코드/포렌식/메모리/위협
인텔리전스)마다 "어디 가서 무엇을 어떻게 수집하는지" 구체적인 도구·명령어를 안내한다.
App 3의 recon_guide.py, App 16/18/20의 SOURCE_TYPES, App 24의 DATA_COLLECTION과 동일한
목적 — 이 앱은 지금까지 입력 예시(placeholder)만 있고 "실제로 어떻게 얻는지"가 없었다.
"""

COLLECTION_GUIDE = {
    "malware": {
        "usage_note": (
            "실제 악성코드 의심 파일은 절대 업무 PC에서 직접 실행하지 마세요 — 반드시 네트워크가 "
            "차단된 격리 가상머신(스냅샷으로 원상복구 가능한 환경)에서 다루거나, 아래 온라인 "
            "샌드박스처럼 파일을 직접 실행하지 않고도 분석 결과를 얻을 수 있는 방법을 우선 사용하세요."
        ),
        "items": [
            {
                "category": "샘플 확보",
                "where": "이메일 첨부파일(격리 후), 백신/EDR의 격리(quarantine) 폴더, 다운로드 폴더",
                "how": "백신이 이미 격리했다면 그 파일을 그대로 쓰는 것이 가장 안전합니다. 직접 확보한 파일은 압축(비밀번호 infected 등)해서 옮기고 확장자를 바꿔(.exe → .txt 등) 실수로 실행되지 않게 하세요.",
            },
            {
                "category": "온라인 샌드박스 (설치 불필요, 가장 안전)",
                "where": "VirusTotal(virustotal.com), any.run, Hybrid Analysis(hybrid-analysis.com)",
                "how": "파일 또는 해시를 업로드/조회하면 다른 백신 엔진의 탐지 결과와 함께 'Behavior' 탭에서 실제 실행 시 API 호출·생성 파일·네트워크 연결 로그를 볼 수 있습니다. 민감한 내부 파일이면 공개 샌드박스 대신 사설/폐쇄망 샌드박스를 사용하세요(업로드한 파일이 외부에 공유될 수 있음).",
            },
            {
                "category": "문자열/정적 분석",
                "where": "격리된 분석 VM 안에서 실행 (샘플 자체는 실행하지 않음)",
                "how": "실행 파일 자체를 실행하지 않고 내부 문자열/구조만 확인합니다.",
                "commands": [
                    "strings malware.exe  # Linux/WSL, 가독 가능한 문자열 추출",
                    "strings64.exe malware.exe  # Windows, Sysinternals Strings",
                    "file malware.exe  # 파일 형식/아키텍처 확인",
                ],
            },
            {
                "category": "로컬 행위 분석 (직접 실행이 필요할 때)",
                "where": "Windows Sandbox 또는 스냅샷 가능한 격리 VM",
                "how": "Process Monitor(Procmon)를 켜둔 상태로 샘플을 실행해 레지스트리/파일/네트워크 이벤트를 실시간 기록합니다. 분석 후 VM은 반드시 스냅샷으로 복구하세요.",
                "commands": [
                    "procmon.exe  # 실행 전 기동, Filter로 대상 프로세스만 추림",
                    "procexp.exe  # Process Explorer로 프로세스 트리·핸들 확인",
                ],
            },
        ],
    },
    "forensics": {
        "usage_note": "",
        "items": [
            {
                "category": "Windows 이벤트 로그",
                "where": "이벤트 뷰어(eventvwr.msc) 또는 PowerShell",
                "how": "특정 EventID(예: 4688 프로세스 생성, 4624/4625 로그온 성공/실패)로 필터링해 관련 이벤트만 추출하세요.",
                "commands": [
                    "Get-WinEvent -LogName Security -MaxEvents 200 | Format-List",
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Select-Object TimeCreated, Message",
                    "wevtutil epl Security C:\\temp\\security.evtx  # 로그 파일 자체를 내보내기",
                ],
            },
            {
                "category": "파일 시스템 타임라인",
                "where": "의심 폴더(다운로드, 임시 폴더, 사용자 프로필) 또는 전체 디스크",
                "how": "최근 생성/수정된 파일을 시간순으로 정렬하면 침해 시점 전후의 활동을 파악하기 좋습니다. 전문 타임라인이 필요하면 Autopsy/FTK Imager를 사용하세요.",
                "commands": [
                    "Get-ChildItem -Recurse -Path C:\\Users | Sort-Object LastWriteTime -Descending | Select-Object FullName, LastWriteTime, CreationTime -First 100",
                ],
            },
            {
                "category": "레지스트리",
                "where": "레지스트리 편집기(regedit) 또는 명령줄, 자동실행 관련 키 위주",
                "how": "Run/RunOnce 키는 악성코드의 흔한 지속성(persistence) 위치입니다.",
                "commands": [
                    "reg export HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run run_hklm.txt",
                    "reg export HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run run_hkcu.txt",
                ],
            },
            {
                "category": "실행 흔적 (Prefetch)",
                "where": "C:\\Windows\\Prefetch 폴더 (관리자 권한 필요)",
                "how": "프로그램이 실행된 이력과 마지막 실행 시각이 파일명에 남습니다. Eric Zimmerman의 PECmd 도구로 파싱하면 더 상세한 정보를 얻습니다.",
                "commands": ["dir C:\\Windows\\Prefetch", "PECmd.exe -d C:\\Windows\\Prefetch --csv C:\\temp"],
            },
            {
                "category": "브라우저 히스토리",
                "where": "각 브라우저의 프로필 폴더 (브라우저 종료 후 복사해서 열람)",
                "how": "History 파일은 SQLite DB입니다 — DB Browser for SQLite 같은 도구로 열어보세요.",
                "commands": [
                    "copy \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History\" C:\\temp\\chrome_history.db",
                ],
            },
        ],
    },
    "memory": {
        "usage_note": "",
        "items": [
            {
                "category": "메모리 덤프 획득",
                "where": "실행 중인 시스템(Windows) 또는 VM 스냅샷",
                "how": "Windows는 Magnet RAM Capture/FTK Imager/winpmem, Linux는 LiME 커널 모듈을 사용합니다. 가상머신이라면 하이퍼바이저의 스냅샷(.vmem/.mem 파일)을 그대로 활용할 수도 있습니다.",
            },
            {
                "category": "프로세스/네트워크 분석 (Volatility 3)",
                "where": "덤프 파일을 분석 PC로 옮긴 뒤 Volatility 프레임워크로 조회",
                "how": "pslist/pstree로 프로세스 트리를, netscan으로 당시 네트워크 연결을, cmdline으로 실행 인자를, malfind로 인젝션 흔적을 확인합니다.",
                "commands": [
                    "vol -f dump.mem windows.pslist",
                    "vol -f dump.mem windows.pstree",
                    "vol -f dump.mem windows.netscan",
                    "vol -f dump.mem windows.cmdline",
                    "vol -f dump.mem windows.malfind",
                    "vol -f dump.mem windows.dlllist --pid <PID>",
                ],
            },
            {
                "category": "메모리 내 문자열",
                "where": "덤프 파일 전체에 대한 문자열 스캔",
                "how": "C2 도메인, 인코딩된 명령, 자격증명 흔적을 찾을 때 유용합니다 — 결과가 방대하므로 grep으로 키워드를 좁혀서 확인하세요.",
                "commands": ["strings dump.mem | grep -i 'http\\|powershell\\|password'"],
            },
        ],
    },
    "threat_intel": {
        "usage_note": "",
        "items": [
            {
                "category": "IoC 평판 조회",
                "where": "VirusTotal(virustotal.com), AlienVault OTX(otx.alienvault.com), abuse.ch(urlhaus.abuse.ch, bazaar.abuse.ch, threatfox.abuse.ch)",
                "how": "발견한 IP/도메인/해시를 조회하면 다른 조직에서도 관측됐는지, 어떤 캠페인과 연관되는지 나옵니다. 이 프로젝트의 IoC 분석기(/ioc)로도 자동 타입 감지 후 판별해볼 수 있습니다.",
            },
            {
                "category": "TTP/공격 기법 매핑",
                "where": "MITRE ATT&CK 공식 사이트(attack.mitre.org), ATT&CK Navigator(mitre-attack.github.io/attack-navigator)",
                "how": "관찰된 행위(예: '명령줄에서 실행됨', '레지스트리 Run 키에 등록')를 ATT&CK 기법 번호(T1059, T1547 등)로 매핑해두면 리포트 작성과 다른 사고 사례 비교가 쉬워집니다.",
            },
            {
                "category": "공개 위협 리포트/CTI 피드",
                "where": "벤더 블로그(Mandiant, CrowdStrike, Microsoft Security Blog, Cisco Talos), 국내는 KISA/금융보안원 위협 인텔리전스 공지",
                "how": "유사한 공격 그룹·캠페인 이름으로 검색하면 이미 공개된 상세 분석(TTP, IoC 목록)을 참고할 수 있습니다.",
            },
            {
                "category": "자체 로그에서 IoC 추출",
                "where": "SIEM/로그 수집 시스템, 방화벽·프록시 로그",
                "how": "이상 도메인/IP로의 아웃바운드 연결, 비정상적으로 빈번한 DNS 쿼리 등을 필터링해 IoC 후보를 뽑아냅니다.",
            },
        ],
    },
}
