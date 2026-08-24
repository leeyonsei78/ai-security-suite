"""취약점 스캐너 '시나리오 따라하기' 콘텐츠.

각 시나리오는 상황 설명·학습 목표·단계별 안내·샘플 데이터·체크리스트(예상 발견 사항)·
실전 팁으로 구성된다. SCENARIO_MOCK_RESULTS는 Mock 모드에서 시나리오별로 항상 동일하고
예상 발견 사항과 정확히 맞아떨어지는 결과를 돌려주기 위한 매핑이다 (Live 모드에서는
실제 샘플 텍스트를 Claude가 그대로 분석하므로 별도 매핑이 필요 없다).
"""

CTF_PREP_GUIDE = {
    "title": "해킹 대회(CTF), 무엇부터 배워야 할까요?",
    "intro": "CTF는 보통 Web·Pwn·Reverse·Crypto·Forensics·Misc 6개 분야로 나뉩니다. 모든 분야를 한 번에 잘할 필요는 없습니다. 기초를 다진 뒤 진입장벽이 낮은 분야부터 실전 감각을 쌓아나가세요.",
    "foundations": [
        "리눅스 커맨드라인에 익숙해지기 (파일 권한, 프로세스, 파이프/리다이렉션)",
        "네트워크 기초 (TCP/IP, HTTP 요청/응답, DNS)",
        "Python으로 간단한 자동화 스크립트 작성하는 법",
        "진법·인코딩 변환에 익숙해지기 (Hex, Base64, URL 인코딩)",
    ],
    "categories": [
        {"name": "Web", "desc": "웹 애플리케이션의 로직/설정 실수를 공략합니다. 진입장벽이 낮아 시작하기 좋은 분야입니다.",
         "learn": ["SQL Injection, XSS, SSRF, 인증/세션 우회 원리", "브라우저 개발자 도구 + Burp Suite/OWASP ZAP으로 요청 가로채기·변조"]},
        {"name": "Forensics", "desc": "패킷·이미지·메모리 덤프 등 주어진 파일에서 숨겨진 정보를 찾아냅니다.",
         "learn": ["파일 시그니처/스테가노그래피 기초", "Wireshark로 패킷 분석", "Volatility로 메모리 덤프 분석"]},
        {"name": "Cryptography", "desc": "취약하게 구현되거나 잘못 사용된 암호 알고리즘을 공략합니다.",
         "learn": ["고전 암호(Caesar, XOR)와 인코딩 구분하기", "RSA 기초 개념(공개키/개인키, 소인수분해 약점)", "CyberChef로 다양한 변환 실험해보기"]},
        {"name": "Reverse Engineering", "desc": "컴파일된 바이너리를 분석해 동작 원리와 숨겨진 조건을 파악합니다.",
         "learn": ["어셈블리어 기초 (x86/x64)", "Ghidra/IDA Free로 디스어셈블·디컴파일 읽는 법"]},
        {"name": "Pwn (Binary Exploitation)", "desc": "메모리 구조를 이해하고 취약한 바이너리의 실행 흐름을 조작합니다. 난이도가 높아 기초를 먼저 다지는 것을 추천합니다.",
         "learn": ["C언어 메모리 구조(스택/힙), 버퍼 오버플로우 원리", "gdb + pwndbg/GEF로 바이너리 디버깅"]},
        {"name": "Misc / OSINT", "desc": "특정 카테고리에 얽매이지 않는 문제나 공개 정보 수집 문제입니다.",
         "learn": ["문제 설명에 숨겨진 힌트를 꼼꼼히 읽는 습관", "검색 연산자를 활용한 공개 정보 수집(OSINT) 기초"]},
    ],
    "tools": [
        {"name": "nmap", "use": "포트/서비스 스캔 (Recon)"},
        {"name": "Burp Suite / OWASP ZAP", "use": "웹 요청 가로채기·변조"},
        {"name": "Wireshark", "use": "패킷 캡처 분석"},
        {"name": "Volatility 3", "use": "메모리 포렌식"},
        {"name": "Ghidra / IDA Free", "use": "리버싱 (디스어셈블/디컴파일)"},
        {"name": "gdb + pwndbg/GEF", "use": "바이너리 디버깅, Pwn"},
        {"name": "CyberChef", "use": "인코딩/디코딩/암호 실험"},
        {"name": "John the Ripper / Hashcat", "use": "해시 크래킹"},
    ],
    "learning_order": [
        "리눅스·네트워크 기초를 다집니다.",
        "Web 카테고리부터 시작합니다 — 이 취약점 스캐너의 시나리오들과 바로 연결됩니다.",
        "Forensics·Crypto로 확장합니다 — 도구 사용법 위주라 비교적 빠르게 성장할 수 있습니다.",
        "Reverse·Pwn은 어셈블리와 메모리 구조부터 천천히 쌓아 올립니다.",
        "위 시나리오들의 체크리스트를 힌트 없이 스스로 채울 수 있는지 반복 확인합니다.",
    ],
    "practice_platforms": [
        "picoCTF — 입문자를 위한 상시 운영 연습 대회",
        "OverTheWire — Bandit 등 단계별 워게임 시리즈",
        "TryHackMe / HackTheBox — 분야별 실습 랩",
        "CTFtime.org — 전 세계 CTF 대회 일정 모음",
    ],
}

SCENARIOS = [
    {
        "id": "beg-portscan-1",
        "audience": "beginner",
        "input_type": "portscan",
        "title": "포트 스캔 결과 읽고 위험한 서비스 찾아내기",
        "level": "입문",
        "situation": "인프라팀에서 신규 배포한 내부 서버에 대해 배포 전 보안 점검을 요청받았습니다. nmap으로 스캔한 결과가 아래와 같습니다.",
        "objective": "열려 있는 포트와 서비스 버전만 보고 '왜 위험할 수 있는지' 스스로 추론하는 습관을 기릅니다.",
        "steps": [
            "샘플을 먼저 눈으로 읽고, 열려 있는 포트·서비스·버전을 표로 정리해 보세요.",
            "각 서비스별로 위험 요소를 스스로 예상해 보세요. (힌트: 오래된 버전, 평문 프로토콜, 인증 없는 서비스)",
            "이 시나리오를 선택하면 아래 입력창에 샘플이 자동으로 채워집니다. 필요하면 직접 수정해도 됩니다.",
            "[AI로 취약점 스캔] 버튼을 클릭해 실제 분석 결과를 확인합니다.",
            "결과와 자신이 예상한 목록을 비교하고, 아래 체크리스트에서 실제로 발견됐는지 확인하세요.",
        ],
        "sample": """Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-24 10:00 KST
Nmap scan report for internal-app-01 (192.168.10.15)
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu
23/tcp   open  telnet
80/tcp   open  http        Apache httpd 2.4.7
443/tcp  open  ssl/http    Apache httpd 2.4.7
3306/tcp open  mysql       MySQL 5.5.28
6379/tcp open  redis       Redis key-value store 3.2.0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .""",
        "expected_findings": [
            {"keyword": "vsftpd", "label": "vsftpd 2.3.4 백도어 취약점", "explain": "CVE-2011-2523 — 특정 사용자명 패턴으로 로그인 시 6200번 포트에 백도어 쉘이 열립니다."},
            {"keyword": "Redis", "label": "Redis 인증 미설정", "explain": "6379 포트가 인증 없이 노출되어 데이터 조회·삭제, 경우에 따라 원격 코드 실행까지 가능합니다."},
            {"keyword": "Telnet", "label": "Telnet 평문 프로토콜 사용", "explain": "모든 통신이 암호화 없이 전송되어 자격증명이 노출될 수 있습니다."},
            {"keyword": "MySQL", "label": "MySQL 외부 접속 허용", "explain": "데이터베이스 포트가 외부에서 직접 접근 가능한 상태입니다."},
            {"keyword": "OpenSSH", "label": "OpenSSH 구버전", "explain": "6.6.1은 오래된 버전으로 이후 패치된 취약점에 노출될 수 있습니다."},
        ],
        "tips": [
            "서비스 버전만으로 CVE를 검색하는 습관을 들이세요. (예: \"vsftpd 2.3.4 CVE\")",
            "nmap -sV 외에 -sC(기본 스크립트 스캔)를 함께 쓰면 더 많은 정보를 얻을 수 있습니다.",
        ],
    },
    {
        "id": "beg-config-1",
        "audience": "beginner",
        "input_type": "config",
        "title": "웹 서버 설정 파일 점검하기",
        "level": "입문",
        "situation": "새로 구축한 쇼핑몰 웹 서버의 nginx 설정 파일을 배포 전에 점검해야 합니다.",
        "objective": "설정 파일 한 줄 한 줄이 실제로 어떤 보안 결과로 이어지는지 연결지어 생각하는 연습을 합니다.",
        "steps": [
            "설정 파일에서 listen, location, autoindex, server_tokens 같은 지시어를 하나씩 확인하세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다.",
            "[AI로 취약점 스캔]을 실행해 결과를 확인합니다.",
            "체크리스트로 놓친 설정 실수가 없는지 확인하세요.",
        ],
        "sample": """# /etc/nginx/nginx.conf
server {
    listen 80;
    server_name shop.example.com;
    server_tokens on;

    location / {
        root /var/www/shop;
        autoindex on;
    }

    location /admin {
        root /var/www/shop;
    }

    location /.git {
        root /var/www/shop;
    }
}""",
        "expected_findings": [
            {"keyword": ".git", "label": ".git 디렉토리 웹 노출", "explain": "차단 설정이 없어 소스코드와 커밋 이력이 그대로 유출될 수 있습니다."},
            {"keyword": "admin", "label": "관리자 페이지 접근 제어 없음", "explain": "/admin 경로에 인증 설정이 없어 누구나 접근할 수 있습니다."},
            {"keyword": "autoindex", "label": "디렉토리 목록 노출", "explain": "autoindex on 설정으로 디렉토리 내용이 그대로 보여집니다."},
            {"keyword": "server_tokens", "label": "서버 버전 정보 노출", "explain": "응답 헤더에 nginx 버전이 노출되어 공격 대상 파악에 활용될 수 있습니다."},
            {"keyword": "HTTPS", "label": "HTTPS 미적용", "explain": "listen 80만 존재하고 443/SSL 설정이 없습니다."},
        ],
        "tips": [
            "민감 경로(.env, .git, /admin 등) 노출 여부는 웹 취약점 스캐너(App 6)로 실제 URL을 점검해볼 수도 있습니다.",
        ],
    },
    {
        "id": "beg-code-1",
        "audience": "beginner",
        "input_type": "code",
        "title": "소스코드에서 취약점 찾기",
        "level": "입문",
        "situation": "동료가 작성한 로그인/프로필 기능 코드에 대해 코드 리뷰를 요청받았습니다.",
        "objective": "SQL Injection, XSS, 하드코딩된 비밀정보처럼 코드에서 자주 나오는 취약 패턴을 눈으로 식별하는 연습을 합니다.",
        "steps": [
            "함수를 하나씩 읽으며 '사용자 입력이 어디로 흘러가는지' 따라가 보세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다.",
            "[AI로 취약점 스캔]을 실행하고 결과를 확인합니다.",
            "체크리스트와 비교하며 놓친 부분이 있는지 확인하세요.",
        ],
        "sample": """import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PASSWORD = "P@ssw0rd123"  # TODO: move to env

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = conn.execute(query).fetchone()
    return "OK" if user else "FAIL"

@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Welcome, {name}!</h1>")

def hash_password(pw):
    import hashlib
    return hashlib.md5(pw.encode()).hexdigest()""",
        "expected_findings": [
            {"keyword": "SQL Injection", "label": "SQL Injection (login)", "explain": "f-string으로 조립된 쿼리라 username/password에 SQL 구문을 주입할 수 있습니다."},
            {"keyword": "하드코딩", "label": "하드코딩된 DB 비밀번호", "explain": "DB_PASSWORD가 소스코드에 평문으로 남아 있습니다."},
            {"keyword": "XSS", "label": "XSS (profile)", "explain": "render_template_string에 사용자 입력을 그대로 넣어 스크립트 실행이 가능합니다."},
            {"keyword": "MD5", "label": "취약한 해시 알고리즘 MD5", "explain": "비밀번호 해싱에 MD5를 사용해 레인보우 테이블 공격에 취약합니다."},
        ],
        "tips": [],
    },
    {
        "id": "ctf-portscan-1",
        "audience": "ctf",
        "input_type": "portscan",
        "title": "실전 시나리오: 침투 우선순위 정하기",
        "level": "대회 대비",
        "situation": "CTF 대회의 Recon(정찰) 단계라고 가정합니다. 시간 제한이 있는 대회에서는 모든 서비스를 다 살펴볼 여유가 없습니다. 아래 nmap 결과에서 flag를 가장 빨리 찾을 수 있는 서비스부터 순서를 매겨 보세요.",
        "objective": "버전 정보만 보고 '공개된 exploit이 있는가'를 기준으로 공략 우선순위를 판단하는 실전 감각을 기릅니다.",
        "steps": [
            "서비스 버전을 하나씩 보며 공개 exploit이 있을 법한 것부터 순서를 매겨 보세요. (searchsploit/CVE 검색 습관)",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다.",
            "[AI로 취약점 스캔]을 실행합니다.",
            "AI가 제시한 심각도 순서와 본인이 세운 우선순위를 비교해 보세요.",
            "체크리스트로 놓친 서비스가 없는지 확인하세요.",
        ],
        "sample": """Nmap scan report for ctf-target (10.10.10.42)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu
80/tcp    open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp   open  netbios-ssn Samba smbd 4.3.11-Ubuntu
8080/tcp  open  http-proxy  Jenkins 1.6
9200/tcp  open  http        Elasticsearch 1.4.2""",
        "expected_findings": [
            {"keyword": "vsftpd", "label": "vsftpd 2.3.4 백도어 (최우선 공략 대상)", "explain": "CVE-2011-2523. 공개 exploit이 있고 즉시 쉘을 획득할 수 있어 CTF 단골 소재입니다."},
            {"keyword": "Samba", "label": "Samba SambaCry RCE", "explain": "CVE-2017-7494. 공유 폴더에 악성 라이브러리를 업로드해 원격 코드 실행이 가능합니다."},
            {"keyword": "Jenkins", "label": "Jenkins 스크립트 콘솔 RCE", "explain": "인증되지 않은 스크립트 콘솔(/script)로 Groovy 코드를 실행해 셸을 얻을 수 있는 구버전입니다."},
            {"keyword": "Elasticsearch", "label": "Elasticsearch 인증 없는 API + RCE 이력", "explain": "CVE-2015-1427 등. 인증 없이 API가 노출되어 있고 원격 코드 실행 취약점 이력이 있습니다."},
        ],
        "tips": [
            "대회에서는 '가장 오래된 버전 + 공개 exploit이 있는 서비스'부터 공략하는 것이 시간 효율적입니다.",
            "vsftpd 2.3.4는 CTF에 자주 등장하는 단골 백도어이니 버전만 보고 바로 알아챌 수 있도록 외워두세요.",
            "searchsploit이나 msfconsole의 exploit 모듈명을 함께 검색해보는 습관을 들이세요.",
        ],
    },
    {
        "id": "ctf-code-1",
        "audience": "ctf",
        "input_type": "code",
        "title": "코드 리뷰로 인증 우회 지점 찾기",
        "level": "대회 대비",
        "situation": "웹 해킹 문제에서는 소스코드가 그대로 주어지는 경우가 많습니다. 아래 로그인 로직에서 인증을 우회할 수 있는 지점을 모두 찾아보세요.",
        "objective": "'서버가 클라이언트 값을 그대로 믿는 지점'을 찾는 관점으로 코드를 읽는 훈련을 합니다.",
        "steps": [
            "함수를 하나씩 보며 '공격자가 이 값을 조작하면 무엇이 뚫리는가?'를 자문하세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다.",
            "[AI로 취약점 스캔]을 실행합니다.",
            "체크리스트와 비교하며 놓친 인증 우회 지점이 있는지 확인하세요.",
        ],
        "sample": """import hashlib

SECRET_KEY = "s3cr3t_ctf_key"  # hardcoded

def check_login(username, password):
    if username == "admin" and password == "backdoor2024":
        return True  # debug backdoor - remove before release
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    result = db.execute(query)
    return len(result) > 0

def generate_token(username):
    # predictable token: md5(username + fixed secret)
    return hashlib.md5((username + SECRET_KEY).encode()).hexdigest()

def is_admin(request):
    role = request.cookies.get("role", "user")
    return role == "admin"  # trusts client-supplied cookie""",
        "expected_findings": [
            {"keyword": "백도어", "label": "하드코딩된 백도어 계정", "explain": "admin/backdoor2024 계정으로 인증을 완전히 우회할 수 있습니다."},
            {"keyword": "SQL Injection", "label": "SQL Injection", "explain": "문자열 포매팅 쿼리라 ' OR '1'='1 같은 페이로드로 인증 우회가 가능합니다."},
            {"keyword": "토큰", "label": "예측 가능한 토큰 생성", "explain": "고정된 SECRET_KEY와 사용자명만으로 MD5 토큰을 만들어 오프라인에서 타 사용자 토큰을 위조할 수 있습니다."},
            {"keyword": "쿠키", "label": "클라이언트 쿠키를 신뢰하는 권한 검증", "explain": "role 쿠키 값을 검증 없이 신뢰해 쿠키를 'admin'으로 조작하면 관리자 권한을 얻습니다."},
        ],
        "tips": [
            "클라이언트가 보낸 쿠키/세션/헤더를 서버가 그대로 믿는 패턴은 웹 CTF의 단골 소재입니다.",
            "TODO, debug, backdoor 같은 주석 옆에 위험한 코드가 남아있는 경우가 많으니 주석도 꼭 확인하세요.",
        ],
    },
    {
        "id": "ctf-config-1",
        "audience": "ctf",
        "input_type": "config",
        "title": "설정 파일에서 숨겨진 정보 유출 지점 찾기",
        "level": "대회 대비",
        "situation": "웹 서버 설정 실수로 민감한 파일이 그대로 노출되는 문제는 CTF Web 카테고리에서 자주 출제됩니다. 아래 nginx 설정에서 정보 유출로 이어지는 지점을 찾아보세요.",
        "objective": "설정 파일 속 정규식/location 블록이 실제로 어떤 파일 접근을 허용하는지 시뮬레이션하며 읽는 훈련을 합니다.",
        "steps": [
            "location 블록을 하나씩 보며 어떤 경로/확장자가 실제로 서빙되는지 따라가 보세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다.",
            "[AI로 취약점 스캔]을 실행합니다.",
            "체크리스트로 놓친 유출 지점이 없는지 확인하세요.",
        ],
        "sample": """# /etc/nginx/sites-enabled/app.conf
server {
    listen 80;
    server_name app.ctf-example.com;
    root /var/www/app;

    location ~ /\\.git {
        allow all;
    }

    location /backup/ {
        autoindex on;
    }

    location ~* \\.(env|bak|old)$ {
        allow all;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header X-Internal-Auth "true";
    }
}""",
        "expected_findings": [
            {"keyword": ".git", "label": ".git 노출", "explain": "git-dumper 등으로 소스 전체와 커밋 이력을 복구할 수 있습니다."},
            {"keyword": "backup", "label": "백업 디렉토리 인덱싱 노출", "explain": "/backup/ 경로의 autoindex가 켜져 있어 백업 파일 목록이 그대로 보입니다."},
            {"keyword": "env", "label": "민감 확장자 파일 접근 허용", "explain": ".env/.bak/.old 확장자 파일이 그대로 서빙되어 환경변수·시크릿이 유출될 수 있습니다."},
            {"keyword": "X-Internal-Auth", "label": "내부 인증 헤더 프록시 신뢰 문제", "explain": "외부 요청의 동일 헤더를 사전에 제거하지 않으면 클라이언트가 헤더를 위조해 내부 인증을 우회할 수 있습니다."},
        ],
        "tips": [
            "CTF에서 .git이 노출되면 git-dumper나 wget -r로 소스 전체를 복구할 수 있습니다.",
            "프록시가 내부 인증 헤더를 주입하는 구조라면, 외부에서 같은 헤더를 보냈을 때 덮어써지는지 반드시 검증해야 합니다.",
        ],
    },
    {
        "id": "ctf-memory-1",
        "audience": "ctf",
        "input_type": "memory",
        "title": "메모리 덤프 분석: 위장된 프로세스와 은닉된 flag 찾기",
        "level": "대회 대비",
        "situation": "CTF Forensics 문제에서는 메모리 덤프(.dmp/.vmem)가 주어지는 경우가 많습니다. Volatility 3로 pstree·netscan·cmdline 플러그인을 돌리고, strings로 문자열을 추출한 결과가 아래와 같습니다.",
        "objective": "정상 프로세스 이름을 흉내낸 마스커레이딩, 의심스러운 외부 연결, 인코딩된 실행 인자를 스스로 식별하는 메모리 포렌식 기초를 익힙니다.",
        "steps": [
            "pstree 결과에서 부모-자식 프로세스 관계를 확인하고, 이름이 정상 프로세스와 비슷하지만 미묘하게 다른(오타) 프로세스가 없는지 찾아보세요.",
            "netscan 결과에서 의심스러운 프로세스가 외부로 연결한 내역이 있는지 확인하세요.",
            "cmdline 결과에서 인코딩되거나 숨겨진(hidden) 실행 옵션이 있는지 확인하세요.",
            "strings 결과에서 Base64로 보이는 문자열을 찾아 직접 디코딩해보세요. (예: echo '문자열' | base64 -d, 또는 CyberChef)",
            "이 시나리오를 선택하면 위 결과가 입력창에 자동으로 채워집니다. [AI로 취약점 스캔]을 눌러 결과를 확인하고 체크리스트와 비교하세요.",
        ],
        "sample": """Volatility 3 Framework 2.5.2

$ vol -f dump.mem windows.pstree
PID    PPID   ImageFileName      CreateTime
4      0      System             2026-08-20 09:00:00
612    4      smss.exe           2026-08-20 09:00:01
988    812    services.exe       2026-08-20 09:00:05
1024   988    svchost.exe        2026-08-20 09:00:06
2200   900    explorer.exe       2026-08-20 09:05:10
4444   988    svch0st.exe        2026-08-20 09:14:22
5210   2200   powershell.exe     2026-08-20 09:14:30
5560   5210   rundll32.exe       2026-08-20 09:15:02

$ vol -f dump.mem windows.netscan
Proto  LocalAddr        ForeignAddr         State        PID   Owner
TCP    10.0.0.5:49732   185.220.101.7:4444  ESTABLISHED  4444  svch0st.exe

$ vol -f dump.mem windows.cmdline
PID 5210: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...

$ strings dump.mem | grep -i flag
b64_flag=Q1RGe21lbV9mb3JlbnNpY3NfMTAxfQ==""",
        "expected_findings": [
            {"keyword": "svch0st", "label": "프로세스 마스커레이딩 (svch0st.exe)", "explain": "정상 프로세스 svchost.exe를 흉내낸 오타 이름으로, 악성코드가 정상 프로세스인 척 위장하고 있을 가능성이 높습니다."},
            {"keyword": "185.220.101", "label": "외부 C2 의심 연결", "explain": "위장된 프로세스가 외부 IP로 ESTABLISHED 상태의 연결을 맺고 있어 명령 제어(C2) 통신일 가능성이 있습니다."},
            {"keyword": "-enc", "label": "인코딩된 PowerShell 실행", "explain": "-enc(EncodedCommand)와 -w hidden 옵션은 파일리스 악성코드가 흔히 쓰는 은닉 실행 기법입니다."},
            {"keyword": "Base64", "label": "메모리 내 Base64 문자열 발견", "explain": "strings로 추출한 문자열 중 Base64로 보이는 값은 디코딩해 flag나 추가 정보를 확인해야 합니다."},
        ],
        "tips": [
            "프로세스 마스커레이딩은 svchost.exe, lsass.exe, explorer.exe 같은 정상 이름을 한 글자만 바꿔 위장하는 경우가 많습니다 (예: scvhost.exe, svch0st.exe).",
            "PowerShell -enc 값은 Base64로 인코딩된 UTF-16LE 문자열이라 일반 base64 -d만으로는 깨져 보일 수 있습니다. CyberChef의 'From Base64' + 'Decode text (UTF-16LE)' 조합을 사용하세요.",
            "자주 쓰는 Volatility 플러그인을 외워두세요: pslist/pstree(프로세스), netscan(네트워크), cmdline(실행 인자), malfind(인젝션 흔적), filescan(파일 핸들).",
            "flag가 메모리에 평문 또는 Base64로 남아있는 경우가 많으니 strings | grep -i flag는 항상 먼저 시도해보는 습관을 들이세요.",
        ],
    },
    {
        "id": "privacy-breach-1",
        "audience": "privacy",
        "input_type": "config",
        "title": "개인정보 유출 사고 대응: 처음부터 종료까지",
        "level": "실무 대응",
        "situation": "취약점 스캐너로 쇼핑몰 서버의 설정을 점검하던 중, 백업 디렉토리 하나가 인증 없이 그대로 노출된 것을 발견했습니다. 접속해보니 고객 정보가 담긴 CSV 파일이 누구나 다운로드할 수 있는 상태였습니다. 지금부터 이 발견을 개인정보 유출 사고 대응 절차로 처음부터 끝까지 이어가 봅니다.",
        "objective": "기술적 취약점 발견이 어떻게 개인정보 유출 사고 대응 프로세스로 이어지는지, 탐지부터 사후 보고까지 전체 흐름을 익힙니다.",
        "steps": [
            "아래 샘플(노출된 설정 + 실제 다운로드된 파일 일부)을 읽고 어떤 개인정보 항목이 유출됐는지 직접 정리해 보세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다. [AI로 취약점 스캔]을 눌러 기술적 분석 결과와 '개인정보 유출 위험' 표시를 확인하세요.",
            "결과 화면에서 확인 포인트(기술적 발견)와 아래 '사고 대응 절차' 체크리스트(처리 절차)를 함께 비교해 보세요.",
            "사고 대응 절차 체크리스트를 탐지 → 즉시조치 → 법적 신고 → 정보주체 통지 → 원인조사 → 재발방지 순서대로 하나씩 눌러 완료 표시를 해보세요.",
        ],
        "sample": """# 1) 문제가 된 nginx 설정
location /backup/ {
    autoindex on;
}

# 2) /backup/ 접속 결과 — 인증 없이 200 OK
GET /backup/customers_2026Q2.csv HTTP/1.1
Host: shop.example.com

# 3) customers_2026Q2.csv 내용 일부 (총 128,430건 추정)
id,name,rrn,phone,email,card_no
1,홍길동,990101-1023456,010-1234-5678,hong@example.com,4111-1111-1111-1111
2,김철수,970615-2087654,010-9876-5432,kim@example.com,5500-0000-0000-0004""",
        "expected_findings": [
            {"keyword": "autoindex", "label": "백업 디렉토리 인증 없이 노출", "explain": "/backup/ 경로에 접근 제어가 없어 디렉토리 목록과 파일이 그대로 노출됩니다."},
            {"keyword": "rrn", "label": "주민등록번호 평문 노출", "explain": "CSV에 주민등록번호가 암호화·마스킹 없이 평문으로 저장되어 있습니다."},
            {"keyword": "card_no", "label": "카드번호 평문 노출", "explain": "카드번호가 평문으로 저장되어 있어 결제 정보 유출로 이어질 수 있습니다."},
            {"keyword": "128,430", "label": "대규모 유출 (건수 확인)", "explain": "약 128,430건 규모로 추정되어 대규모 개인정보 유출에 해당할 수 있습니다."},
        ],
        "tips": [
            "이 시나리오는 학습용 요약입니다. 실제 사고 대응은 반드시 법무팀/개인정보보호책임자(CPO)·전문 포렌식 인력과 함께 진행하세요.",
            "증거를 보전할 때는 원본 파일이나 로그를 직접 수정하지 말고 반드시 사본으로 작업하세요.",
            "유출 사실을 숨기거나 늦게 알리는 것 자체가 법적 리스크를 키웁니다 — 확인되는 즉시 내부 보고 체계를 가동하세요.",
        ],
        "response_plan": [
            {
                "phase": "1. 탐지 및 초기 확인",
                "items": [
                    "유출 정황을 캡처해 증거를 보전한다 (원본 수정 없이 스크린샷/사본으로 확인)",
                    "유출된 개인정보 항목(이름, 주민등록번호, 연락처, 카드번호 등)을 정리한다",
                    "영향을 받은 정보주체(고객) 규모를 추정한다",
                    "유출 경로(어떤 설정 실수·취약점)를 특정한다",
                ],
            },
            {
                "phase": "2. 즉시 조치 / 봉쇄",
                "items": [
                    "노출된 경로를 즉시 차단한다 (autoindex off, 접근 제어 추가, 파일 삭제/비공개 위치로 이동)",
                    "함께 노출된 자격증명(DB 비밀번호, API 키 등)이 있다면 즉시 회전(rotate)한다",
                    "필요 시 관련 서비스·API의 임시 중단 여부를 판단한다",
                    "내부 비상 연락망(보안팀·개인정보보호책임자·경영진)에 즉시 보고한다",
                ],
            },
            {
                "phase": "3. 법적 신고 의무 확인",
                "items": [
                    "유출 규모와 정보 유형을 기준으로 개인정보보호법상 신고 대상 여부를 법무팀/CPO와 함께 확인한다",
                    "신고 대상이면 개인정보보호위원회 또는 한국인터넷진흥원(KISA)에 지체 없이 신고한다",
                    "신고 내용(유출 항목, 인지 시점, 경위, 피해 최소화 조치)을 문서로 정리한다",
                ],
            },
            {
                "phase": "4. 정보주체 통지",
                "items": [
                    "유출된 개인정보 항목과 발생 시점·경위를 정보주체에게 통지한다",
                    "정보주체가 취할 수 있는 피해 최소화 조치(비밀번호 변경, 카드 재발급 등)를 안내한다",
                    "상담·문의를 받을 수 있는 창구와 연락처를 안내한다",
                    "통지 방법(이메일/서면/홈페이지 공지 등)과 발송 기록을 남긴다",
                ],
            },
            {
                "phase": "5. 원인 조사 및 증거 보전",
                "items": [
                    "언제부터 노출되어 있었는지 로그 타임스탬프로 확인한다",
                    "실제 외부 접근·다운로드 이력이 있는지 접근 로그를 분석한다",
                    "원본 증거는 변경하지 않고 사본으로 포렌식 분석을 진행한다",
                ],
            },
            {
                "phase": "6. 재발 방지 및 사후 보고",
                "items": [
                    "동일한 설정 실수가 다른 시스템에도 있는지 전수 점검한다",
                    "정기적인 외부 노출 점검(이 앱의 취약점/웹 스캐너 등)을 운영 프로세스에 반영한다",
                    "사고 경위·조치 내역·재발 방지 대책을 담은 사후 보고서를 작성해 공유한다",
                ],
            },
        ],
    },
    {
        "id": "pentest-fullchain-1",
        "audience": "pentest",
        "input_type": "portscan",
        "title": "모의 해킹(침투테스트) 처음부터 끝까지 따라하기",
        "level": "실무 대응",
        "situation": "회사로부터 스테이징 웹 서버(staging.acme-corp.example)에 대한 모의 해킹을 정식으로 의뢰받았습니다. 계약과 승인이 끝난 뒤, 정찰부터 권한 상승, 보고서 작성까지 실제 침투테스트 절차를 처음부터 끝까지 따라가 봅니다.",
        "objective": "정찰(Recon) → 스캐닝/열거 → 취약점 검증 → 권한 상승 → 흔적 정리/보고까지 이어지는 모의 해킹의 전체 방법론과, 각 단계에서 지켜야 할 윤리적·법적 원칙을 익힙니다.",
        "steps": [
            "샘플의 각 단계(정찰/열거/PoC 검증/권한 상승 로그)를 순서대로 읽고, 어떤 취약점이 어떻게 연결되어 있는지 공격 경로를 스스로 그려보세요.",
            "이 시나리오를 선택하면 샘플이 입력창에 자동으로 채워집니다. [AI로 취약점 스캔]을 눌러 발견된 취약점과 CVSS 점수, 컴플라이언스 매핑을 확인하세요.",
            "확인 포인트 체크리스트로 기술적 발견을 검증하고, 아래 '모의 해킹 절차' 체크리스트를 사전 협의부터 보고서 작성까지 순서대로 하나씩 완료해보세요.",
            "실제 업무에서는 1단계(사전 협의/승인)가 없으면 이후 어떤 단계도 진행해서는 안 된다는 점을 반드시 기억하세요.",
        ],
        "sample": """[사전 협의 완료] 서면 RoE(Rules of Engagement) 승인됨 — 대상: 203.0.113.10 (staging.acme-corp.example), 기간: 2026-08-24 ~ 2026-08-26, 금지행위: DoS 유발 공격/운영 데이터 변경

=== 1단계: 정찰 (nmap -sV) ===
Nmap scan report for staging.acme-corp.example (203.0.113.10)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu
80/tcp   open  http       Apache httpd 2.4.18
443/tcp  open  ssl/http   Apache httpd 2.4.18
3000/tcp open  http       Node.js Express (internal admin panel)

=== 2단계: 웹 애플리케이션 열거 ===
GET  /admin/login  -> 200 OK (인증 없이 접근 가능한 내부 관리자 로그인 페이지)
POST /api/login    -> username 파라미터에서 SQL Injection 확인: ' OR '1'='1

=== 3단계: 취약점 검증 (PoC, 운영 데이터 변경 없음) ===
' OR '1'='1'-- 페이로드로 관리자 세션 획득 확인 (읽기 전용으로만 확인 후 즉시 로그아웃)

=== 4단계: 권한 상승 시도 ===
획득한 관리자 세션으로 /api/users/export 접근 가능 확인 -> 전체 사용자 목록 다운로드가 가능한 상태 (실제 다운로드는 진행하지 않고 응답 헤더/건수만 확인)""",
        "expected_findings": [
            {"keyword": "SQL Injection", "label": "로그인 API SQL Injection", "explain": "' OR '1'='1 페이로드로 인증을 우회해 관리자 세션을 획득할 수 있습니다."},
            {"keyword": "admin", "label": "내부 관리자 패널 외부 노출", "explain": "내부 전용이어야 할 관리자 로그인 페이지가 외부에서 인증 없이 접근 가능합니다."},
            {"keyword": "users/export", "label": "권한 상승 후 전체 사용자 데이터 노출", "explain": "획득한 관리자 권한으로 전체 사용자 목록을 다운로드할 수 있는 기능에 접근 가능합니다."},
            {"keyword": "OpenSSH", "label": "OpenSSH 구버전", "explain": "7.2p2는 오래된 버전으로 이후 패치된 취약점에 노출될 수 있습니다."},
        ],
        "tips": [
            "서면 승인(RoE) 없이는 어떤 시스템도 테스트하지 마세요 — 범위를 벗어난 테스트는 그 자체로 불법 해킹이 됩니다.",
            "PoC(개념 증명)는 '취약점이 존재한다는 것을 확인'하는 최소한의 행위로 그치고, 실제 데이터 열람·다운로드·변경은 고객과 합의된 범위 내에서만 하세요.",
            "모의 해킹 결과 보고서는 경영진용 요약(Executive Summary)과 기술 상세(재현 절차·권장 조치)를 함께 담아야 실제로 조치로 이어집니다.",
        ],
        "response_plan": [
            {
                "phase": "1. 사전 협의 및 범위 설정 (Pre-engagement)",
                "items": [
                    "테스트 대상 범위(IP·도메인·애플리케이션)를 명확히 합의한다",
                    "서면 승인(RoE)을 받는다 — 승인 없는 시스템은 절대 테스트하지 않는다",
                    "테스트 가능 시간대와 비상 연락 체계를 확인한다",
                    "금지 행위(DoS 유발 공격, 운영 데이터 변경 등)를 사전에 합의한다",
                ],
            },
            {
                "phase": "2. 정찰 (Reconnaissance)",
                "items": [
                    "공개 정보(OSINT)로 대상의 도메인·서브도메인·기술 스택을 조사한다",
                    "능동적 정찰(nmap 등)로 열린 포트와 서비스 버전을 확인한다",
                    "발견한 정보를 체계적으로 기록한다",
                ],
            },
            {
                "phase": "3. 스캐닝 및 열거 (Scanning & Enumeration)",
                "items": [
                    "서비스 버전별로 알려진 취약점(CVE)이 있는지 확인한다",
                    "웹 애플리케이션이라면 디렉토리·파라미터·입력 지점을 열거한다",
                    "이 취약점 스캐너로 결과를 분석해 우선순위를 정한다",
                ],
            },
            {
                "phase": "4. 취약점 분석 (Vulnerability Analysis)",
                "items": [
                    "발견된 취약점의 심각도(CVSS)와 공개 exploit 존재 여부를 평가한다",
                    "오탐(false positive)인지 실제 악용 가능한지 검증한다",
                ],
            },
            {
                "phase": "5. 침투/공격 실행 (Exploitation)",
                "items": [
                    "합의된 범위 내에서만, 최소한의 영향으로 취약점을 검증(PoC)한다",
                    "실제 운영 데이터를 변경·삭제하지 않도록 주의한다",
                    "성공한 공격 단계와 사용한 페이로드를 상세히 기록한다",
                ],
            },
            {
                "phase": "6. 권한 상승 및 후속 공격 (Post-Exploitation)",
                "items": [
                    "획득한 접근 권한으로 추가로 접근 가능한 자원이 있는지 확인한다",
                    "민감 데이터에 접근했다면 실제 열람은 최소화하고 파일명/건수만 증거로 남긴다",
                    "지속 접근(백도어 등)은 고객과 사전 합의된 경우에만 시도한다",
                ],
            },
            {
                "phase": "7. 흔적 정리 및 보고서 작성 (Cleanup & Reporting)",
                "items": [
                    "테스트 중 생성한 계정·파일·백도어를 모두 제거한다",
                    "발견한 취약점을 심각도별로 정리하고 재현 절차·권장 조치를 포함한 보고서를 작성한다",
                    "경영진 요약과 기술 상세를 함께 담아 보고서를 구성한다",
                    "조치 후 재점검(Retest) 일정을 협의한다",
                ],
            },
        ],
    },
]

_SCENARIOS_BY_ID = {s["id"]: s for s in SCENARIOS}


def get_scenario(scenario_id: str) -> dict | None:
    return _SCENARIOS_BY_ID.get(scenario_id)


_LEGAL_NOTE = (
    "개인정보가 실제로 유출된 것으로 확인되면 규모와 정보 유형에 따라 개인정보보호법상 신고·통지 의무가 발생할 수 있습니다. "
    "정확한 기준과 절차는 최신 법령을 확인하고 법무팀/개인정보보호책임자(CPO)와 함께 판단하세요."
)

SCENARIO_MOCK_RESULTS: dict[str, dict] = {
    "beg-portscan-1": {
        "risk_score": 92,
        "summary": "백도어가 알려진 vsftpd 버전과 인증 없는 Redis가 발견된 심각한 스캔 결과입니다. 즉각적인 조치가 필요합니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "vsftpd 2.3.4 백도어 취약점", "severity": "CRITICAL", "cve": "CVE-2011-2523",
             "description": "vsftpd 2.3.4에는 특정 문자열(':)')을 포함한 사용자명으로 로그인 시도 시 6200번 포트에 백도어 쉘이 열리는 취약점이 있습니다.",
             "affected": "FTP 서비스 (포트 21)", "recommendation": "vsftpd를 최신 버전으로 즉시 업그레이드하세요."},
            {"id": "VULN-002", "title": "Redis 인증 미설정", "severity": "HIGH", "cve": "CWE-306",
             "description": "Redis(6379)가 인증 없이 노출되어 있어 외부에서 데이터 조회·삭제, 경우에 따라 원격 코드 실행까지 가능합니다.",
             "affected": "Redis (포트 6379)", "recommendation": "requirepass를 설정하고 방화벽으로 외부 접근을 차단하세요."},
            {"id": "VULN-003", "title": "Telnet 평문 프로토콜 사용", "severity": "HIGH", "cve": "CWE-319",
             "description": "포트 23(Telnet)이 열려 있어 모든 통신이 암호화 없이 전송됩니다.",
             "affected": "Telnet (포트 23)", "recommendation": "Telnet을 비활성화하고 SSH로 대체하세요."},
            {"id": "VULN-004", "title": "MySQL 외부 접속 허용", "severity": "MEDIUM", "cve": "CWE-284",
             "description": "포트 3306(MySQL)이 외부에서 접근 가능한 상태입니다.",
             "affected": "MySQL (포트 3306)", "recommendation": "방화벽으로 3306 포트를 로컬호스트로 제한하세요."},
            {"id": "VULN-005", "title": "OpenSSH 구버전", "severity": "MEDIUM", "cve": "CWE-1104",
             "description": "OpenSSH 6.6.1은 오래된 버전으로 이후 발견된 다수의 취약점 패치가 누락되어 있을 수 있습니다.",
             "affected": "SSH (포트 22)", "recommendation": "최신 LTS 버전으로 업그레이드하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "POTENTIAL",
            "types": ["Redis/MySQL에 저장됐을 수 있는 고객 정보"],
            "explanation": "Redis와 MySQL이 인증 없이 또는 외부에 노출되어 있어, 이 안에 고객 개인정보가 저장되어 있다면 함께 유출될 위험이 있습니다. 실제 데이터 내용 확인이 필요합니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "beg-config-1": {
        "risk_score": 78,
        "summary": ".git 디렉토리 노출과 관리자 페이지 접근 제어 누락이 가장 심각한 문제입니다. 배포 전 반드시 수정하세요.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": ".git 디렉토리 웹 노출", "severity": "CRITICAL", "cve": "CWE-538",
             "description": "/.git 경로가 별도 차단 없이 서빙되어 소스코드와 커밋 이력이 그대로 유출될 수 있습니다.",
             "affected": "location /.git", "recommendation": "location ~ /\\.git { deny all; } 처리하거나 배포 시 .git을 제외하세요."},
            {"id": "VULN-002", "title": "관리자 페이지 접근 제어 없음", "severity": "HIGH", "cve": "CWE-306",
             "description": "/admin 경로에 인증 설정이 없어 누구나 접근할 수 있습니다.",
             "affected": "location /admin", "recommendation": "Basic Auth 또는 애플리케이션 레벨 인증, IP 화이트리스트를 추가하세요."},
            {"id": "VULN-003", "title": "디렉토리 목록 노출", "severity": "MEDIUM", "cve": "CWE-548",
             "description": "autoindex on 설정으로 디렉토리 내용이 외부에 노출됩니다.",
             "affected": "location /", "recommendation": "autoindex off; 로 변경하세요."},
            {"id": "VULN-004", "title": "서버 버전 정보 노출", "severity": "MEDIUM", "cve": "CWE-200",
             "description": "server_tokens on 설정으로 nginx 버전이 응답 헤더에 노출됩니다.",
             "affected": "nginx.conf server_tokens", "recommendation": "server_tokens off; 를 추가하세요."},
            {"id": "VULN-005", "title": "HTTPS 미적용", "severity": "LOW", "cve": "CWE-319",
             "description": "listen 80만 존재하고 443/SSL 설정이 없습니다.",
             "affected": "server 블록 전체", "recommendation": "인증서를 발급받아 HTTPS로 리다이렉트하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "POTENTIAL",
            "types": [".git 이력에 남아있을 수 있는 개인정보"],
            "explanation": ".git 저장소가 노출되면 과거 커밋 이력에 포함됐던 고객 데이터나 자격증명이 그대로 남아있을 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "beg-code-1": {
        "risk_score": 80,
        "summary": "SQL Injection과 XSS를 포함한 여러 코드 취약점이 발견됐습니다. 배포 전 반드시 수정하세요.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "SQL Injection (login)", "severity": "CRITICAL", "cve": "CWE-89",
             "description": "f-string으로 조립된 쿼리라 username/password에 SQL 구문을 주입할 수 있습니다.",
             "affected": "login() 함수", "recommendation": "Prepared Statement 또는 ORM으로 교체하세요."},
            {"id": "VULN-002", "title": "하드코딩된 DB 비밀번호", "severity": "HIGH", "cve": "CWE-798",
             "description": "DB_PASSWORD가 소스코드에 평문으로 남아 있습니다.",
             "affected": "DB_PASSWORD 상수", "recommendation": "환경변수 또는 시크릿 매니저로 이동하세요."},
            {"id": "VULN-003", "title": "XSS (profile)", "severity": "HIGH", "cve": "CWE-79",
             "description": "render_template_string에 사용자 입력을 그대로 넣어 스크립트 실행이 가능합니다.",
             "affected": "profile() 함수", "recommendation": "사용자 입력을 템플릿 문자열에 직접 삽입하지 말고 이스케이프 처리하세요."},
            {"id": "VULN-004", "title": "취약한 해시 알고리즘 MD5", "severity": "MEDIUM", "cve": "CWE-327",
             "description": "비밀번호 해싱에 MD5를 사용해 레인보우 테이블 공격에 취약합니다.",
             "affected": "hash_password() 함수", "recommendation": "bcrypt 또는 argon2로 교체하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "CONFIRMED",
            "types": ["계정 자격증명(아이디/비밀번호)"],
            "explanation": "로그인 기능이 SQL Injection에 취약하고 비밀번호가 취약한 해시(MD5)로 저장되어 있어, 공격 시 전체 회원의 계정 정보가 유출될 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "ctf-portscan-1": {
        "risk_score": 96,
        "summary": "여러 서비스에서 공개 exploit이 존재하는 심각한 취약점이 발견됐습니다. vsftpd 백도어가 가장 빠르고 확실한 공략 지점입니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "vsftpd 2.3.4 백도어 (최우선 공략 대상)", "severity": "CRITICAL", "cve": "CVE-2011-2523",
             "description": "공개 exploit이 있고 즉시 쉘을 획득할 수 있어 CTF 단골 소재입니다.",
             "affected": "FTP (포트 21)", "recommendation": "즉시 패치된 버전으로 업그레이드하세요."},
            {"id": "VULN-002", "title": "Samba SambaCry RCE", "severity": "CRITICAL", "cve": "CVE-2017-7494",
             "description": "공유 폴더에 악성 라이브러리를 업로드해 원격 코드 실행이 가능한 취약점입니다.",
             "affected": "Samba (포트 139/445)", "recommendation": "Samba를 최신 버전으로 업그레이드하세요."},
            {"id": "VULN-003", "title": "Jenkins 스크립트 콘솔 RCE", "severity": "HIGH", "cve": "CWE-94",
             "description": "인증되지 않은 스크립트 콘솔(/script)로 Groovy 코드를 실행해 셸을 얻을 수 있는 구버전입니다.",
             "affected": "Jenkins (포트 8080)", "recommendation": "인증을 활성화하고 최신 버전으로 업그레이드하세요."},
            {"id": "VULN-004", "title": "Elasticsearch 인증 없는 API + RCE 이력", "severity": "HIGH", "cve": "CVE-2015-1427",
             "description": "인증 없이 API가 노출되어 있고 원격 코드 실행 취약점 이력이 있습니다.",
             "affected": "Elasticsearch (포트 9200)", "recommendation": "인증을 추가하고 최신 버전으로 업그레이드하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "POTENTIAL",
            "types": ["Elasticsearch에 색인된 데이터"],
            "explanation": "인증 없는 Elasticsearch에 개인정보가 색인되어 있다면 API 호출만으로 그대로 조회·유출될 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "ctf-code-1": {
        "risk_score": 93,
        "summary": "하드코딩된 백도어 계정을 포함해 인증을 여러 경로로 우회할 수 있는 심각한 취약점들이 발견됐습니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "하드코딩된 백도어 계정", "severity": "CRITICAL", "cve": "CWE-798",
             "description": "admin/backdoor2024 계정으로 인증을 완전히 우회할 수 있습니다.",
             "affected": "check_login() 함수", "recommendation": "디버그용 백도어 코드를 즉시 제거하세요."},
            {"id": "VULN-002", "title": "SQL Injection", "severity": "CRITICAL", "cve": "CWE-89",
             "description": "문자열 포매팅 쿼리라 ' OR '1'='1 같은 페이로드로 인증 우회가 가능합니다.",
             "affected": "check_login() 함수", "recommendation": "Prepared Statement로 교체하세요."},
            {"id": "VULN-003", "title": "예측 가능한 토큰 생성", "severity": "HIGH", "cve": "CWE-330",
             "description": "고정된 SECRET_KEY와 사용자명만으로 MD5 토큰을 만들어 오프라인에서 타 사용자 토큰을 위조할 수 있습니다.",
             "affected": "generate_token() 함수", "recommendation": "충분한 엔트로피의 무작위 토큰과 서버 측 서명 검증을 사용하세요."},
            {"id": "VULN-004", "title": "클라이언트 쿠키를 신뢰하는 권한 검증", "severity": "HIGH", "cve": "CWE-602",
             "description": "role 쿠키 값을 검증 없이 신뢰해 쿠키를 'admin'으로 조작하면 관리자 권한을 얻습니다.",
             "affected": "is_admin() 함수", "recommendation": "권한 정보는 서버 세션에서만 조회하고 클라이언트 값을 신뢰하지 마세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "CONFIRMED",
            "types": ["계정 자격증명", "세션 토큰"],
            "explanation": "백도어 계정과 SQL Injection으로 전체 계정 정보에 접근할 수 있고, 예측 가능한 토큰으로 임의 사용자를 사칭해 개인정보에 접근할 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "ctf-config-1": {
        "risk_score": 88,
        "summary": ".git 노출과 민감 확장자 파일 접근 허용으로 소스코드와 시크릿이 유출될 수 있는 심각한 설정 실수입니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": ".git 노출", "severity": "CRITICAL", "cve": "CWE-538",
             "description": "git-dumper 등으로 소스 전체와 커밋 이력을 복구할 수 있습니다.",
             "affected": "location ~ /.git", "recommendation": "해당 location 블록을 제거하고 deny all;로 차단하세요."},
            {"id": "VULN-002", "title": "백업 디렉토리 인덱싱 노출", "severity": "HIGH", "cve": "CWE-548",
             "description": "/backup/ 경로의 autoindex가 켜져 있어 백업 파일 목록이 그대로 보입니다.",
             "affected": "location /backup/", "recommendation": "autoindex off; 로 변경하고 접근을 제한하세요."},
            {"id": "VULN-003", "title": "민감 확장자 파일 접근 허용", "severity": "HIGH", "cve": "CWE-538",
             "description": ".env/.bak/.old 확장자 파일이 그대로 서빙되어 환경변수·시크릿이 유출될 수 있습니다.",
             "affected": "location ~* \\.(env|bak|old)$", "recommendation": "해당 location 블록을 제거하고 배포 시 이런 파일이 웹 루트에 남지 않게 하세요."},
            {"id": "VULN-004", "title": "내부 인증 헤더 프록시 신뢰 문제", "severity": "MEDIUM", "cve": "CWE-290",
             "description": "외부 요청의 X-Internal-Auth 헤더를 사전에 제거하지 않으면 클라이언트가 헤더를 위조해 내부 인증을 우회할 수 있습니다.",
             "affected": "location /api/", "recommendation": "proxy_set_header 전에 proxy_set_header X-Internal-Auth \"\"; 로 클라이언트 값을 먼저 제거하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "CONFIRMED",
            "types": [".env/백업 파일 내 DB 접속 정보 및 고객 데이터"],
            "explanation": ".env와 백업 디렉토리가 그대로 노출되어 있어 데이터베이스 접속 정보나 백업된 고객 데이터가 그대로 다운로드될 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "ctf-memory-1": {
        "risk_score": 94,
        "summary": "정상 프로세스로 위장한 악성 프로세스와 외부 C2 연결, 인코딩된 PowerShell 실행이 함께 발견된 전형적인 침해 흔적입니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "프로세스 마스커레이딩 (svch0st.exe)", "severity": "CRITICAL", "cve": "CWE-706",
             "description": "정상 프로세스 svchost.exe를 흉내낸 'svch0st.exe'(오타 삽입)가 발견되어 악성코드가 정상 프로세스로 위장하고 있을 가능성이 높습니다.",
             "affected": "PID 4444 (svch0st.exe)", "recommendation": "해당 프로세스를 격리하고 디스크상의 실행 파일 경로 및 디지털 서명을 확인하세요."},
            {"id": "VULN-002", "title": "외부 C2 의심 연결 (185.220.101.7)", "severity": "CRITICAL", "cve": "CWE-200",
             "description": "svch0st.exe(PID 4444)가 외부 IP 185.220.101.7:4444로 ESTABLISHED 연결을 맺고 있어 C2(명령 제어) 통신일 가능성이 있습니다.",
             "affected": "네트워크 연결 (PID 4444)", "recommendation": "해당 IP를 방화벽에서 차단하고 위협 인텔리전스로 평판을 조회하세요."},
            {"id": "VULN-003", "title": "인코딩된 PowerShell 실행", "severity": "HIGH", "cve": "CWE-506",
             "description": "-enc 옵션과 -w hidden 옵션으로 실행된 PowerShell 명령이 발견되어 파일리스 악성코드 실행이 의심됩니다.",
             "affected": "PID 5210 (powershell.exe)", "recommendation": "Base64 명령을 디코딩해 실제 동작을 분석하고 PowerShell ScriptBlock Logging을 활성화하세요."},
            {"id": "VULN-004", "title": "메모리 내 Base64 인코딩 문자열 발견", "severity": "MEDIUM", "cve": "CWE-200",
             "description": "strings 결과에서 Base64로 인코딩된 문자열(b64_flag=...)이 발견되어 추가 조사와 디코딩이 필요합니다.",
             "affected": "메모리 덤프 문자열 영역", "recommendation": "CyberChef 또는 base64 -d로 디코딩해 민감 정보 포함 여부를 확인하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "POTENTIAL",
            "types": ["C2 연결을 통한 데이터 유출 가능성"],
            "explanation": "C2로 의심되는 외부 연결이 확인되어, 시스템에 저장된 개인정보가 함께 유출되고 있을 가능성이 있습니다. 확인하려면 네트워크 트래픽과 파일 접근 로그를 추가로 조사해야 합니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "privacy-breach-1": {
        "risk_score": 97,
        "summary": "인증 없이 노출된 백업 파일을 통해 대규모 고객 개인정보(주민등록번호·카드번호 포함)가 실제로 유출된 것으로 확인됩니다. 즉시 사고 대응 절차를 시작해야 합니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "백업 디렉토리 인증 없이 노출 (autoindex)", "severity": "CRITICAL", "cve": "CWE-548",
             "description": "/backup/ 경로에 접근 제어가 없고 autoindex가 켜져 있어 누구나 파일 목록을 보고 다운로드할 수 있습니다.",
             "affected": "location /backup/", "recommendation": "즉시 autoindex off로 변경하고 인증 없이는 접근할 수 없도록 차단하세요."},
            {"id": "VULN-002", "title": "주민등록번호 평문 저장·노출", "severity": "CRITICAL", "cve": "CWE-359",
             "description": "customers_2026Q2.csv에 주민등록번호가 암호화·마스킹 없이 평문으로 저장되어 그대로 노출되었습니다.",
             "affected": "customers_2026Q2.csv (rrn 컬럼)", "recommendation": "고유식별정보는 암호화 저장이 원칙입니다. 즉시 파일 접근을 차단하고 암호화 저장으로 전환하세요."},
            {"id": "VULN-003", "title": "카드번호 평문 저장·노출", "severity": "CRITICAL", "cve": "CWE-359",
             "description": "카드번호가 마스킹 없이 평문으로 저장되어 있어 결제 정보 유출로 이어질 수 있습니다.",
             "affected": "customers_2026Q2.csv (card_no 컬럼)", "recommendation": "카드정보는 저장하지 않거나 PCI-DSS 기준에 따라 토큰화/암호화하세요."},
            {"id": "VULN-004", "title": "대규모 개인정보 유출 (약 128,430건)", "severity": "CRITICAL", "cve": "CWE-200",
             "description": "노출된 파일의 규모가 약 128,430건으로 추정되어 대규모 개인정보 유출 사고에 해당할 수 있습니다.",
             "affected": "customers_2026Q2.csv 전체", "recommendation": "사고 대응 절차(탐지-봉쇄-신고-통지-조사-재발방지)를 즉시 개시하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "CONFIRMED",
            "types": ["주민등록번호", "전화번호", "이메일", "카드번호"],
            "explanation": "인증 없이 노출된 백업 파일에 고객 개인정보가 평문으로 포함되어 있어 유출이 확인되었습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
    "pentest-fullchain-1": {
        "risk_score": 95,
        "summary": "정찰부터 권한 상승까지 전체 침투 경로가 확인된 심각한 사례입니다. SQL Injection으로 관리자 권한을 획득해 전체 사용자 데이터에 접근할 수 있습니다.",
        "vulnerabilities": [
            {"id": "VULN-001", "title": "관리자 로그인 API SQL Injection", "severity": "CRITICAL", "cve": "CWE-89",
             "description": "' OR '1'='1 페이로드로 인증을 우회해 관리자 세션을 획득할 수 있습니다.",
             "affected": "/api/login", "recommendation": "Prepared Statement로 교체하고 로그인 실패 임계치를 적용하세요."},
            {"id": "VULN-002", "title": "내부 관리자 패널 외부 노출", "severity": "HIGH", "cve": "CWE-284",
             "description": "3000번 포트의 내부 관리용 Node.js 패널이 외부에서 인증 없이 접근 가능합니다.",
             "affected": "포트 3000 (/admin/login)", "recommendation": "내부 전용 네트워크로 제한하고 VPN을 통해서만 접근하도록 하세요."},
            {"id": "VULN-003", "title": "권한 상승 후 전체 사용자 데이터 노출", "severity": "HIGH", "cve": "CWE-639",
             "description": "획득한 관리자 세션으로 /api/users/export에 접근해 전체 사용자 목록을 다운로드할 수 있는 것이 확인되었습니다.",
             "affected": "/api/users/export", "recommendation": "관리자 기능에 대해 추가 인증(MFA)과 세분화된 권한 검증을 적용하세요."},
            {"id": "VULN-004", "title": "OpenSSH 구버전", "severity": "MEDIUM", "cve": "CWE-1104",
             "description": "OpenSSH 7.2p2는 오래된 버전으로 이후 패치된 취약점에 노출될 수 있습니다.",
             "affected": "SSH (포트 22)", "recommendation": "최신 버전으로 업그레이드하세요."},
        ],
        "personal_data_exposure": {
            "risk_level": "CONFIRMED",
            "types": ["계정 정보 전체 (관리자 export 기능을 통한 접근)"],
            "explanation": "SQL Injection으로 획득한 관리자 권한을 통해 전체 사용자 목록을 다운로드할 수 있는 것이 확인되어 개인정보 유출로 이어질 수 있습니다.",
            "legal_note": _LEGAL_NOTE,
        },
        "_mock": True,
    },
}
