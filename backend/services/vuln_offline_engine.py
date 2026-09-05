"""취약점 스캐너(App 3)의 "오프라인(폐쇄망)" 모드 — Claude/로컬 LLM 둘 다 쓸 수 없을 때도
실제 입력 내용을 분석하도록, 정규식/키워드 기반 결정론적 규칙 엔진으로 4개 입력 유형
(포트 스캔/설정 파일/코드/메모리 덤프)을 검사한다.

기존 Mock 모드(mock_vulnerability.py)는 입력 내용과 무관하게 고정 샘플 중 하나를 반환하는
데모용이라 폐쇄망 "실제 분석" 대체재로 쓸 수 없다 — 이 엔진은 그 대신 실제로 붙여넣은
텍스트를 파싱해 사전 정의된 위험 패턴과 대조한다. AI만큼 폭넓게 탐지하지는 못하므로
`ENGINE_DISCLAIMER`를 결과에 함께 담아 한계를 명시한다.

시크릿(하드코딩된 자격증명) 탐지는 이미 검증된 App 19 시크릿 스캐너(secret_scanner_service)를
그대로 재사용한다 — 중복 구현하지 않고, 원본 값 마스킹 등 안전장치도 그대로 물려받는다.
"""
import re

from services.secret_scanner_service import scan_text as _scan_secrets

ENGINE_DISCLAIMER = (
    "이 결과는 네트워크 연결 없이 동작하는 규칙/정규식 기반 오프라인 분석 엔진이 생성했습니다 — "
    "AI가 아니라 사전 정의된 패턴(위험 포트, 알려진 취약 버전 배너, 설정 안티패턴, 코드 패턴)과의 "
    "매칭 결과이므로 AI 분석보다 탐지 범위가 좁고 새롭거나 변형된 취약점은 놓칠 수 있습니다. "
    "인터넷 또는 로컬 LLM을 사용할 수 있게 되면 AI 모드로 재분석하는 것을 권장합니다."
)

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEV_BASE_SCORE = {"CRITICAL": 90, "HIGH": 68, "MEDIUM": 42, "LOW": 15}


def _mk(title: str, severity: str, cve: str, description: str, affected: str, recommendation: str) -> dict:
    return {
        "id": "VULN-000",  # analyze_offline()에서 정렬 후 다시 번호를 매김
        "title": title,
        "severity": severity,
        "cve": cve,
        "description": description,
        "affected": affected,
        "recommendation": recommendation,
    }


def _secrets_as_vulns(content: str) -> list[dict]:
    result = _scan_secrets(content)
    vulns = []
    for f in result.get("findings", []):
        vulns.append(_mk(
            title=f"하드코딩된 시크릿 발견: {f['pattern_label']}",
            severity=f["severity"],
            cve="CWE-798",
            description=f"{f['pattern_label']}(으)로 추정되는 값이 {f['line']}번째 줄에서 발견되었습니다 "
                        f"(마스킹됨: {f['matched_masked']}).",
            affected=f"{f['line']}번째 줄",
            recommendation=f["recommendation"],
        ))
    return vulns


# ---------------------------------------------------------------- portscan

_PORT_LINE_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)\s*(.*)$", re.I | re.M)

_RISKY_PORTS = {
    21: ("HIGH", "FTP 평문 전송 활성화", "CWE-319",
         "포트 21(FTP)이 열려 있어 자격증명과 데이터가 암호화 없이 전송됩니다.",
         "FTP를 비활성화하고 SFTP(포트 22) 또는 FTPS로 대체하세요."),
    23: ("HIGH", "Telnet 서비스 활성화", "CWE-319",
         "포트 23(Telnet)이 열려 있어 모든 통신이 암호화 없이 전송됩니다.",
         "Telnet을 즉시 비활성화하고 SSH로 대체하세요."),
    445: ("MEDIUM", "SMB 서비스 외부 노출", "CWE-284",
          "포트 445(SMB)가 외부에서 접근 가능해 EternalBlue류 취약점의 공격 표면이 됩니다.",
          "SMB 접근을 신뢰된 네트워크로 제한하고 최신 패치를 적용하세요."),
    3389: ("HIGH", "RDP 외부 노출", "CWE-284",
           "포트 3389(RDP)가 외부에서 접근 가능해 무차별 대입 공격의 표적이 되기 쉽습니다.",
           "RDP를 VPN 뒤에 두거나 접근 IP를 제한하고 MFA를 적용하세요."),
    3306: ("MEDIUM", "MySQL 외부 접속 허용", "CWE-284",
           "포트 3306(MySQL)이 외부에서 접근 가능합니다.",
           "방화벽으로 3306 포트 접근을 신뢰된 IP(애플리케이션 서버 등)로 제한하세요."),
    5432: ("MEDIUM", "PostgreSQL 외부 접속 허용", "CWE-284",
           "포트 5432(PostgreSQL)가 외부에서 접근 가능합니다.",
           "방화벽으로 5432 포트 접근을 신뢰된 IP로 제한하세요."),
    6379: ("HIGH", "Redis 외부 노출 (인증 여부 미확인)", "CWE-306",
           "포트 6379(Redis)가 외부에서 접근 가능합니다. Redis는 기본적으로 인증이 없는 경우가 많아 "
           "데이터 탈취나 원격 코드 실행으로 이어질 수 있습니다.",
           "requirepass를 설정하고 방화벽으로 접근을 제한하세요."),
    27017: ("MEDIUM", "MongoDB 외부 접속 허용", "CWE-284",
            "포트 27017(MongoDB)이 외부에서 접근 가능합니다.",
            "인증을 활성화하고 방화벽으로 접근을 제한하세요."),
    9200: ("MEDIUM", "Elasticsearch 외부 노출", "CWE-284",
           "포트 9200(Elasticsearch)이 외부에서 접근 가능합니다.",
           "인증·네트워크 제한 없이는 외부에 노출하지 마세요."),
    1433: ("MEDIUM", "MSSQL 외부 접속 허용", "CWE-284",
           "포트 1433(MSSQL)이 외부에서 접근 가능합니다.",
           "방화벽으로 접근을 신뢰된 IP로 제한하세요."),
    135: ("LOW", "RPC 엔드포인트 매퍼 노출", "CWE-284",
          "포트 135(RPC)가 열려 있어 원격 프로시저 호출 관련 정보 수집에 활용될 수 있습니다.",
          "불필요하면 비활성화하거나 방화벽으로 제한하세요."),
}

_VULN_BANNERS = [
    (re.compile(r"vsftpd\s*2\.3\.4", re.I), "CRITICAL", "vsftpd 2.3.4 백도어", "CVE-2011-2523",
     "vsftpd 2.3.4에는 악의적으로 삽입된 백도어가 존재해 원격 셸 실행이 가능합니다.",
     "즉시 최신 버전으로 업그레이드하세요."),
    (re.compile(r"openssl\s*1\.0\.1[a-f]?\b", re.I), "CRITICAL", "OpenSSL Heartbleed 취약 버전", "CVE-2014-0160",
     "OpenSSL 1.0.1~1.0.1f는 Heartbleed 취약점에 노출되어 메모리 내용이 유출될 수 있습니다.",
     "OpenSSL 3.x 이상으로 즉시 업그레이드하세요."),
    (re.compile(r"proftpd\s*1\.3\.3", re.I), "CRITICAL", "ProFTPd 1.3.3c 백도어", "CVE-2010-4221",
     "ProFTPd 1.3.3c에는 백도어가 삽입된 배포판이 유포된 이력이 있습니다.",
     "최신 버전으로 즉시 업그레이드하세요."),
    (re.compile(r"apache(?:\s*httpd)?[/\s]2\.2\b", re.I), "MEDIUM", "EOL Apache 2.2 사용", "CWE-1104",
     "Apache 2.2는 2018년 EOL되어 더 이상 보안 패치를 받지 않습니다.",
     "Apache 2.4 이상으로 업그레이드하세요."),
    (re.compile(r"openssh[/\s][4-6]\.\d", re.I), "MEDIUM", "오래된 OpenSSH 버전", "CWE-1104",
     "감지된 OpenSSH 버전대는 다수의 알려진 취약점이 존재하는 오래된 버전입니다.",
     "최신 OpenSSH로 업그레이드하세요."),
]


def _analyze_portscan(content: str) -> list[dict]:
    vulns: list[dict] = []
    seen_ports: set[int] = set()
    for m in _PORT_LINE_RE.finditer(content):
        port = int(m.group(1))
        service = m.group(4)
        version = (m.group(5) or "").strip()
        banner = f"{service} {version}".strip()

        if port in _RISKY_PORTS and port not in seen_ports:
            seen_ports.add(port)
            sev, title, cwe, desc, rec = _RISKY_PORTS[port]
            vulns.append(_mk(title, sev, cwe, desc, f"{service} 서비스 (포트 {port})", rec))

        for rx, sev, title, cve, desc, rec in _VULN_BANNERS:
            if rx.search(banner):
                vulns.append(_mk(title, sev, cve, desc, f"{service} (포트 {port})", rec))

    if not vulns:
        vulns.append(_mk(
            "알려진 위험 패턴 미발견", "LOW", "N/A",
            "규칙 기반 스캔에서 사전 정의된 위험 포트/알려진 취약 버전 배너 패턴이 발견되지 않았습니다. "
            "이는 안전을 보장하지 않으며, 이 엔진이 모르는 취약점은 놓칠 수 있습니다.",
            "스캔 대상 전체",
            "AI 모드(Cloud/로컬 LLM) 또는 nmap --script vuln 등 전용 도구로 추가 점검을 권장합니다.",
        ))
    return vulns


# ------------------------------------------------------------------ config

_CONFIG_CHECKS = [
    (re.compile(r"PermitRootLogin\s+yes", re.I), "CRITICAL", "SSH 루트 로그인 허용", "CWE-250",
     "sshd_config에서 PermitRootLogin이 yes로 설정되어 있어 루트 계정으로 직접 접속이 가능합니다.",
     "PermitRootLogin no로 변경 후 sshd를 재시작하세요."),
    (re.compile(r"Protocol\s+1\b", re.I), "CRITICAL", "SSH 프로토콜 버전 1 사용", "CWE-327",
     "SSH 프로토콜 1은 다수의 알려진 취약점이 있는 폐기된 버전입니다.",
     "Protocol 2만 사용하도록 설정하세요(대부분의 최신 sshd는 기본값이 이미 2입니다)."),
    (re.compile(r"PasswordAuthentication\s+yes", re.I), "MEDIUM", "SSH 비밀번호 인증 허용", "CWE-521",
     "비밀번호 기반 SSH 인증이 허용되어 있어 무차별 대입 공격에 노출될 수 있습니다.",
     "공개키 인증으로 전환하고 PasswordAuthentication no로 설정하세요."),
    (re.compile(r"server_tokens\s+on", re.I), "MEDIUM", "서버 버전 정보 노출", "CWE-200",
     "Nginx server_tokens가 on으로 설정되어 응답 헤더에 버전 정보가 노출됩니다.",
     "server_tokens off; 설정을 추가하세요."),
    (re.compile(r"autoindex\s+on", re.I), "MEDIUM", "디렉토리 목록 노출", "CWE-548",
     "autoindex on 설정으로 디렉토리 내용이 외부에 노출됩니다.",
     "autoindex off;로 변경하세요."),
    (re.compile(r"ssl_protocols[^;]*\b(SSLv[23]|TLSv1\.0|TLSv1\.1|TLSv1\s)", re.I), "HIGH", "취약한 TLS 버전 허용", "CWE-327",
     "SSLv2/v3 또는 TLS 1.0/1.1처럼 폐기된 프로토콜 버전이 허용되어 있습니다.",
     "TLSv1.2 이상만 허용하도록 ssl_protocols를 수정하세요."),
]


def _analyze_config(content: str) -> list[dict]:
    vulns: list[dict] = []
    for rx, sev, title, cwe, desc, rec in _CONFIG_CHECKS:
        if rx.search(content):
            vulns.append(_mk(title, sev, cwe, desc, "설정 파일", rec))

    if re.search(r"listen\s+443|ssl_certificate", content, re.I) and not re.search(r"Strict-Transport-Security", content, re.I):
        vulns.append(_mk(
            "HSTS 헤더 누락", "LOW", "CWE-523",
            "HTTPS를 사용하지만 Strict-Transport-Security 헤더 설정이 보이지 않습니다.",
            "웹 서버 설정", "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always; 추가를 검토하세요.",
        ))

    vulns.extend(_secrets_as_vulns(content))

    if not vulns:
        vulns.append(_mk(
            "알려진 위험 설정 패턴 미발견", "LOW", "N/A",
            "규칙 기반 스캔에서 사전 정의된 설정 안티패턴이 발견되지 않았습니다. 이 엔진이 모르는 취약점은 놓칠 수 있습니다.",
            "설정 파일 전체", "AI 모드로 재분석하거나 CIS 벤치마크 등 공식 하드닝 가이드와 대조해보세요.",
        ))
    return vulns


# -------------------------------------------------------------------- code

# 따옴표 안에 SQL 문자열 리터럴(작은따옴표)이 섞이는 흔한 경우(예: f"...name='{username}'")를
# 다루기 위해 큰따옴표/작은따옴표 f-string을 따로 매칭한다 — 둘 다 한 클래스로 묶어 제외하면
# 문자열 내부의 반대쪽 따옴표에서 매칭이 조기 종료돼 버린다.
_SQL_FSTRING_RE = re.compile(
    r"""f"[^"\n]*\b(select|insert|update|delete)\b[^"\n]*\{"""
    r"""|f'[^'\n]*\b(select|insert|update|delete)\b[^'\n]*\{""",
    re.I,
)
_SQL_CONCAT_RE = re.compile(
    r'''"[^"\n]*\b(select|insert|update|delete)\b[^"\n]*"\s*(\+|%\s*\()'''
    r"""|'[^'\n]*\b(select|insert|update|delete)\b[^'\n]*'\s*(\+|%\s*\()""",
    re.I,
)
_EVAL_EXEC_RE = re.compile(r"\b(eval|exec)\s*\(", re.I)
_PICKLE_RE = re.compile(r"\bpickle\.loads?\(", re.I)
_YAML_UNSAFE_RE = re.compile(r"yaml\.load\((?!.*Loader\s*=\s*yaml\.SafeLoader)", re.I)
_WEAK_HASH_RE = re.compile(r"hashlib\.(md5|sha1)\(|\bmd5\(", re.I)
_XSS_RE = re.compile(
    r"""\.innerHTML\s*=|dangerouslySetInnerHTML"""
    r"""|f"[^"\n]*<[a-zA-Z]+[^>\n]*>[^"\n]*\{"""
    r"""|f'[^'\n]*<[a-zA-Z]+[^>\n]*>[^'\n]*\{""",
    re.I,
)


def _analyze_code(content: str) -> list[dict]:
    vulns: list[dict] = []

    if _SQL_FSTRING_RE.search(content) or _SQL_CONCAT_RE.search(content):
        vulns.append(_mk(
            "SQL Injection 의심 패턴", "CRITICAL", "CWE-89",
            "사용자 입력으로 보이는 값이 문자열 포매팅/연결로 SQL 쿼리에 직접 삽입되는 패턴이 발견됐습니다.",
            "쿼리 조합 코드", "Prepared Statement 또는 ORM의 파라미터 바인딩으로 교체하세요.",
        ))
    if _XSS_RE.search(content):
        vulns.append(_mk(
            "Reflected/DOM XSS 의심 패턴", "HIGH", "CWE-79",
            "사용자 입력이 HTML 이스케이프 없이 그대로 출력/삽입되는 패턴이 발견됐습니다.",
            "출력 처리 코드", "출력 시 HTML 이스케이프를 적용하거나(escape(), bleach 등) innerHTML 대신 textContent를 사용하세요.",
        ))
    if _EVAL_EXEC_RE.search(content):
        vulns.append(_mk(
            "동적 코드 실행 (eval/exec) 사용", "HIGH", "CWE-95",
            "eval() 또는 exec()로 문자열을 코드로 실행하는 패턴이 발견됐습니다. 입력값이 여기 도달하면 임의 코드 실행으로 이어질 수 있습니다.",
            "동적 실행 코드", "eval/exec 사용을 제거하고 ast.literal_eval이나 명시적 파싱 로직으로 대체하세요.",
        ))
    if _PICKLE_RE.search(content):
        vulns.append(_mk(
            "안전하지 않은 역직렬화 (pickle)", "HIGH", "CWE-502",
            "신뢰할 수 없는 데이터를 pickle.loads()로 역직렬화하면 임의 코드 실행으로 이어질 수 있습니다.",
            "역직렬화 코드", "신뢰되지 않은 입력에는 pickle 대신 JSON 등 안전한 포맷을 사용하세요.",
        ))
    if _YAML_UNSAFE_RE.search(content):
        vulns.append(_mk(
            "안전하지 않은 YAML 로드", "HIGH", "CWE-502",
            "yaml.load()를 SafeLoader 없이 호출하면 임의 Python 객체 생성으로 이어질 수 있습니다.",
            "YAML 파싱 코드", "yaml.safe_load() 또는 Loader=yaml.SafeLoader를 사용하세요.",
        ))
    if _WEAK_HASH_RE.search(content):
        vulns.append(_mk(
            "취약한 해시 알고리즘 사용 (MD5/SHA1)", "MEDIUM", "CWE-327",
            "MD5 또는 SHA1이 사용되고 있습니다. 비밀번호 저장 등 보안 목적으로 쓰였다면 레인보우 테이블 공격에 취약합니다.",
            "해시 사용 코드", "비밀번호 해싱에는 bcrypt, scrypt, argon2를 사용하세요.",
        ))

    vulns.extend(_secrets_as_vulns(content))

    if not vulns:
        vulns.append(_mk(
            "알려진 위험 코드 패턴 미발견", "LOW", "N/A",
            "규칙 기반 스캔에서 사전 정의된 취약 코드 패턴이 발견되지 않았습니다. 이 엔진이 모르는 취약점은 놓칠 수 있습니다.",
            "코드 전체", "AI 모드로 재분석하거나 Bandit/Semgrep 등 전용 정적분석 도구를 함께 사용하는 것을 권장합니다.",
        ))
    return vulns


# ------------------------------------------------------------------ memory

_MASQUERADE_RE = re.compile(r"\b(svch0st|scvhost|lsas+\d|explor3r|exp1orer|iexplor3|csrs+\d)\b", re.I)
_ENCODED_PS_RE = re.compile(r"-enc(odedcommand)?\b|FromBase64String", re.I)
_ESTABLISHED_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\s+(?:->\s*)?(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+ESTABLISHED\b", re.I)
_PRIVATE_IP_RE = re.compile(r"^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0)")


def _analyze_memory(content: str) -> list[dict]:
    vulns: list[dict] = []

    if _MASQUERADE_RE.search(content):
        vulns.append(_mk(
            "프로세스 마스커레이딩 의심", "HIGH", "CWE-706",
            "정상 시스템 프로세스와 이름이 유사하지만 철자가 다른 프로세스가 발견되어 악성코드의 위장 가능성이 있습니다.",
            "프로세스 목록", "해당 프로세스의 실행 파일 경로와 디지털 서명을 확인하세요.",
        ))

    for m in _ESTABLISHED_RE.finditer(content):
        ip = m.group(1)
        if not _PRIVATE_IP_RE.match(ip):
            vulns.append(_mk(
                "비정상적인 외부 네트워크 연결", "MEDIUM", "CWE-200",
                f"알려지지 않은 외부 IP({ip})로의 활성 연결이 발견되어 C2 통신 가능성이 있습니다.",
                "네트워크 연결 목록", "해당 IP의 평판을 조회하고 필요시 차단하세요.",
            ))
            break  # 한 건만 대표로 보고 — 소음 방지

    if _ENCODED_PS_RE.search(content):
        vulns.append(_mk(
            "인코딩된 PowerShell 명령 발견", "MEDIUM", "CWE-506",
            "-EncodedCommand 또는 Base64 디코딩 호출이 발견되어 난독화된 명령 실행이 의심됩니다.",
            "프로세스 명령줄", "인코딩된 값을 디코딩해 실제 실행 내용을 확인하세요.",
        ))

    if not vulns:
        vulns.append(_mk(
            "알려진 위험 패턴 미발견", "LOW", "N/A",
            "규칙 기반 스캔에서 프로세스 마스커레이딩/의심 연결/인코딩된 명령 패턴이 발견되지 않았습니다. "
            "이 엔진이 모르는 IoC는 놓칠 수 있습니다.",
            "메모리 덤프 전체", "AI 모드로 재분석하거나 Volatility의 malfind/hollowfind 등 추가 플러그인으로 점검하세요.",
        ))
    return vulns


# --------------------------------------------------------------- 개인정보

_PII_PATTERNS = {
    "주민등록번호": re.compile(r"\b\d{6}[-\s]?[1-4]\d{6}\b"),
    "카드번호": re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
    "이메일": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "휴대전화번호": re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b"),
}
_POTENTIAL_TRIGGER_WORDS = (
    "mysql", "postgresql", "mongodb", "redis", "sql injection", "db 연결", "데이터베이스",
    "자격증명", "비밀번호", "smb", "하드코딩된 시크릿",
)


def _pii_exposure(content: str, vulns: list[dict]) -> dict:
    found = [label for label, rx in _PII_PATTERNS.items() if rx.search(content)]
    if found:
        return {
            "risk_level": "CONFIRMED",
            "types": found,
            "explanation": f"입력 내용에서 개인정보로 보이는 값({', '.join(found)})이 직접 발견되었습니다.",
            "legal_note": "개인정보 유출이 실제로 확인되면 개인정보보호법상 신고·통지 의무가 발생할 수 있으니 "
                          "법무팀/개인정보보호책임자와 함께 확인하세요.",
        }

    haystack = " ".join(f"{v.get('title', '')} {v.get('description', '')}" for v in vulns).lower()
    if any(w in haystack for w in _POTENTIAL_TRIGGER_WORDS):
        return {
            "risk_level": "POTENTIAL",
            "types": ["발견된 취약점을 통해 접근 가능한 시스템/자격증명에 개인정보가 포함되어 있을 가능성"],
            "explanation": "직접적인 개인정보 문자열은 발견되지 않았으나, 위 취약점을 통해 접근 가능한 시스템에 "
                          "개인정보가 저장되어 있다면 함께 노출될 위험이 있습니다. 실제 데이터 내용 확인이 필요합니다.",
            "legal_note": "개인정보 유출이 실제로 확인되면 개인정보보호법상 신고·통지 의무가 발생할 수 있으니 "
                          "법무팀/개인정보보호책임자와 함께 확인하세요.",
        }
    return {"risk_level": "NONE", "types": [], "explanation": "", "legal_note": ""}


def _risk_score(vulns: list[dict]) -> int:
    if not vulns:
        return 5
    top_sev = min((v["severity"] for v in vulns), key=lambda s: _SEV_RANK.get(s, 9))
    base = _SEV_BASE_SCORE.get(top_sev, 30)
    bonus = min(9, (len(vulns) - 1) * 2)
    return min(99, base + bonus)


def _summary_text(vulns: list[dict], counts: dict) -> str:
    crit, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
    if crit > 0:
        return f"규칙 기반 오프라인 분석에서 심각(CRITICAL) {crit}건을 포함해 총 {len(vulns)}건의 보안 문제가 발견됐습니다. 즉각적인 조치가 필요합니다."
    if high > 0:
        return f"규칙 기반 오프라인 분석에서 높음(HIGH) {high}건을 포함해 총 {len(vulns)}건의 보안 문제가 발견됐습니다."
    return f"규칙 기반 오프라인 분석에서 총 {len(vulns)}건의 사항이 발견됐습니다."


_ANALYZERS = {
    "portscan": _analyze_portscan,
    "config": _analyze_config,
    "code": _analyze_code,
    "memory": _analyze_memory,
}


def analyze_offline(content: str, input_type: str) -> dict:
    analyzer = _ANALYZERS.get(input_type, _analyze_config)
    vulns = analyzer(content)

    vulns.sort(key=lambda v: _SEV_RANK.get(v["severity"], 9))
    for i, v in enumerate(vulns, start=1):
        v["id"] = f"VULN-{i:03d}"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        if v["severity"] in counts:
            counts[v["severity"]] += 1

    return {
        "risk_score": _risk_score(vulns),
        "summary": _summary_text(vulns, counts),
        "vulnerabilities": vulns,
        "personal_data_exposure": _pii_exposure(content, vulns),
        "engine_note": ENGINE_DISCLAIMER,
    }
