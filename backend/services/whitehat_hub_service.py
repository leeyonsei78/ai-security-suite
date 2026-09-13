"""화이트해커 연습 허브 — App 22(통합 리스크 대시보드)와 같은 성격의 순수 집계 페이지.
새로운 실습 콘텐츠를 만들지 않고, 이미 흩어져 있는 실습 모듈(App 9 Pwn/Reverse/Misc, App 10 Web
CTF 아레나, App 13 모의 해킹 랩, App 25의 '실습 랩' 탭, App 29 AD/Kerberos 공격 실습)을 하나의
학습 경로(curriculum)로 묶어 보여준다. 각 모듈의 실제 데이터(챌린지/스테이지 목록)를 직접
import해서 개수를 세므로, 각 모듈에 챌린지가 추가되어도 이 파일을 손대지 않아도 자동으로
반영된다(App 22 섹션에서 지적된 "하드코딩된 목록은 새 항목 추가 시 누락되기 쉽다"는 교훈을
피하기 위해, 개수 집계만큼은 정적 상수 대신 실제 import로 계산한다).
"""

from services.pwn_lab import CHALLENGES as PWN_CHALLENGES
from services.web_arena import CHALLENGE_META as WEB_ARENA_CHALLENGES
from services.pentest_lab import CHAINS as PENTEST_CHAINS
from services.forensics_lab import CHALLENGES as FORENSICS_CHALLENGES
from services.ad_attack_lab import STAGES as AD_STAGES

SAFETY_NOTICE = (
    "이 허브에 모인 모든 실습은 로컬에서만 동작하는 가상의 대상(취약한 로컬 서비스, 시뮬레이터, "
    "가짜 도메인)입니다. 실제 시스템이 아닙니다. 여기서 배운 공격 기법을 서면 승인(RoE) 없는 실제 "
    "시스템에 사용하는 것은 명백한 불법 행위이며, 이 프로젝트의 목적(정보보안팀의 방어 역량 강화)에도 "
    "정면으로 어긋납니다. 실제 업무에 적용할 때는 반드시 소속 조직의 모의해킹 승인 절차를 따르세요."
)


def _pwn_lab_module() -> dict:
    by_category: dict[str, int] = {}
    for c in PWN_CHALLENGES:
        by_category[c.get("category", "기타")] = by_category.get(c.get("category", "기타"), 0) + 1
    return {
        "id": "pwn_lab",
        "title": "Pwn/Reverse/Misc 실습실",
        "route": "/pwn-lab",
        "category": "시스템 해킹",
        "description": "실제로 컴파일한 바이너리를 gdb/Ghidra로 분석해 스택 버퍼 오버플로우, ret2libc, "
                       "포맷 스트링, 리버싱, 스테가노그래피/OSINT를 연습합니다.",
        "difficulty_range": "입문~고급",
        "challenge_count": len(PWN_CHALLENGES),
        "breakdown": by_category,
        "requires": "pwn/reverse 6종은 Docker Desktop 또는 WSL 필요 — misc 3종은 설치 없이 바로 가능",
    }


def _web_arena_module() -> dict:
    return {
        "id": "web_arena",
        "title": "Web CTF 아레나",
        "route": "/web-arena",
        "category": "웹 해킹",
        "description": "실제로 살아있는 취약 API를 상대로 SQLi/IDOR/XSS/SSRF/JWT 위조/SSTI/BFLA(OWASP API "
                       "Top 10)/Mass Assignment(OWASP API Top 10)를 실습합니다.",
        "difficulty_range": "입문~중급",
        "challenge_count": len(WEB_ARENA_CHALLENGES),
        "breakdown": {},
        "requires": "없음 — 서버만 켜면 바로 가능",
    }


def _pentest_lab_module() -> dict:
    return {
        "id": "pentest_lab",
        "title": "모의 해킹 랩",
        "route": "/pentest-lab",
        "category": "모의해킹 체이닝",
        "description": "정찰→초기 침투→내부망 피벗/권한 상승까지 하나의 가상 네트워크를 처음부터 끝까지 "
                       "공격하는 3개의 독립된 공격 체인(경로 조작+세션 위조 / 커맨드 인젝션+SUID / "
                       "파일 업로드+서비스 권한 오용).",
        "difficulty_range": "중급",
        "challenge_count": sum(len(c["stages"]) for c in PENTEST_CHAINS),
        "breakdown": {c["id"]: len(c["stages"]) for c in PENTEST_CHAINS},
        "requires": "없음",
    }


def _ad_attack_lab_module() -> dict:
    return {
        "id": "ad_attack_lab",
        "title": "AD/Kerberos 공격 실습",
        "route": "/ad-attack-lab",
        "category": "네트워크·AD 해킹",
        "description": "가상 Active Directory 도메인(CORP.LOCAL)을 대상으로 Kerberoasting, AS-REP Roasting, "
                       "DCSync 권한 오용까지 실제 기업 침해사고에서 가장 흔한 AD 공격 흐름을 재현합니다.",
        "difficulty_range": "중급~고급",
        "challenge_count": len(AD_STAGES),
        "breakdown": {},
        "requires": "없음",
    }


def _forensics_lab_module() -> dict:
    return {
        "id": "forensics_lab",
        "title": "포렌식 실습 랩",
        "route": "/forensics",
        "category": "포렌식",
        "description": "실제로 유효한 SQLite/pcap/ZIP 파일을 분석해 브라우저 히스토리, 네트워크 트래픽, "
                       "파일 카빙에서 증거를 찾아냅니다. 공격 기법을 반대로(방어팀 시각으로) 복기하는 실습입니다.",
        "difficulty_range": "입문~중급",
        "challenge_count": len(FORENSICS_CHALLENGES),
        "breakdown": {},
        "requires": "Python 표준 라이브러리만 필요 — Wireshark/binwalk는 있으면 더 정석적이지만 없어도 가능",
    }


LEARNING_PATH = [
    {
        "order": 1,
        "title": "1단계 — 웹 해킹으로 시작하기",
        "modules": ["web_arena"],
        "why": "설치가 전혀 필요 없고, 실무에서 가장 흔한 취약점 유형(SQLi/IDOR/XSS)부터 시작해 API 특화 "
               "취약점(BFLA/Mass Assignment)까지 자연스럽게 난이도가 올라갑니다.",
    },
    {
        "order": 2,
        "title": "2단계 — 하나의 네트워크를 처음부터 끝까지 공격해보기",
        "modules": ["pentest_lab"],
        "why": "개별 취약점이 아니라 정찰→침투→피벗→권한 상승으로 이어지는 '체이닝' 사고방식을 익힙니다.",
    },
    {
        "order": 3,
        "title": "3단계 — 바이너리/시스템 해킹",
        "modules": ["pwn_lab"],
        "why": "실제 컴파일된 바이너리를 gdb/Ghidra로 분석하는, 텍스트 분석만으로는 익힐 수 없는 감각을 기릅니다.",
    },
    {
        "order": 4,
        "title": "4단계 — 네트워크/디렉터리 서비스 공격",
        "modules": ["ad_attack_lab"],
        "why": "실제 기업 침해사고의 대다수가 거쳐가는 Active Directory 공격 기법(Kerberoasting/DCSync)을 다룹니다 "
               "— 정보보안팀이 가장 먼저 이해해야 할 공격 표면 중 하나입니다.",
    },
    {
        "order": 5,
        "title": "5단계 — 사고 대응 관점에서 되짚어보기",
        "modules": ["forensics_lab"],
        "why": "공격자가 남기는 흔적을 반대로 조사하는 방어팀의 시각으로 같은 유형의 사고를 복기합니다.",
    },
]


def get_catalog() -> dict:
    modules = [
        _web_arena_module(),
        _pentest_lab_module(),
        _pwn_lab_module(),
        _ad_attack_lab_module(),
        _forensics_lab_module(),
    ]
    total_challenges = sum(m["challenge_count"] for m in modules)
    return {
        "modules": modules,
        "learning_path": LEARNING_PATH,
        "safety_notice": SAFETY_NOTICE,
        "total_challenge_count": total_challenges,
    }
