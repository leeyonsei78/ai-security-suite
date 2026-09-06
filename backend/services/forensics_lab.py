"""포렌식 실습·분석 센터(App 25)의 "실습 랩" 탭 콘텐츠.

App 9(Pwn/Reverse 실습실)·App 10(Web CTF 아레나)와 같은 철학 — 텍스트 설명이 아니라
실제로 유효한 파일을 다운로드해 진짜 도구로 분석하는 CTF식 실습. 다만 Pwn/Reverse처럼
Docker/WSL 같은 무거운 환경이 필요 없도록, 이미 이 프로젝트가 요구하는 Python 3.11+
표준 라이브러리(sqlite3, zipfile, struct)만으로 "실제로 유효한" 파일 포맷을 만든다:

  1. browser-history: 진짜 SQLite DB 파일 (sqlite3.Connection.serialize() 사용,
     Python 3.11+ 표준 라이브러리 — DB Browser for SQLite나 sqlite3 CLI로 그대로 열림)
  2. pcap-exfil: 진짜 pcap 파일 (Ethernet/IP/TCP 헤더를 직접 struct로 조립하고 IP/TCP
     체크섬까지 정확히 계산 — Wireshark에서 체크섬 오류 경고 없이 깨끗하게 열림)
  3. file-carving: 진짜 ZIP 아카이브가 쓰레기 바이트 뒤에 이어붙은 바이너리 —
     ZIP은 파일 끝의 중앙 디렉토리 레코드를 기준으로 읽으므로 확장자만 .zip으로
     바꾸면 대부분의 압축 프로그램이 그대로 열 수 있다(설치 없이 푸는 최소 경로),
     binwalk 등 정식 카빙 도구 사용법도 함께 안내한다.

세 파일 생성 함수는 스크래치패드에서 실제로 실행해 (a) sqlite3 CLI/모듈로 재조회,
(b) 수동 pcap 파서로 페이로드 재추출, (c) zipfile로 재오픈 — 세 가지 모두 실제로
검증한 뒤 이 모듈로 옮겼다. FLAGS는 CHALLENGES/아티팩트 바이트와 분리해 두고
/verify 엔드포인트의 서버 측 비교에만 사용한다(Pwn Lab과 동일한 원칙).
"""

import base64
import socket
import sqlite3
import struct
import time
import zipfile
import io

LAB_SETUP = {
    "title": "실습 전 확인 — 무거운 환경 설정이 필요 없습니다",
    "intro": (
        "Pwn/Reverse 실습실과 달리 Docker나 WSL이 필요 없습니다. 세 챌린지 모두 "
        "Windows에 이미 있는 도구(Python)나 가벼운 무료 도구 하나만으로 풀 수 있고, "
        "각 챌린지마다 '설치 없이 푸는 법'도 함께 안내합니다."
    ),
    "tools": [
        {
            "name": "Python 3 (이미 설치되어 있음)",
            "why": "브라우저 히스토리(SQLite) 챌린지 — sqlite3 모듈이 표준 라이브러리에 내장되어 있어 추가 설치가 필요 없습니다.",
            "install": "이 프로젝트의 백엔드를 실행 중이라면 이미 설치돼 있습니다.",
        },
        {
            "name": "Wireshark (권장, 선택)",
            "why": "네트워크 트래픽(pcap) 챌린지 — 정식으로는 패킷을 열어 프로토콜별로 분석하는 것이 정석입니다.",
            "install": "wireshark.org 에서 설치. 설치하지 않고 풀고 싶다면 챌린지 안내의 'PowerShell만으로 푸는 법'을 참고하세요.",
        },
        {
            "name": "압축 프로그램 (Windows 기본 내장) 또는 binwalk (선택)",
            "why": "파일 카빙 챌린지 — 확장자를 .zip으로 바꾸면 Windows 탐색기가 기본으로 열 수 있습니다.",
            "install": "정석적인 카빙 도구를 연습하려면 binwalk(pip install binwalk, 또는 WSL 안에서 apt install binwalk)를 추가로 써볼 수 있습니다.",
        },
    ],
}


# ── 1. 브라우저 히스토리 (SQLite) ──────────────────────────────────────────

_BROWSER_HISTORY_FLAG = "FORENSIC{h1dd3n_1n_ur1_qu3ry}"


def _build_browser_history_db() -> bytes:
    token = base64.b64encode(_BROWSER_HISTORY_FLAG.encode()).decode()
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 1,
            last_visit_time TEXT
        )
        """
    )
    rows = [
        ("https://mail.google.com/mail/u/0/", "Gmail", 42, "2026-08-30 09:12:01"),
        ("https://github.com/notifications", "Notifications - GitHub", 18, "2026-08-30 09:15:44"),
        ("https://www.notion.so/workspace", "Notion", 7, "2026-08-30 10:02:12"),
        (f"http://cdn-assets-update.example.net/sync?client=win11&token={token}", "Sync in progress...", 1, "2026-08-30 10:03:55"),
        ("https://outlook.office.com/mail/", "Outlook", 25, "2026-08-30 10:20:03"),
        ("https://www.google.com/search?q=quarterly+report+template", "quarterly report template - Google Search", 3, "2026-08-30 11:05:19"),
        ("https://slack.com/workspace/general", "general | Slack", 55, "2026-08-30 11:30:44"),
        ("https://drive.google.com/drive/my-drive", "My Drive - Google Drive", 12, "2026-08-30 13:44:02"),
    ]
    conn.executemany(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)", rows
    )
    conn.commit()
    data = bytes(conn.serialize())
    conn.close()
    return data


# ── 2. 네트워크 트래픽 (pcap) ──────────────────────────────────────────────

_PCAP_FLAG = "FORENSIC{pl41nt3xt_ftp_cr3ds_1n_pcap}"


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload: bytes) -> bytes:
    offset_reserved = 5 << 4
    window = 64240
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_reserved, flags, window, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(header) + len(payload))
    checksum = _ip_checksum(pseudo + header + payload)
    header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, 0)
    return header + payload


def _build_ip(src_ip, dst_ip, ident, tcp_segment: bytes) -> bytes:
    total_len = 20 + len(tcp_segment)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, 6, 0,
                          socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    checksum = _ip_checksum(header)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000, 64, 6, checksum,
                          socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return header + tcp_segment


def _eth_frame(dst_mac: str, src_mac: str, payload: bytes) -> bytes:
    return (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", 0x0800)
        + payload
    )


def _pcap_global_header() -> bytes:
    return struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcap_record(ts: float, data: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("!IIII", sec, usec, len(data), len(data)) + data


def _build_pcap() -> bytes:
    client_mac, server_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    client_ip, server_ip = "192.168.56.101", "203.0.113.50"
    b64flag = base64.b64encode(_PCAP_FLAG.encode()).decode()
    t0 = time.time()
    packets = []

    ftp_user = b"USER contractor_backup\r\n"
    ftp_resp = b"331 Password required for contractor_backup.\r\n"
    ftp_pass = b"PASS Summer2026!\r\n"
    seq_c, seq_s = 1000, 5000

    tcp = _build_tcp(client_ip, server_ip, 51410, 21, seq_c, seq_s, 0x18, ftp_user)
    packets.append((t0 + 0.10, _eth_frame(server_mac, client_mac, _build_ip(client_ip, server_ip, 1, tcp))))
    seq_c += len(ftp_user)

    tcp = _build_tcp(server_ip, client_ip, 21, 51410, seq_s, seq_c, 0x18, ftp_resp)
    packets.append((t0 + 0.15, _eth_frame(client_mac, server_mac, _build_ip(server_ip, client_ip, 1, tcp))))
    seq_s += len(ftp_resp)

    tcp = _build_tcp(client_ip, server_ip, 51410, 21, seq_c, seq_s, 0x18, ftp_pass)
    packets.append((t0 + 0.20, _eth_frame(server_mac, client_mac, _build_ip(client_ip, server_ip, 2, tcp))))

    http_req = b"GET /status?check=1 HTTP/1.1\r\nHost: cdn-telemetry.example.net\r\nUser-Agent: curl/8.4\r\n\r\n"
    http_resp = (
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Debug-Flag: " + b64flag.encode()
        + b"\r\nContent-Length: 2\r\n\r\nOK"
    )
    seq_c2, seq_s2 = 2000, 8000
    tcp = _build_tcp(client_ip, server_ip, 51512, 80, seq_c2, seq_s2, 0x18, http_req)
    packets.append((t0 + 0.30, _eth_frame(server_mac, client_mac, _build_ip(client_ip, server_ip, 3, tcp))))
    seq_c2 += len(http_req)

    tcp = _build_tcp(server_ip, client_ip, 80, 51512, seq_s2, seq_c2, 0x18, http_resp)
    packets.append((t0 + 0.35, _eth_frame(client_mac, server_mac, _build_ip(server_ip, client_ip, 2, tcp))))

    out = _pcap_global_header()
    for ts, frame in packets:
        out += _pcap_record(ts, frame)
    return out


# ── 3. 파일 카빙 ────────────────────────────────────────────────────────

_CARVING_FLAG = "FORENSIC{c4rv3d_th3_h1dd3n_z1p}"


def _build_carving_blob() -> bytes:
    filler = bytes([0x00, 0x00, 0x00, 0x00]) + b"CORRUPTED_SECTOR_DATA_" * 20 + bytes(range(256)) * 4
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("flag.txt", _CARVING_FLAG + "\n")
        zf.writestr("readme.txt", "If you can read this, you successfully carved the embedded ZIP archive.\n")
    return filler + zip_buf.getvalue()


_ARTIFACTS = {
    "forensics-browser-history": _build_browser_history_db(),
    "forensics-pcap-exfil": _build_pcap(),
    "forensics-file-carving": _build_carving_blob(),
}

FLAGS = {
    "forensics-browser-history": _BROWSER_HISTORY_FLAG,
    "forensics-pcap-exfil": _PCAP_FLAG,
    "forensics-file-carving": _CARVING_FLAG,
}

CHALLENGES = [
    {
        "id": "forensics-browser-history",
        "category": "forensics",
        "title": "브라우저 히스토리에서 유출 흔적 찾기",
        "difficulty": "입문",
        "tool_focus": "SQLite",
        "download_filename": "history.sqlite",
        "media_type": "application/octet-stream",
        "situation": (
            "IT 부서로부터 '한 직원의 PC가 낯선 외부 서버와 통신한 것 같다'는 제보를 받았습니다. "
            "해당 PC에서 수집한 브라우저 히스토리 데이터베이스(history.sqlite)가 유일한 단서입니다. "
            "실제 Chrome/Edge의 히스토리 DB와 동일하게 urls 테이블 구조로 되어 있습니다."
        ),
        "objective": "SQLite DB의 urls 테이블을 조회해 의심스러운 방문 기록을 찾고, 그 안에 인코딩되어 숨겨진 flag를 복원하세요.",
        "learning_point": "브라우저 히스토리는 실제 침해사고 조사에서 가장 먼저 확인하는 아티팩트 중 하나입니다 — 피싱 링크 클릭, C2 체크인, 데이터 유출 URL이 그대로 남습니다. 도구 설치 없이 sqlite3 표준 라이브러리만으로 DB를 직접 조회하는 법을 익힙니다.",
        "analysis_steps": [
            "설치 없이 조회하기: python -c \"import sqlite3; [print(r) for r in sqlite3.connect('history.sqlite').execute('SELECT url, title, visit_count FROM urls')]\"",
            "GUI로 보고 싶다면 DB Browser for SQLite(sqlitebrowser.org, 무료)를 설치해 파일을 열고 Browse Data 탭에서 urls 테이블을 확인하세요.",
            "정상적인 사이트(Gmail·GitHub·Slack 등) 사이에서 낯선 도메인 + 긴 쿼리 파라미터(token=...)가 붙은 URL을 찾으세요.",
            "그 token 값을 Base64로 디코딩하면 flag가 나옵니다: python -c \"import base64; print(base64.b64decode('여기에_토큰').decode())\"",
        ],
        "hints": [
            "정상적인 사이트 사이에 딱 하나, 처음 보는 도메인(cdn-assets-update.example.net)이 섞여 있습니다.",
            "그 URL의 쿼리 파라미터 이름은 token= 입니다.",
            "Base64로 디코딩하면 FORENSIC{...} 형식의 flag가 나옵니다.",
        ],
        "solution": (
            "1) sqlite3 모듈로 urls 테이블을 조회하면 8개 행 중 하나가 "
            "http://cdn-assets-update.example.net/sync?client=win11&token=... 형태입니다.\n"
            "2) 다른 방문 기록은 실제 존재하는 서비스(Gmail, GitHub, Notion 등)인데 이 도메인만 "
            "정상 서비스명과 무관한 임의 문자열이라는 점이 의심 신호입니다.\n"
            "3) token 값을 Base64 디코딩하면 flag가 그대로 복원됩니다."
        ),
    },
    {
        "id": "forensics-pcap-exfil",
        "category": "forensics",
        "title": "패킷 캡처 속 평문 계정정보와 데이터 유출",
        "difficulty": "중급",
        "tool_focus": "Wireshark / 패킷 분석",
        "download_filename": "capture.pcap",
        "media_type": "application/vnd.tcpdump.pcap",
        "situation": (
            "네트워크 IDS가 특정 시간대에 사내 PC 한 대에서 나간 트래픽을 캡처해 증거로 넘겼습니다"
            "(capture.pcap). 이 안에는 서로 다른 두 가지 문제가 섞여 있습니다 — 평문으로 전송된 "
            "계정정보, 그리고 데이터 유출 흔적입니다."
        ),
        "objective": "패킷 캡처를 분석해 (1) 평문 FTP 계정정보를 찾고 (2) HTTP 응답 헤더에 숨겨진 유출 데이터를 Base64 디코딩해 flag를 복원하세요.",
        "learning_point": "네트워크 캡처는 사고 대응에서 '무엇이 실제로 전송됐는지'를 확인할 수 있는 유일한 증거인 경우가 많습니다. 평문 프로토콜(FTP)이 왜 위험한지, 그리고 정상적인 응답처럼 보이는 HTTP 헤더에도 데이터가 숨겨질 수 있다는 점을 직접 확인합니다.",
        "analysis_steps": [
            "Wireshark로 capture.pcap을 열고 필터 창에 ftp 를 입력해 USER/PASS 명령을 확인합니다.",
            "필터를 http 로 바꿔 응답 패킷을 펼치고 HTTP 헤더의 X-Debug-Flag 값을 확인합니다.",
            "설치 없이 푸는 법(Windows): PowerShell에서 Select-String -Path capture.pcap -Pattern 'X-Debug-Flag|PASS' -Encoding ascii — pcap은 패킷 헤더 외 페이로드가 원문 그대로 저장되어 있어 평문 문자열은 이렇게도 찾을 수 있습니다.",
            "찾은 X-Debug-Flag 값을 Base64 디코딩하세요.",
        ],
        "hints": [
            "포트 21(FTP)과 포트 80(HTTP) 트래픽이 함께 들어 있습니다.",
            "굳이 Wireshark를 설치하지 않아도, pcap 파일도 결국 바이트의 나열이라 평문 문자열은 grep/Select-String으로 찾을 수 있습니다.",
            "flag는 HTTP 응답의 X-Debug-Flag 헤더에 Base64로 인코딩되어 있습니다.",
        ],
        "solution": (
            "1) FTP 세션(포트 21)에서 'USER contractor_backup' / 'PASS Summer2026!'이 평문으로 전송된 "
            "것을 확인할 수 있습니다 — 실제로도 FTP는 기본적으로 암호화되지 않아 이런 노출이 흔합니다.\n"
            "2) 별도의 HTTP 세션(포트 80)에서 서버 응답에 X-Debug-Flag 헤더가 포함되어 있고, "
            "그 값이 Base64로 인코딩된 flag입니다.\n"
            "3) 두 문제는 서로 다른 취약점 유형입니다 — 하나는 '평문 프로토콜 사용'(FTP), "
            "다른 하나는 '디버그/내부 정보가 응답 헤더로 노출'(X-Debug-Flag)."
        ),
    },
    {
        "id": "forensics-file-carving",
        "category": "forensics",
        "title": "파일 카빙으로 숨겨진 압축파일 복구하기",
        "difficulty": "입문~중급",
        "tool_focus": "File Carving / binwalk",
        "download_filename": "evidence.bin",
        "media_type": "application/octet-stream",
        "situation": (
            "디스크 이미지의 미할당 영역에서 복구한 것으로 추정되는 바이너리 조각(evidence.bin)이 "
            "있습니다. 파일 시그니처만 보면 손상된 것처럼 보이지만, 실제로는 뒷부분에 다른 파일이 "
            "이어붙어 숨겨져 있습니다."
        ),
        "objective": "파일 카빙(file carving) 기법으로 숨겨진 파일을 복구해 flag를 찾으세요.",
        "learning_point": "삭제되거나 손상된 것처럼 보이는 파일도 파일 포맷의 구조(ZIP은 파일 끝의 중앙 디렉토리를 기준으로 읽음)를 이해하면 복구할 수 있습니다 — 실제 디스크 포렌식에서 미할당 영역 복구에 쓰이는 핵심 기법입니다.",
        "analysis_steps": [
            "가장 간단한 방법: evidence.bin의 확장자를 evidence.zip으로 바꾼 뒤 그대로 열어보세요 — ZIP은 파일 끝의 '중앙 디렉토리'를 기준으로 읽기 때문에 앞에 다른 데이터가 붙어 있어도 대부분의 압축 프로그램이 무시하고 열 수 있습니다.",
            "정석적인 방법: binwalk evidence.bin 으로 파일 내부에 숨겨진 시그니처(PK\\x03\\x04 = ZIP)의 위치를 찾습니다.",
            "binwalk -e evidence.bin 으로 자동 추출하거나, 찾은 오프셋부터 파일 끝까지를 별도 파일로 잘라내 복구합니다.",
            "복구한 zip을 열어 flag.txt를 확인하세요.",
        ],
        "hints": [
            "파일 앞부분은 의도적으로 채워 넣은 쓰레기 데이터입니다 — 진짜 파일은 뒤쪽에 있습니다.",
            "ZIP 파일 시그니처는 PK로 시작합니다 (hex로 50 4B 03 04).",
            "확장자만 .zip으로 바꿔서 여는 게 가장 빠른 방법입니다 — 진짜 포렌식에서는 정확한 오프셋을 찾아 정식으로 카빙합니다.",
        ],
        "solution": (
            "1) evidence.bin 앞부분은 의미 없는 채움 데이터이고, 뒷부분에 정상적인 ZIP 아카이브 "
            "(로컬 파일 헤더 시그니처 PK\\x03\\x04로 시작)가 그대로 이어붙어 있습니다.\n"
            "2) ZIP 포맷은 파서가 파일 끝의 EOCD(End Of Central Directory) 레코드부터 역으로 읽기 "
            "때문에, 앞의 쓰레기 데이터가 있어도 확장자만 .zip으로 바꾸면 대부분의 도구가 정상적으로 "
            "엽니다 — 실제 사고 대응에서도 이런 '뒤에 이어붙이기(append)' 스테가노그래피가 흔히 쓰입니다.\n"
            "3) 압축을 풀면 flag.txt에 flag가 그대로 들어 있습니다."
        ),
    },
]


def get_challenge(challenge_id: str) -> dict | None:
    return next((c for c in CHALLENGES if c["id"] == challenge_id), None)


def get_artifact_bytes(challenge_id: str) -> bytes | None:
    return _ARTIFACTS.get(challenge_id)
