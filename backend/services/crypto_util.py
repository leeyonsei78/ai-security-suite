"""장비 등록 화면(신규)에서 입력받는 접속 비밀번호를 저장 시점에 암호화하기 위한
최소 유틸리티. App 19(시크릿 스캐너)·App 23/25의 "자격증명은 저장하지 않고 매 요청
전달만 함" 원칙과 달리, 이 기능은 스케줄러가 사용자 개입 없이 주기적으로 재접속해야
하므로 저장이 불가피하다 — 그 대신 평문으로 두지 않고 대칭키(Fernet)로 암호화해
`backend/data/`(gitignore 대상, history.db와 동일한 취급)에 보관한다.

키 파일이 없으면 최초 호출 시 자동 생성한다 — 이 프로젝트의 다른 로컬 전용 런타임
데이터(history.db)와 같은 패턴. 키 파일을 잃어버리면 그때까지 저장된 비밀번호는
복호화할 수 없게 되므로(장비를 재등록해야 함), 백업 대상이 아닌 로컬 개발 편의
장치임을 전제한다.
"""

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "device_secret.key"
_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load_key() -> bytes:
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)
    return key


_fernet = Fernet(_load_key())


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    try:
        return _fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return ""
