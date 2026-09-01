"""n8n 등 외부 자동화 도구가 백엔드 API를 직접 호출할 수 있게 되면서 추가한 선택적
API 키 검증. `API_KEY` 환경변수가 없으면 지금까지와 동일하게 인증 없이 전부 열려있고
(다른 앱들의 Mock/Live 같은 opt-in 패턴), 설정하면 `/api/*` 요청에 `X-API-Key` 헤더가
일치해야 통과한다. 프론트엔드는 이 헤더를 보내지 않으므로, API_KEY를 켜는 경우
프론트도 동작하려면 별도 프록시/헤더 주입이 필요함을 문서에서 함께 안내한다."""

import os

from fastapi import Header, HTTPException, status

API_KEY = os.getenv("API_KEY", "").strip()
IS_AUTH_ENABLED = bool(API_KEY)


async def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    if not IS_AUTH_ENABLED:
        return
    if x_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
