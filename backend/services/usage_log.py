"""Claude API 호출의 response.usage를 JSONL로 기록하는 공용 모듈.

비용 최적화(프롬프트 캐싱, 모델 전환) 효과를 "추정"이 아니라 "실측"으로 검증하기 위해
도입 — Admin API 키가 없는 개인/소규모 계정에서도 이 로그만으로 캐시 적중률
(cache_read_input_tokens 비중)과 앱별 토큰 소비량을 직접 계산할 수 있다.
원본 프롬프트/응답 내용은 저장하지 않고 토큰 수치만 남긴다(App19 시크릿 스캐너의
"원본 미저장" 원칙과 동일 방향).
"""
import json
import time
from pathlib import Path

_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "usage_log.jsonl"


def log_usage(app: str, usage, model: str = "") -> None:
    """usage: anthropic Message.usage 객체(input_tokens/output_tokens/
    cache_creation_input_tokens/cache_read_input_tokens 속성을 가짐).
    로깅 실패가 실제 분석 흐름을 막으면 안 되므로 예외는 삼킨다."""
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": time.time(),
            "app": app,
            "model": model,
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", None),
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
        }
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass
