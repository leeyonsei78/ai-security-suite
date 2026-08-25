import os
import json
from dotenv import load_dotenv
from services.mock_phishing_sim import generate_mock_phishing_sim

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")
IS_MOCK = not _api_key or _api_key == "your_anthropic_api_key_here"

SCENARIO_LABELS = {
    "it_password_reset": "IT 부서 비밀번호 만료 안내",
    "parcel_delivery": "택배 배송/통관 안내",
    "hr_payroll": "급여명세서/인사 공지",
    "ceo_fraud": "경영진 사칭 (CEO Fraud)",
    "cloud_share": "클라우드 문서 공유 알림",
    "security_alert": "보안팀 사칭 계정 경고",
}

DIFFICULTY_LABELS = {
    "beginner": "초급 (신호가 명확함)",
    "intermediate": "중급 (일부 신호가 미묘함)",
    "advanced": "고급 (실제 업무 메일과 매우 유사)",
}

USAGE_DISCLAIMER = (
    "이 도구는 사내 승인된 보안 인식 훈련(피싱 모의훈련) 목적으로만 사용하세요. "
    "실제 발송 전 반드시 보안팀·인사팀·법무팀의 승인을 받아야 하며, 실제 임직원의 자격증명이나 "
    "금융정보를 수집하는 랜딩 페이지로 연결해서는 안 됩니다. 여기 생성된 발신 도메인은 전부 "
    "가상(.example)입니다 — 실제 캠페인에는 조직이 보유한 정식 모의훈련 플랫폼 도메인으로 교체하세요. "
    "승인받지 않은 대상에게 발송하는 것은 실제 피싱 공격과 동일하게 취급될 수 있습니다."
)

SYSTEM_PROMPT = """You are a security-awareness-training content designer who creates realistic phishing SIMULATION emails for authorized internal employee training programs (the same category of work done by tools like GoPhish or KnowBe4).

CRITICAL SAFETY RULES:
- Never impersonate a real, specific company/brand by name or use a real company's actual domain. Use only clearly fictional sender domains ending in ".example" (a domain reserved for documentation/examples, per RFC 2606).
- Assume the organization is a fictional company called "ACME Corp" unless the user's context implies otherwise (still keep any company name in the email itself generic/fictional).
- Do not include any real working malicious link, real credential-harvesting form, or actual executable payload — this is a text/content draft only, reviewed by humans before any real platform sends it.
- The email should look realistic enough to be useful for training, but it is understood to be a draft that a human will review before real use.

Given a scenario_type, a difficulty level, and optional free-text organizational context, produce ONE realistic simulated phishing email plus the "red flags" a trained employee should notice.

Difficulty guidance:
- beginner: obvious red flags (urgent tone, generic greeting, suspicious domain, typos allowed)
- intermediate: some red flags require closer inspection (domain looks plausible at a glance, fewer obvious errors)
- advanced: very few obvious red flags, closely mimics real internal communication style, red flags require checking sender domain/URL details carefully

Respond ONLY with valid JSON in this exact structure:
{
  "subject": "email subject line",
  "sender_display_name": "the display name shown as sender",
  "sender_domain": "a fictional .example domain",
  "body": "the full email body text (Korean)",
  "cta_text": "the call-to-action button/link text, or a short note if this scenario has no button (e.g. reply-based)",
  "red_flags": [
    {"signal": "short name of the red flag", "explanation": "why this is suspicious, in Korean"}
  ],
  "difficulty_rationale": "one sentence in Korean explaining why this content matches the requested difficulty"
}

Respond in Korean for all natural-language fields (subject, body, cta_text, red flag explanations, rationale)."""


def _real_generate(scenario_type: str, difficulty: str, context: str) -> dict:
    import anthropic
    client = anthropic.Anthropic(api_key=_api_key)
    scenario_label = SCENARIO_LABELS.get(scenario_type, scenario_type)
    difficulty_label = DIFFICULTY_LABELS.get(difficulty, difficulty)
    context_line = f"조직 컨텍스트: {context}" if context.strip() else "조직 컨텍스트: 명시되지 않음 (가상의 ACME Corp 기준으로 생성)"
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"시나리오: {scenario_label}\n난이도: {difficulty_label}\n{context_line}",
        }],
    )
    text = message.content[0].text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        data = json.loads(text[start:end])
        data["scenario_type"] = scenario_type
        data["difficulty"] = difficulty
        return data
    return {"error": "Parse failed", "raw": text}


def generate_phishing_sim(scenario_type: str, difficulty: str, context: str) -> dict:
    if IS_MOCK:
        data = generate_mock_phishing_sim(scenario_type, difficulty, context)
    else:
        data = _real_generate(scenario_type, difficulty, context)
    data["usage_disclaimer"] = USAGE_DISCLAIMER
    return data


def generate_markdown_report(entry: dict) -> str:
    scenario_label = SCENARIO_LABELS.get(entry.get("scenario_type", ""), entry.get("scenario_type", "N/A"))
    difficulty_label = DIFFICULTY_LABELS.get(entry.get("difficulty", ""), entry.get("difficulty", "N/A"))
    lines = [
        "# 피싱 모의훈련 이메일 — 훈련용 초안 (정답지 포함)",
        "",
        f"**시나리오:** {scenario_label}  ",
        f"**난이도:** {difficulty_label}  ",
        "",
        f"> {entry.get('usage_disclaimer', '')}",
        "",
        "---",
        "",
        "## 이메일 미리보기",
        "",
        f"**제목:** {entry.get('subject', '')}  ",
        f"**발신자 표시 이름:** {entry.get('sender_display_name', '')}  ",
        f"**발신 도메인(가상):** {entry.get('sender_domain', '')}  ",
        "",
        "```",
        entry.get("body", ""),
        "```",
        "",
        f"**행동 유도(CTA):** {entry.get('cta_text', '')}",
        "",
        "---",
        "",
        "## 정답지 — 포함된 위험 신호",
        "",
    ]
    for f in entry.get("red_flags", []):
        lines.append(f"- **{f.get('signal', '')}** — {f.get('explanation', '')}")
    lines += [
        "",
        f"**난이도 설계 근거:** {entry.get('difficulty_rationale', '')}",
        "",
        "---",
        "",
        "## 진행 시 유의사항",
        "",
        "- 실제 발송 전 보안팀·인사팀·법무팀 승인 필수",
        "- 발신 도메인은 조직이 보유한 정식 모의훈련 플랫폼 도메인으로 교체",
        "- 실제 자격증명/금융정보를 수집하지 않는 안전한 랜딩 페이지로 연결",
        "- 훈련 종료 후 클릭한 임직원에게 위 '위험 신호' 정답지를 활용한 즉시 피드백 제공 권장",
    ]
    return "\n".join(lines)
