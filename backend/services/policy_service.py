import os
import json
from dotenv import load_dotenv
from services.mock_policy import generate_mock_policy
from services.policy_offline_engine import generate_offline
from services import mode_manager, local_llm_client

load_dotenv()

_api_key = os.getenv("ANTHROPIC_API_KEY", "")

_ENV_LABELS = {
    "web_server": "인터넷에 공개된 웹 서버(리버스 프록시+WAS)",
    "cloud": "퍼블릭 클라우드 인프라 (AWS/Azure/GCP류)",
    "internal_network": "사내 업무망",
    "container": "Docker/Kubernetes 컨테이너 환경",
    "database": "데이터베이스 서버",
}

SYSTEM_PROMPT = """You are a senior security architect who drafts firewall rule sets and security policy documents for real environments described by the user.

Given an environment type, a free-text description of the system (services, ports, data handled, current issues), and optionally a list of compliance frameworks the organization must satisfy, produce a concrete draft.

Use these policy category names when applicable (for consistency, reuse these exact Korean names rather than inventing new ones unless truly needed): "접근 통제", "네트워크 분리", "데이터 보호", "로깅 및 모니터링", "패치 및 취약점 관리", "사고 대응", "계정 및 인증 관리", "백업 및 복구", "이미지 및 공급망 보안", "런타임 격리".

Respond ONLY with valid JSON in this exact structure:
{
  "summary": "one-paragraph overview of the environment's security posture and main concerns",
  "firewall_rules": [
    {"id": "FW-001", "action": "ALLOW|DENY", "protocol": "TCP|UDP|ICMP|ANY", "port": "e.g. 443 or 3306/5432", "source": "CIDR or named zone", "destination": "CIDR or named zone", "description": "why this rule exists"}
  ],
  "policies": [
    {
      "category": "one of the category names above (or a closely related one)",
      "title": "short policy title",
      "rules": ["concrete, actionable policy statements"],
      "rationale": "why this matters for this specific environment"
    }
  ],
  "risk_notes": ["specific warnings based on risky details explicitly mentioned in the user's description, e.g. an exposed management port or default credentials — empty array if nothing stands out"],
  "compliance_mapping": [
    {"framework": "name of a requested compliance framework", "items": ["specific requirement -> which policy/rule addresses it"]}
  ]
}

Generate 4-6 firewall rules and 4-7 policy sections covering the categories most relevant to the described environment.
Only include compliance_mapping entries for frameworks explicitly requested by the user (if none requested, you may omit compliance_mapping or return an empty array).
Respond in Korean for all natural-language fields."""


def _real_generate(environment_type: str, compliance: list[str], description: str, backend: str = "cloud") -> dict:
    label = _ENV_LABELS.get(environment_type, environment_type)
    compliance_line = f"적용 대상 컴플라이언스: {', '.join(compliance)}" if compliance else "적용 대상 컴플라이언스: 명시되지 않음 (일반적인 보안 모범사례 기준으로 작성)"
    user_prompt = f"환경 유형: {label}\n{compliance_line}\n\n환경 설명:\n{description}"

    if backend == "local":
        text = local_llm_client.call_local_llm(SYSTEM_PROMPT, user_prompt, max_tokens=3072)
    else:
        import anthropic
        client = anthropic.Anthropic(api_key=_api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=3072,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text

    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return json.loads(text[start:end])
    return {"error": "Parse failed", "raw": text}


# 우선순위와 검증 방법은 카테고리 기반으로 일괄 부여한다 — 5개 mock 템플릿과 실시간 생성 결과 모두
# 개별 데이터 수정 없이 일관된 우선순위/검증 가이드를 갖도록 하기 위함 (vulnerability_service._enrich와 동일한 방식).
_PRIORITY_RANK = {
    "접근 통제": (1, "즉시 (P0)", "관리자·인증 우회는 가장 흔하고 즉각적인 침해 경로이므로 최우선으로 조치합니다."),
    "계정 및 인증 관리": (1, "즉시 (P0)", "과도한 권한이나 취약한 인증은 침해 시 피해 범위를 곧바로 키웁니다."),
    "네트워크 분리": (2, "즉시 (P0)", "불필요하게 노출된 경로를 막는 것은 비용 대비 효과가 가장 큰 조치입니다."),
    "데이터 보호": (3, "단기 (P1)", "접근 통제가 뚫리더라도 실제 피해를 최소화하는 최후 방어선입니다."),
    "로깅 및 모니터링": (4, "단기 (P1)", "위 조치들이 실제로 작동하는지, 침해 시 이를 알아챌 수 있는지 확인하는 데 필수적입니다."),
    "이미지 및 공급망 보안": (4, "단기 (P1)", "취약한 이미지는 배포 즉시 공격 표면이 되므로 빌드 단계에서 조기 차단이 필요합니다."),
    "런타임 격리": (4, "단기 (P1)", "컨테이너 탈출은 클러스터 전체 장악으로 이어질 수 있어 접근 통제 다음으로 시급합니다."),
    "패치 및 취약점 관리": (5, "중장기 (P2)", "지속적으로 관리해야 할 항목이나, 알려진 미패치 취약점이 없다면 즉각적 침해 경로는 아닙니다."),
    "사고 대응": (6, "중장기 (P2)", "예방 조치들이 어느 정도 갖춰진 이후 체계화하는 것이 효율적입니다."),
    "백업 및 복구": (7, "중장기 (P2)", "예방이 아닌 최후의 안전망이므로 병행 준비하되 시급성은 상대적으로 낮습니다."),
}
_DEFAULT_PRIORITY = (8, "중장기 (P2)", "다른 우선 조치들과 함께 계획적으로 반영하세요.")

_VALIDATION_BY_CATEGORY = {
    "접근 통제": ("테스트 계정으로 '허용되어야 할 접근'과 '차단되어야 할 접근'을 모두 실제로 시도하세요.", "예: VPN 없이 SSH 접속 시도 → 연결 거부 확인 / 일반 계정으로 관리자 기능 접근 시도 → 거부 확인"),
    "계정 및 인증 관리": ("테스트 계정으로 부여된 권한 범위를 벗어난 작업을 시도해 실제로 차단되는지 확인하세요.", "예: 애플리케이션 DB 계정으로 DROP TABLE 시도 → 권한 오류 확인"),
    "네트워크 분리": ("nmap 등으로 실제 포트 스캔을 수행해 의도한 포트만 응답하고 나머지는 차단되는지 확인하세요.", "nmap -p- <대상 IP> (닫혀야 할 포트가 filtered/closed로 나오는지 확인)"),
    "데이터 보호": ("TLS 설정은 openssl로 실제 협상 버전을 확인하고, 저장 데이터 암호화는 DB/스토리지 콘솔에서 직접 상태를 조회하세요.", "openssl s_client -connect <host>:443 -tls1 (구버전 TLS가 거부되는지 확인)"),
    "로깅 및 모니터링": ("의도적으로 이벤트를 발생시켜 로그가 실제로 기록되고 알림까지 도착하는지 end-to-end로 확인하세요.", "예: 잘못된 비밀번호로 5회 로그인 시도 → 알림 채널(Slack/이메일)에 실제 알림 도착 확인"),
    "패치 및 취약점 관리": ("패치 적용 후 실제 버전을 확인하고, 취약점 스캐너로 재스캔해 해당 CVE가 더 이상 탐지되지 않는지 확인하세요.", "패치 전/후 취약점 스캐너 결과 비교"),
    "사고 대응": ("테이블탑 훈련(모의 시나리오로 대응 절차를 실제로 따라가보는 훈련)을 정기적으로 실시해 절차의 공백을 미리 찾으세요.", "분기 1회 모의 침해 시나리오로 팀 훈련 + 연락체계 실제 응답 여부 점검"),
    "백업 및 복구": ("백업이 '있다'는 것과 '복구된다'는 것은 다릅니다. 실제로 백업에서 시스템을 복구해보는 훈련을 정기적으로 수행하세요.", "분기 1회 실제 복구 테스트 + 복구 소요시간(RTO) 측정"),
    "이미지 및 공급망 보안": ("CI 파이프라인에서 의도적으로 취약한 이미지를 빌드해 배포가 실제로 차단되는지 확인하세요.", "알려진 CVE가 있는 구버전 베이스 이미지로 빌드 → 파이프라인이 배포를 막는지 확인"),
    "런타임 격리": ("컨테이너 내부에서 실제로 권한 상승이나 호스트 접근을 시도해 제한되는지 확인하세요.", "컨테이너 안에서 root 권한 명령/호스트 파일시스템 접근 시도 → 거부 확인"),
}
_DEFAULT_VALIDATION = ("정책 적용 전 테스트 환경에서 먼저 검증하고, 적용 후에도 정기적으로 재점검하세요.", "")

_FIREWALL_VALIDATION_TIP = (
    "방화벽 규칙은 운영 반영 전 스테이징 환경에 먼저 적용하세요. 반영 후에는 nmap -p- <대상 IP>로 "
    "의도한 포트만 열려 있는지, curl/telnet으로 차단 대상 포트가 실제로 거부되는지 직접 확인하고, "
    "허용되어야 할 정상 트래픽 경로도 함께 테스트해 과차단이 없는지 확인하세요."
)


def _enrich(data: dict) -> dict:
    policies = data.get("policies", [])
    ranked = []
    for p in policies:
        category = p.get("category", "")
        rank_key = next((k for k in _PRIORITY_RANK if k in category or category in k), None)
        sort_order, level, reason = _PRIORITY_RANK.get(rank_key, _DEFAULT_PRIORITY)
        val_key = next((k for k in _VALIDATION_BY_CATEGORY if k in category or category in k), None)
        method, example = _VALIDATION_BY_CATEGORY.get(val_key, _DEFAULT_VALIDATION)
        p["validation"] = {"method": method, "example": example}
        ranked.append({"category": category, "title": p.get("title", ""), "level": level, "reason": reason, "_sort": sort_order})

    ranked.sort(key=lambda x: x["_sort"])
    for i, r in enumerate(ranked, start=1):
        r["rank"] = i
        del r["_sort"]

    data["priority_order"] = ranked
    data["firewall_validation_tip"] = _FIREWALL_VALIDATION_TIP
    data.setdefault("risk_notes", [])
    data.setdefault("compliance_mapping", [])
    return data


async def generate_policy(environment_type: str, compliance: list[str], description: str) -> dict:
    mode = await mode_manager.get_ai_mode()

    if mode == "mock":
        data = generate_mock_policy(environment_type, compliance, description)
    elif mode in ("local", "cloud"):
        try:
            data = _real_generate(environment_type, compliance, description, backend=mode)
        except Exception as e:
            data = generate_offline(environment_type, compliance, description)
            data["fallback_reason"] = f"{'로컬 LLM' if mode == 'local' else 'Claude Cloud'} 호출 실패로 오프라인 템플릿 기반으로 대체됨: {e}"
            mode = "offline"
    else:
        data = generate_offline(environment_type, compliance, description)

    data["mode"] = mode
    return _enrich(data)


def generate_markdown_report(entry: dict) -> str:
    label = _ENV_LABELS.get(entry.get("environment_type", ""), entry.get("environment_type", "N/A"))
    lines = [
        "# 보안 정책 초안",
        "",
        f"**환경 유형:** {label}  ",
        f"**적용 대상 컴플라이언스:** {', '.join(entry.get('compliance', [])) or '명시되지 않음'}  ",
        "",
        "> 이 문서는 AI가 생성한 초안입니다. 실제 조직에 적용하기 전 반드시 인프라/보안/법무 담당자의 검토를 거치세요.",
        "",
        "---",
        "",
        "## 종합 평가",
        "",
        entry.get("summary", ""),
        "",
    ]

    risk_notes = entry.get("risk_notes") or []
    if risk_notes:
        lines += ["## ⚠️ 주의가 필요한 사항", ""]
        lines += [f"- {n}" for n in risk_notes]
        lines += ["", "---", ""]

    priority = entry.get("priority_order") or []
    if priority:
        lines += ["## 적용 우선순위", "", "| 순위 | 정책 영역 | 시급도 | 이유 |", "|------|-----------|--------|------|"]
        for p in priority:
            lines.append(f"| {p['rank']} | {p['category']} | {p['level']} | {p['reason']} |")
        lines += ["", "---", ""]

    lines += ["## 방화벽 규칙", "", "| ID | 동작 | 프로토콜 | 포트 | 출발지 | 목적지 | 설명 |", "|----|------|----------|------|--------|--------|------|"]
    for r in entry.get("firewall_rules", []):
        lines.append(f"| {r.get('id')} | {r.get('action')} | {r.get('protocol')} | {r.get('port')} | {r.get('source')} | {r.get('destination')} | {r.get('description')} |")
    if entry.get("firewall_validation_tip"):
        lines += ["", f"> **검증 방법:** {entry['firewall_validation_tip']}"]
    lines += ["", "---", ""]

    lines += ["## 정책 상세", ""]
    for p in entry.get("policies", []):
        lines += [f"### {p.get('category')} — {p.get('title')}", ""]
        for rule in p.get("rules", []):
            lines.append(f"- {rule}")
        lines += ["", f"**근거:** {p.get('rationale', '')}", ""]
        val = p.get("validation") or {}
        if val.get("method"):
            lines.append(f"**검증 방법:** {val['method']}" + (f" ({val['example']})" if val.get("example") else ""))
        lines += ["", "---", ""]

    compliance_mapping = entry.get("compliance_mapping") or []
    if compliance_mapping:
        lines += ["## 컴플라이언스 매핑", "", "> 참고용 매핑이며, 정확한 인증기준 충족 여부는 전문가 검토와 최신 기준 확인이 필요합니다.", ""]
        for c in compliance_mapping:
            lines += [f"### {c.get('framework')}", ""]
            for item in c.get("items", []):
                lines.append(f"- {item}")
            lines.append("")

    return "\n".join(lines)
