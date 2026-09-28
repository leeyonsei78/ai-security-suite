# 외부 로그 소스 연동 가이드 (App 18: Syslog 등)

rsyslog·syslog-ng 같이 이미 있는 로그 포워더가 **HTTPS로 로그를 직접 보내게** 해서
App 1(대시보드)의 AI 분석 파이프라인에 실시간으로 흘려보내는 기능입니다.

## 왜 이 서버가 UDP 514(syslog 기본 포트)를 직접 열지 않는가

이 서버가 임의의 UDP 514 트래픽을 인터넷에 열어두면 스푸핑·DoS에 취약해집니다.
대신 **고객사 쪽에 이미 있는 rsyslog/syslog-ng가 로그를 파싱해서 HTTPS로
포워딩**하도록 설정합니다 — 고객사 인바운드 방화벽 규칙을 전혀 안 건드려도
되는 방식입니다(모든 트래픽이 고객사 → 우리 서버로 나가는 outbound).

## 1. 소스 등록 (우리 쪽에서)

`/log-sources` 페이지 또는 API로 소스를 하나 등록하면 그 소스 전용 Ingest Key가
즉시 발급됩니다:

```bash
curl -X POST http://localhost:8000/api/log-sources \
  -H "Content-Type: application/json" \
  -d '{"label": "고객사 A rsyslog"}'
```

응답의 `ingest_key`를 아래 2단계 설정에 사용합니다.

## 2. rsyslog 설정 (`omhttp` 모듈)

```conf
module(load="omhttp")

action(
  type="omhttp"
  server="<우리_배포_도메인>"
  serverport="443"
  usehttps="on"
  restpath="api/logs/ingest"
  httpheaderkey1="X-Ingest-Key" httpheadervalue1="<위에서 발급받은 ingest_key>"
  template="json_tmpl"
  action.resumeRetryCount="-1"
)

template(name="json_tmpl" type="string"
  string="[{\"host\":\"%HOSTNAME%\",\"severity\":\"%syslogseverity-text%\",\"message\":\"%msg%\",\"timestamp\":\"%timestamp:::date-rfc3339%\"}]")
```

## 3. syslog-ng 설정 (`http()` destination)

```conf
destination d_http {
    http(
        url("https://<우리_배포_도메인>/api/logs/ingest")
        method("POST")
        headers("Content-Type: application/json", "X-Ingest-Key: <ingest_key>")
        body("[$(format-json --scope rfc5424 --key '*')]")
        persist-name("d_http")
    );
};
log { source(s_src); destination(d_http); };
```

## 4. 요청 형식

`POST /api/logs/ingest`, 헤더 `X-Ingest-Key: <소스별 발급 키>`.

바디는 아래 셋 중 하나를 지원합니다(자동 판별):

- JSON 객체 배열: `[{"host": "...", "severity": "...", "message": "...", "timestamp": "..."}, ...]`
- JSON 객체 하나: `{"host": "...", "message": "..."}`
- 순수 텍스트(줄바꿈으로 구분된 로그 라인) — 간단한 curl/스크립트 클라이언트용

한 번에 최대 200줄까지 처리합니다(그 이상은 잘림 — 프롬프트 비용 보호).

## 5. 동작 확인

1. 위 설정 반영 후 고객사 서버에서 로그가 발생하면 rsyslog/syslog-ng가 즉시
   우리 엔드포인트로 포워딩합니다.
2. 받은 로그는 한 배치로 묶여 App 1의 `analyze_logs()`에 그대로 들어갑니다.
3. 결과는 App 1(대시보드) 히스토리에 쌓이고, CRITICAL이면 기존 알림 시스템으로
   자동 전송됩니다.
4. `/log-sources` 페이지에서 소스별 "수집된 로그 건수"·"마지막 수신 시각"으로
   정상 동작 여부를 확인할 수 있습니다.

## 보안 참고사항

- 소스마다 서로 다른 Ingest Key가 발급되어 격리됩니다 — 한 소스의 키가 유출돼도
  다른 소스에는 영향이 없습니다. 키가 유출된 것으로 의심되면 해당 소스를
  삭제하고 새로 등록하세요(재발급은 삭제 후 재생성 방식).
- 이 엔드포인트는 (CloudTrail 웹훅과 마찬가지로) 이 앱의 전역 `API_KEY` 인증
  대상이 아닙니다 — 외부 포워더가 커스텀 `X-API-Key`를 보낼 수 없는 경우가
  많아서, 대신 소스별 Ingest Key로 인증합니다.
- 프로덕션에서는 반드시 HTTPS 엔드포인트를 사용하세요 — 평문 HTTP로 Ingest Key와
  로그 내용이 그대로 노출됩니다.

## 다른 클라우드 제공자 로그 (Azure/GCP)

AWS는 App 17(CloudTrail)·App 16 확장(CloudWatch Logs/GuardDuty)으로 이미
지원합니다. Azure Activity Log(Azure Monitor REST API, Service Principal 인증)와
GCP Cloud Logging API(Service Account 인증)는 인증 모델이 AWS와 달라(각각 Azure AD
App 등록, GCP Service Account/Workload Identity) 아직 이 앱에 구현하지 않았습니다
— 실제 고객 요청이 들어오면 이 문서의 AWS 커넥터와 같은 패턴(연결 관리 화면 +
App 16 스케줄러에 새 job_type 추가)으로 확장할 예정입니다.
