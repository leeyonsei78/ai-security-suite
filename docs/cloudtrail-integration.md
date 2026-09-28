# AWS CloudTrail 연동 가이드 (App 17)

고객사 AWS 계정의 CloudTrail 감사 로그를 **S3 + SNS 웹훅** 방식으로 받아서, 이 앱의
App 1(대시보드) 분석 파이프라인에 실시간에 가깝게 흘려보내는 기능입니다. n8n이나
별도 폴링 스케줄 없이, 새 CloudTrail 로그 파일이 S3에 쌓이는 순간 SNS가 우리
웹훅을 호출해 바로 분석이 시작됩니다.

## 인증 모델

장기 AWS 액세스 키를 절대 주고받지 않습니다. AWS의 표준 **Cross-Account IAM Role**
패턴을 씁니다:

1. 고객사가 자기 AWS 계정에 IAM Role을 만들고, "우리 회사 AWS 계정"이 그 Role을
   맡을(AssumeRole) 수 있도록 신뢰 정책에 등록합니다.
2. 우리는 매 요청마다 그 Role로 **몇 분짜리 임시 자격증명**만 빌려 써서 딱 필요한
   S3 파일만 읽습니다.
3. 우리 DB에는 Role ARN과 ExternalId만 저장됩니다 — 액세스 키는 저장되지 않습니다.

## 사전 준비 (운영자 — 우리 쪽)

이 백엔드 서버 자체가 "우리 회사 AWS 계정"으로 인증돼 있어야 고객사 Role을
AssumeRole할 수 있습니다. boto3의 표준 자격증명 체인을 그대로 씁니다 — 코드
변경 없이 아래 중 하나만 서버 환경에 설정하면 됩니다:

```bash
# 옵션 1: 환경변수
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# 옵션 2: 서버가 AWS EC2/ECS에서 돈다면 인스턴스 역할(Instance Profile)만 붙이면
#         환경변수 없이도 자동 인증됨 (권장 — 장기 키가 서버에 남지 않음)
```

이 계정에는 `sts:AssumeRole` 권한만 있으면 됩니다(고객사 Role의 신뢰 정책이
실제 접근 범위를 제한함).

## 고객사 온보딩 절차 (고객사가 하는 일)

### 1단계: IAM Role 생성

고객사 AWS 콘솔 → IAM → 역할 만들기 → "다른 AWS 계정" 선택:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<우리_AWS_계정번호>:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "<고객사와 합의한 임의의 문자열>" }
    }
  }]
}
```

`ExternalId`는 "혼동된 대리인 공격(Confused Deputy)"을 막기 위한 필수 조건입니다
— 누구나 예측 못 할 임의 문자열로 고객사가 직접 정합니다.

### 2단계: 읽기 전용 권한 부여

같은 Role에 아래 권한 정책을 연결(대상 버킷 이름은 실제 CloudTrail 로그 버킷으로 교체):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::<cloudtrail-bucket-name>",
      "arn:aws:s3:::<cloudtrail-bucket-name>/*"
    ]
  }]
}
```

### 3단계: CloudTrail에 SNS 알림 켜기

새 로그 파일이 S3에 쌓일 때마다 SNS로 알려주도록 설정합니다:

```bash
aws cloudtrail update-trail --name <trail-name> --sns-topic-name <topic-name>
```

(콘솔에서는 CloudTrail → 추적 → 편집 → "SNS 알림 전송" 켜기로 동일하게 설정 가능)

### 4단계: SNS 토픽에 우리 웹훅을 HTTPS 구독으로 추가

AWS 콘솔 → SNS → 해당 토픽 → 구독 생성 → 프로토콜 "HTTPS" → 엔드포인트에
이 앱의 **`https://<우리_배포_도메인>/api/cloudtrail/webhook`** 입력.

구독을 만들면 AWS가 즉시 우리 웹훅으로 "SubscriptionConfirmation" 메시지를 보내고,
우리 서버가 자동으로 그 확인 요청을 처리합니다(사람이 따로 링크를 클릭할 필요
없음) — 몇 초 뒤 AWS 콘솔에서 구독 상태가 "Confirmed"로 바뀌는지 확인하세요.

⚠️ 로컬 개발 환경(`localhost`)은 AWS가 도달할 수 없으므로, 실제로 테스트하려면
공인 도메인/고정 IP로 배포된 서버가 필요합니다.

### 5단계: 우리 쪽에 연결 정보 등록

고객사로부터 아래 4가지를 전달받아 `/cloudtrail` 페이지(또는 API)에 등록:

```bash
curl -X POST http://localhost:8000/api/cloudtrail/connections \
  -H "Content-Type: application/json" \
  -d '{
    "role_arn": "arn:aws:iam::<고객계정번호>:role/<역할이름>",
    "external_id": "<2단계에서 정한 값>",
    "region": "us-east-1",
    "topic_arn": "arn:aws:sns:us-east-1:<고객계정번호>:<topic-name>"
  }'
```

등록하는 즉시 실제로 AssumeRole이 되는지 검증합니다 — 실패하면 Role ARN/ExternalId/
신뢰 정책을 다시 확인하라는 에러 메시지가 바로 돌아옵니다.

## 동작 확인

1. 고객사 AWS 계정에서 아무 API 호출(예: 콘솔 로그인)이 발생하면 CloudTrail이
   로그를 S3에 씁니다.
2. S3에 새 파일이 생기면 CloudTrail이 SNS로 알림을 보냅니다.
3. SNS가 우리 웹훅(`/api/cloudtrail/webhook`)을 호출합니다.
4. 우리 서버가 서명을 검증하고, 등록된 연결의 Role로 그 로그 파일을 읽어와
   각 이벤트를 한 줄씩 정리한 뒤 App 1의 AI 로그 분석기(`analyze_logs()`)에 넣습니다.
5. 결과는 App 1(대시보드) 히스토리에 쌓이고, CRITICAL이면 기존 알림 시스템(Slack/이메일)으로
   자동 전송됩니다.
6. `/cloudtrail` 페이지에서 연결별 "수집된 이벤트 건수"·"마지막 수신 시각"으로
   정상 동작 여부를 확인할 수 있습니다.

## 보안 참고사항

- 웹훅 엔드포인트(`/api/cloudtrail/webhook`)는 AWS SNS가 직접 호출해야 하므로
  이 앱의 `API_KEY` 인증에서 예외 처리되어 있습니다. 대신 **AWS SNS 메시지 서명을
  암호학적으로 검증**해서 진짜 AWS가 보낸 메시지인지 확인합니다
  (`backend/services/sns_verify.py`).
- 서명 검증만으로는 "서명이 유효한 아무 SNS 토픽의 메시지"가 다 통과하므로,
  추가로 메시지의 `TopicArn`이 우리가 등록해둔 연결과 일치하는지 확인합니다 —
  등록하지 않은 토픽에서 오는 메시지는 조용히 무시됩니다.
- 프로덕션에 배포할 때는 웹훅 URL이 반드시 HTTPS(TLS)여야 합니다 — SNS는 HTTPS
  엔드포인트만 신뢰성 있게 재시도합니다.
