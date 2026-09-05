#!/bin/bash
set -e

# App 16(방화벽 정책 감사기, AWS 보안그룹)·App 18(클라우드 IAM 정책 감사기, AWS)
# 실습용 — LocalStack(로컬 AWS 에뮬레이터)에 실제 aws CLI로 의도적으로 취약한
# IAM 정책/역할/사용자 + 보안그룹을 생성해두고, 그 결과를 실제 조회 명령으로
# 꺼내 앱에 붙여넣는 용도. LocalStack은 실제 AWS 요금이 전혀 발생하지 않는다.

EP="${LOCALSTACK_ENDPOINT:-http://localstack:4566}"

echo "LocalStack 준비 대기 중..."
until aws --endpoint-url="$EP" iam list-users >/dev/null 2>&1; do
  sleep 2
done

# ---- App 18 IAM 감사기 테스트용: 과도한 권한 정책 + 위험한 신뢰 관계(Principal: *) ----
aws --endpoint-url="$EP" iam create-policy \
  --policy-name AdminAccessInline \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  >/dev/null 2>&1 || true

aws --endpoint-url="$EP" iam create-role \
  --role-name deploy-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null 2>&1 || true

POLICY_ARN=$(aws --endpoint-url="$EP" iam list-policies --scope Local \
  --query "Policies[?PolicyName=='AdminAccessInline'].Arn" --output text)

aws --endpoint-url="$EP" iam attach-role-policy \
  --role-name deploy-role --policy-arn "$POLICY_ARN" >/dev/null 2>&1 || true

aws --endpoint-url="$EP" iam create-user --user-name legacy-svc-account >/dev/null 2>&1 || true
aws --endpoint-url="$EP" iam attach-user-policy \
  --user-name legacy-svc-account --policy-arn "$POLICY_ARN" >/dev/null 2>&1 || true
aws --endpoint-url="$EP" iam create-access-key --user-name legacy-svc-account >/dev/null 2>&1 || true

# ---- App 16 방화벽 정책 감사기(AWS 보안그룹) 테스트용: SSH/DB 포트 전역 공개 ----
VPC_ID=$(aws --endpoint-url="$EP" ec2 describe-vpcs --query "Vpcs[0].VpcId" --output text 2>/dev/null)
SG_ID=$(aws --endpoint-url="$EP" ec2 create-security-group \
  --group-name bad-sg --description "intentionally insecure (test-range)" --vpc-id "$VPC_ID" \
  --query "GroupId" --output text 2>/dev/null || \
  aws --endpoint-url="$EP" ec2 describe-security-groups --group-names bad-sg \
  --query "SecurityGroups[0].GroupId" --output text 2>/dev/null)

aws --endpoint-url="$EP" ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
aws --endpoint-url="$EP" ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" --protocol tcp --port 3306 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true

echo "=== 완료: 의도적으로 취약한 AWS 리소스가 LocalStack에 생성되었습니다 (실제 AWS 요금 없음) ==="
echo ""
echo "호스트에 aws CLI가 설치돼 있다면 (환경변수: AWS_ACCESS_KEY_ID=test, AWS_SECRET_ACCESS_KEY=test, AWS_DEFAULT_REGION=us-east-1 아무 값이나 가능):"
echo "  App 18(IAM):  aws --endpoint-url=http://localhost:4566 iam get-account-authorization-details"
echo "  App 16(SG):   aws --endpoint-url=http://localhost:4566 ec2 describe-security-groups --group-ids $SG_ID"
echo ""
echo "호스트에 aws CLI가 없다면 이 컨테이너 안에서 그대로 조회 가능합니다:"
echo "  docker exec -it test-range-aws-sandbox aws --endpoint-url=$EP iam get-account-authorization-details"
echo "  docker exec -it test-range-aws-sandbox aws --endpoint-url=$EP ec2 describe-security-groups --group-ids $SG_ID"

exec sleep infinity
