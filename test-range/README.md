# 테스트 레인지 (로컬 취약 환경)

App 6(웹 취약점 스캐너)/App 16(방화벽 정책 감사기)/App 17(인프라 취약점 스캐너)을
**실제 대상**으로 테스트해보기 위한 로컬 전용 Docker Compose 스택입니다. 전부 검증된
공식 이미지(또는 그 위에 만든 커스텀 Dockerfile)만 사용하며, 절대 인터넷에 노출하지 않고
로컬호스트에서만 접근 가능하도록 구성되어 있습니다.

## 시작 / 종료

```bash
cd test-range
docker compose up -d --build   # 시작
docker compose down            # 종료 (컨테이너·네트워크 제거, 이미지는 남음)
docker compose ps              # 상태 확인
```

## 구성 요소

| 컨테이너 | 용도 | 접속 방법 |
|---|---|---|
| `test-range-juice-shop` | OWASP Juice Shop — 의도적으로 100개 이상의 취약점이 심어진 웹 애플리케이션 | 브라우저: `http://localhost:3000`, App 6 대상 URL: `http://localhost:3000` |
| `test-range-old-tomcat` | Apache Tomcat 8.5.19 (오래된 버전 고정) | `http://localhost:8080`, App 17 네트워크 스캔 대상: `127.0.0.1` |
| `test-range-old-redis` | Redis 4.0 (인증 없이 노출, `protected-mode no`) | App 17 네트워크 스캔 대상: `127.0.0.1` (포트 6379) |
| `test-range-bad-firewall` | 의도적으로 취약하게 구성한 iptables 규칙 — 포트 게시 없음, CLI 실습 전용 | `docker exec -it test-range-bad-firewall bash` 후 `iptables -L -n -v --line-numbers` |
| `test-range-localstack` | LocalStack(로컬 AWS 에뮬레이터, 4.4.0 고정) — 실제 AWS 요금 없이 IAM/EC2 API를 흉내낸다 | `http://localhost:4566` (aws CLI `--endpoint-url`로 접속) |
| `test-range-aws-sandbox` | LocalStack에 의도적으로 취약한 IAM 정책/역할/사용자 + 보안그룹을 실제 aws CLI로 생성해두는 컨테이너 | `docker exec -it test-range-aws-sandbox bash` — 아래 App 16/18 절 참고 |

## 각 앱과 연결하는 방법

### App 6 웹 취약점 스캐너 (`/webscan`)
대상 URL에 `http://localhost:3000` 입력 → 보안 헤더/노출 경로 점검.
App 3(취약점 스캐너)에 Juice Shop 관련 텍스트를 붙여넣어 분석해보는 것도 가능합니다.

### App 17 인프라 취약점 스캐너 → 네트워크 라이브 스캔 (`/infra-scan`)
대상에 **`127.0.0.1`**을 입력하고 승인 체크박스를 체크한 뒤 스캔 실행. 실제 검증 결과:
- 포트 6379(Redis) — 배너 `redis_version:4.0.14` 실제 수집, NVD에서 **CVE-2019-10192/10193(HIGH, hyperloglog 버퍼 오버플로우)** 실제 매칭 확인됨
- 포트 8080(Tomcat) — 배너 `Apache Tomcat/8.5.19` 실제 수집(이 버전은 Server 헤더를 보내지 않아 응답 본문의 `<title>`에서 추출). NVD 키워드 검색으로는 이 특정 버전과 매칭되는 CVE가 나오지 않을 수 있습니다 — CPE 기반이 아닌 키워드 검색의 한계이며 정상적인 동작입니다.

> ⚠️ **Windows + Docker Desktop 환경 주의**: 컨테이너의 브리지 네트워크 IP(예: 172.x)는
> Docker Desktop이 WSL2 VM 안에서 컨테이너를 실행하기 때문에 Windows 호스트에서 직접
> 스캔할 수 없습니다. 이 백엔드(uvicorn)는 Windows 호스트에서 네이티브로 실행되므로,
> 반드시 **컨테이너가 아니라 `127.0.0.1`(호스트에 게시된 포트)을 스캔 대상으로 사용**하세요.
> 이 구성의 모든 서비스가 `docker-compose.yml`에서 호스트로 포트를 게시(`ports:`)해두는
> 것도 이 때문입니다.

### App 17 인프라 취약점 스캐너 → 의존성(SCA) 스캔
이 테스트 레인지와는 무관하게 동작합니다 — `requirements.txt`/`package.json` 텍스트를
직접 붙여넣으면 됩니다. 예시(`flask==0.12` / `requests==2.6.0`)는 App 17 페이지의
플레이스홀더를 참고하세요.

### App 16 방화벽 정책 감사기 (`/firewall-audit`)
```bash
docker exec test-range-bad-firewall iptables -L -n -v --line-numbers
```
위 명령의 실제 출력(아래와 유사한 형태)을 그대로 복사해 App 16의 "방화벽 규칙" 입력창에
붙여넣고, 플랫폼은 **Linux iptables/nftables**를 선택하세요.

```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2        0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306
3        0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8081 /* 2024-01 temp debug */
4        0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443
5        0     0 ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443
```
심어둔 문제: SSH(22)·가짜 DB 포트(3306) 전역 공개(과도 허용), 근거 불명의 디버그 포트(8081, 미사용),
443 규칙 중복, OUTPUT 체인 통제 없음(누락된 통제) — App 16이 이 네 가지 유형을 실제로
찾아내는지 확인하는 용도입니다. (⚠️ 이 프로젝트가 Mock 모드로 실행 중이라면 App 16은
붙여넣은 내용을 실제로 읽지 않고 소스 타입별로 미리 정해둔 예시 결과를 반환합니다 —
`ANTHROPIC_API_KEY`를 설정한 Live 모드에서만 실제로 이 텍스트를 분석합니다.)

### App 16(AWS 보안그룹)·App 18(클라우드 IAM 정책 감사기, AWS)

`localstack`이 뜨면 `aws-sandbox` 컨테이너가 자동으로 의도적으로 취약한 IAM 정책/역할/
사용자(과도한 권한 `Action:"*"` + 신뢰 관계 `Principal:"*"`) + 보안그룹(SSH/MySQL 전역
공개)을 실제 aws CLI로 생성해둡니다. **비용은 전혀 발생하지 않습니다** — LocalStack은
로컬에서 AWS API를 그대로 흉내내는 에뮬레이터입니다.

```bash
docker logs test-range-aws-sandbox   # 생성된 리소스의 실제 그룹 ID 등 확인
```

호스트에 aws CLI가 설치돼 있다면(더미 자격증명이면 충분: `AWS_ACCESS_KEY_ID=test`,
`AWS_SECRET_ACCESS_KEY=test`, 리전은 아무 값이나) 아래처럼 `--endpoint-url`만 추가해서
조회하면 됩니다. 설치가 없다면 `docker exec -it test-range-aws-sandbox aws ...`로 컨테이너
안에서 그대로 조회할 수 있습니다(내부에서는 `--endpoint-url=http://localstack:4566` 사용).

```bash
# App 18(IAM) — 실제 AWS 계정을 조회할 때와 동일한 명령, --endpoint-url만 다름
aws --endpoint-url=http://localhost:4566 iam get-account-authorization-details \
  --filter User Role LocalManagedPolicy
```

> ⚠️ `--filter` 없이 호출하면 LocalStack이 AWS 관리형 정책 수천 개를 통째로 반환해
> 결과가 지나치게 커집니다(실제 AWS 계정에서도 마찬가지입니다) — 커스텀(Local) 정책만
> 보려면 항상 `--filter User Role LocalManagedPolicy`를 붙이세요.

```bash
# App 16(보안그룹) — GroupId는 위 docker logs 출력에서 확인
aws --endpoint-url=http://localhost:4566 ec2 describe-security-groups --group-ids <sg-id>
```

위 명령의 실제 출력을 각각 App 18의 입력창(플랫폼: AWS IAM)과 App 16의 입력창(플랫폼:
AWS 보안그룹)에 그대로 붙여넣으면 됩니다. 심어둔 문제: IAM은 과도한 권한(Admin 정책)
+ 위험한 신뢰 관계(누구나 역할을 맡을 수 있음), 보안그룹은 SSH(22)·MySQL(3306) 포트가
0.0.0.0/0에 전역 공개된 과도 허용(overly_permissive) — 둘 다 실제로 탐지되는지 확인하는
용도입니다.

## 안전 수칙

- **인터넷에 노출 금지**: `docker-compose.yml`은 `127.0.0.1`에만 바인딩되도록 포트를
  게시합니다(호스트 방화벽에서 별도로 막지 않았다면 LAN 내 다른 기기에서도 접근 가능할
  수 있으니, 굳이 `--host`로 개방하지 않는 한 로컬 전용으로 유지하세요).
- 이 컨테이너들은 **이 프로젝트를 테스트하는 용도로만** 사용하고, 실제 운영 환경 옆에
  띄워두지 마세요.
- 다 쓴 뒤에는 `docker compose down`으로 반드시 종료하세요.
