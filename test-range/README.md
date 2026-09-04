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

## 안전 수칙

- **인터넷에 노출 금지**: `docker-compose.yml`은 `127.0.0.1`에만 바인딩되도록 포트를
  게시합니다(호스트 방화벽에서 별도로 막지 않았다면 LAN 내 다른 기기에서도 접근 가능할
  수 있으니, 굳이 `--host`로 개방하지 않는 한 로컬 전용으로 유지하세요).
- 이 컨테이너들은 **이 프로젝트를 테스트하는 용도로만** 사용하고, 실제 운영 환경 옆에
  띄워두지 마세요.
- 다 쓴 뒤에는 `docker compose down`으로 반드시 종료하세요.
