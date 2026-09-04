# App 16(방화벽 정책 감사기) 실습용 — 의도적으로 취약하게 구성한 iptables 규칙을
# 컨테이너 안에서 실제로 적용해두고, 사용자가 docker exec로 들어가 실제 규칙을
# 조회(iptables -L -n -v --line-numbers)해서 그대로 App 16에 붙여넣어보는 용도.
# 이 컨테이너는 어떤 포트도 게시하지 않는다 — 네트워크 스캔 대상이 아니라 CLI 실습 대상이다.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY apply-bad-rules.sh /usr/local/bin/apply-bad-rules.sh
RUN chmod +x /usr/local/bin/apply-bad-rules.sh

ENTRYPOINT ["/usr/local/bin/apply-bad-rules.sh"]
