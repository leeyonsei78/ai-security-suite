#!/bin/bash
set -e

# App 3/CLAUDE.md의 mock_firewall_audit.py "iptables" 템플릿과 의도적으로 대응시킨
# 취약 규칙 — 과도허용(SSH/DB 전역공개) + 미사용(디버그 포트) + 중복(443 두 번) +
# 누락된 통제(OUTPUT 무제한)까지 App 16이 잡아내야 할 문제 유형을 한 번에 재현한다.
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -m comment --comment "2024-01 temp debug" -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
# OUTPUT 체인은 기본 정책(ACCEPT)을 그대로 방치 — 의도적으로 아웃바운드 통제 없음

echo "=== 의도적으로 취약하게 구성된 iptables 규칙 적용 완료 ==="
echo "다음 명령으로 실제 규칙을 조회해 App 16(방화벽 정책 감사기)에 그대로 붙여넣으세요:"
echo "  iptables -L -n -v --line-numbers"
echo ""
echo "컨테이너 진입: docker exec -it test-range-bad-firewall bash"

exec sleep infinity
