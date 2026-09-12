# AI Security Suite 정기 점검 보고서 에이전트
#
# "AI 에이전트와 연계" 방향 중 "정기 점검 보고서 에이전트" — 매일 한 번 이 PC에서 직접
# 실행되어(Windows 작업 스케줄러) 로컬 백엔드(localhost:8000)의 통합 리스크 현황과 알림을
# 조회하고, 이 PC에 로그인된 Claude Code CLI(구독, API 크레딧 아님)에게 한국어로 요약을
# 맡긴다.
#
# 클라우드 예약 에이전트(schedule 스킬)는 격리된 샌드박스에서 실행되어 이 PC의 localhost에
# 접근할 수 없어 이 용도에 쓸 수 없다 — 그래서 이 PC에서 직접 도는 로컬 스케줄로 구현했다.
#
# 안전 설계: Claude에게 Bash 등 도구 접근을 주지 않는다(--tools "") — 대신 이 스크립트가
# 먼저 결정론적으로 API를 호출해 JSON을 받아온 뒤, 그 텍스트를 요약해달라고만 시킨다.
# 무인 실행(로그인 세션 없이 작업 스케줄러가 트리거)에서 도구 호출 승인 프롬프트가 막히는
# 것을 원천적으로 피하기 위함이며, backend/services/claude_cli_client.py가 이미 쓰는 것과
# 동일한 원칙(--tools ""로 프롬프트 인젝션 시 실제 명령 실행 위험 차단)이다.

$ErrorActionPreference = "Stop"
$backend = "http://localhost:8000"
$reportDir = "C:\test_AI_security\backend\data\daily_reports"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$ts = Get-Date -Format "yyyy-MM-dd_HHmm"
$reportPath = Join-Path $reportDir "$ts.txt"

try {
    $overview = Invoke-RestMethod -Uri "$backend/api/dashboard/overview" -TimeoutSec 10
    $alerts = Invoke-RestMethod -Uri "$backend/api/alerts" -TimeoutSec 10
} catch {
    $message = "[$(Get-Date -Format o)] 백엔드($backend)에 접속할 수 없어 오늘 점검을 건너뜁니다: $($_.Exception.Message)"
    $message | Out-File -FilePath $reportPath -Encoding utf8
    Write-Output $message
    exit 0
}

$data = @{ overview = $overview; alerts = $alerts } | ConvertTo-Json -Depth 10 -Compress

$prompt = @"
다음은 보안 점검 도구(AI Security Suite)의 통합 리스크 대시보드(overview)와 최근 알림
(alerts) 데이터를 JSON으로 담은 것입니다. 미해결 CRITICAL 항목을 중심으로, 오늘 담당자가
무엇을 우선 확인해야 하는지 한국어로 5줄 이내로 요약해주세요. 특이사항이 없으면 그렇다고만
간단히 답하세요. 데이터:
$data
"@

# claude CLI가 구독 로그인 대신 API 키를 쓰지 않도록 상속 환경에서 제거한다
# (claude_cli_client.py가 이미 겪은 함정과 동일 — API 키가 있으면 그걸로 인증을 시도해
# 이 스크립트의 목적인 "API 크레딧이 아닌 구독 사용량" 전제가 깨진다).
Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

# PowerShell이 resolve하는 claude.ps1 래퍼는 파이프로 넘긴 stdin을 내부에서 감싸는
# 실제 node 프로세스로 제대로 전달하지 못해("Input must be provided either through stdin
# or as a prompt argument") 조용히 실패한다 — Bash의 echo | claude는 되는데 PowerShell의
# "..." | & claude.ps1은 안 되는, 이 프로젝트에서 반복돼 온 "셸마다 다르다" 유형의 새 사례.
# cmd.exe의 진짜 파일 리다이렉션(<)으로 claude.cmd를 호출하면 우회된다.
$claudeCmdPath = "$env:APPDATA\npm\claude.cmd"
if (-not (Test-Path $claudeCmdPath)) {
    "claude CLI를 찾을 수 없습니다($claudeCmdPath) — 이 PC에 Claude Code가 설치·로그인되어 있어야 합니다." | Out-File -FilePath $reportPath -Encoding utf8
    exit 1
}

$promptFile = Join-Path $env:TEMP "daily-security-report-prompt.txt"
$prompt | Out-File -FilePath $promptFile -Encoding utf8 -NoNewline

# ⚠️ 여기서 실제로 겪은 두 번째 함정: cmd.exe의 출력을 `$summary = cmd.exe /c "..."`처럼
# PowerShell 변수로 캡처하면, PowerShell이 외부 프로세스의 stdout 바이트를 콘솔
# 코드페이지(한글 Windows 기본 CP949)로 잘못 디코딩해 한글이 깨진다 — Out-File에 utf8을
# 지정해도 이미 문자열 단계에서 깨진 뒤라 소용없다. cmd.exe 자신의 `>` 리다이렉션으로
# claude의 stdout 바이트를 파일에 직접 쓰게 해 PowerShell의 문자열 캡처 단계 자체를
# 건너뛴다(청크가 통째로 그대로 저장되어야 UTF-8이 안 깨짐).
$quotedClaudeCmd = '"' + $claudeCmdPath + '"'
$quotedPromptFile = '"' + $promptFile + '"'
$quotedReportPath = '"' + $reportPath + '"'
cmd.exe /c "$quotedClaudeCmd -p --tools `"`" --no-session-persistence --strict-mcp-config --setting-sources user --model claude-sonnet-5 --output-format text < $quotedPromptFile > $quotedReportPath"
Remove-Item $promptFile -ErrorAction SilentlyContinue

Get-Content -Raw -Encoding utf8 $reportPath
