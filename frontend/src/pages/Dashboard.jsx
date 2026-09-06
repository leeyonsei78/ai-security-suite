import { useState, useEffect, useRef, Fragment } from 'react'
import axios from 'axios'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Shield, AlertTriangle, Upload, Trash2, RefreshCw, Radio, Send, Play, Square, Cloud, Server, Terminal, WifiOff, FlaskConical, Download, Info, X, Search, Wrench, CheckCircle2 } from 'lucide-react'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import GuidePanel from '../components/GuidePanel'
import CopyButton from '../components/CopyButton'
import { DEFAULT_ACCEPT as UPLOAD_ACCEPT } from '../components/FileUploadButton'

const MODE_BADGE = {
  cloud:      { icon: Cloud,        label: '외부 AI API로 분석됨', color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  local:      { icon: Server,       label: '로컬 LLM으로 분석됨',    color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/30' },
  claude_cli: { icon: Terminal,     label: 'Claude Code CLI로 분석됨(구독)', color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/30' },
  offline:    { icon: WifiOff,      label: '오프라인 규칙 기반으로 분석됨(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  mock:       { icon: FlaskConical, label: 'Mock 데모 데이터 (학습용, 실제 분석 아님)', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
}

// 각 모드가 실제로 "무엇을 근거로" 판정했는지 한 줄 설명. 특히 "오프라인 규칙 기반"은 AI가
// 아니라 사전에 정해둔 정규식 패턴(반복된 인증 실패, SQLi 문자열, 인코딩된 PowerShell 등)과
// 대조한 결과라는 점 — 겉보기엔 "AI가 분석했다"는 다른 배지들과 똑같아 보이지만 근거가
// 완전히 다르므로 항상 함께 보여준다.
const MODE_EXPLANATION = {
  cloud: '외부 AI API(Claude 등)가 로그 내용을 실제로 읽고 스스로 판단한 결과입니다.',
  local: '사내에 구성한 로컬 LLM이 로그 내용을 실제로 읽고 스스로 판단한 결과입니다.',
  claude_cli: '이 PC에 로그인된 Claude Code를 통해 로그 내용을 실제로 읽고 판단한 결과입니다 — API 크레딧이 아니라 Claude 구독 사용량으로 처리됩니다. 보통 외부 AI API 크레딧이 소진됐을 때 수동으로 이 모드를 선택했을 때 쓰입니다.',
  offline: 'AI가 읽고 판단한 게 아니라, 미리 정해둔 정규식 패턴(반복된 인증 실패, SQL 인젝션 문자열, 인코딩된 PowerShell 등)과 단순 대조한 결과입니다 — 인터넷 연결 없이도 동작하지만, 정해진 패턴에 없는 새로운 유형의 위협은 놓칠 수 있습니다. 보통 외부 AI API 호출이 실패했을 때(인터넷 단절, API 크레딧 소진 등) 자동으로 여기로 전환됩니다. 실제 규칙 정의는 backend/services/log_offline_engine.py 파일에서 확인·수정할 수 있습니다.',
  mock: '실제 로그를 분석한 게 아니라, 화면 구성을 미리 보기 위한 고정된 학습용 샘플입니다.',
}

function ModeBanner({ result }) {
  if (!result?.mode) return null
  const cfg = MODE_BADGE[result.mode] ?? MODE_BADGE.offline
  const Icon = cfg.icon
  // "(폐쇄망)"은 실제로 인터넷이 안 되는 경우를 위한 표현인데, fallback_reason이 있다는 건
  // 인터넷은 되지만 AI 호출 자체가 실패(크레딧 소진 등)해서 대체됐다는 뜻이라 그대로 두면
  // "내 네트워크가 문제"라고 오해할 수 있다 — 이 경우엔 라벨에서 그 표현을 바꿔준다.
  const label = (result.mode === 'offline' && result.fallback_reason)
    ? cfg.label.replace('(폐쇄망)', '(AI 호출 실패로 대체)')
    : cfg.label
  return (
    <div className={`border rounded-xl p-3 flex items-start gap-2 ${cfg.bg}`}>
      <Icon size={14} className={`${cfg.color} shrink-0 mt-0.5`} />
      <div>
        <p className={`text-xs font-semibold ${cfg.color}`}>{label}</p>
        {result.fallback_reason && (
          <p className="text-xs text-slate-400 mt-1">{result.fallback_reason}</p>
        )}
        {result.engine_note && (
          <p className="text-xs text-slate-400 mt-1">{result.engine_note}</p>
        )}
      </div>
    </div>
  )
}

const DASHBOARD_STEPS = [
  '상단 탭에서 "분석" 탭을 선택합니다.',
  '로그 파일(.log, .txt)을 드래그하거나 [파일 업로드] 버튼으로 업로드하거나, 텍스트 박스에 로그를 직접 붙여넣습니다.',
  '[분석 시작] 버튼을 클릭하면 AI가 로그를 읽고 위협을 분류합니다.',
  '"개요" 탭에서 위협 분포 파이차트와 심각도별 통계를 확인합니다.',
  '"이벤트" 탭에서 탐지된 이벤트 목록(소스 IP, 심각도, 대응 방안)을 확인합니다.',
  '"상세" 탭에서 선택한 분석 건의 전체 결과를 조회합니다.',
  '"실시간" 탭에서 [모니터링 시작]을 누르면 합성 로그가 주기적으로 생성되어 자동 분석되는 모습을 볼 수 있습니다.',
]
const DASHBOARD_TIPS = [
  'API 키 없이도 Mock 모드로 샘플 위협 8종이 자동 생성됩니다 — 실제 분석이 아니라 화면 구성을 미리 보기 위한 고정된 학습용 데모 데이터입니다(같은 8개 시나리오가 계속 반복됨).',
  '실제 값을 보려면: 좌상단 NavBar의 AI 모드 배지(현재 "Mock 데모" 등으로 표시됨)를 클릭해 "Claude Cloud"·"로컬 LLM"·"오프라인(폐쇄망)" 중 사용 가능한 것으로 바꾸세요 — API 키가 설정돼 있으면 자동으로 Claude Cloud가 선택되고, 폐쇄망이면 오프라인 규칙 기반으로 실제 입력을 분석합니다. 이후 "분석" 탭에 진짜 로그(파일 업로드 또는 붙여넣기)를 넣으면 실제 결과가 나옵니다.',
  '"실시간" 탭에서도 실제 값을 볼 수 있습니다 — "수집 대상"을 "실제 이 PC(Windows)"로 선택하면 가상 시뮬레이션 대신 이 PC의 실제 로그온 실패·Defender 탐지·리스닝 포트 변화를 조회해 분석합니다.',
  '우측 상단 새로고침(↺) 버튼으로 최신 결과를 다시 불러옵니다.',
  '휴지통(🗑) 버튼으로 전체 분석 내역을 초기화할 수 있습니다.',
  '심각도: Critical(즉시조치) → High → Medium → Low → Info 순으로 위험합니다.',
  '"실시간" 탭의 "가상 대상 시스템" 프로필(일반 서버/웹 서버/사내망 업무 시스템)은 실제 로그 소스가 아니라 데모용으로 합성한 로그를 주기적으로 생성하는 시뮬레이션입니다 — 실제 이 PC를 보려면 위 "실제 이 PC(Windows)" 옵션을, 다른 서버를 보려면 실시간 공격 모니터링 & 대응(/attack-monitor)의 원격 대상 지정 기능을 이용하세요.',
]

const THREAT_ACTION_GUIDANCE = {
  CRITICAL: '즉시 조치가 필요합니다 — 아래 이벤트별 "대응 방안"을 지금 바로 시행하고, 관련 계정·시스템을 격리·차단하세요.',
  HIGH: '빠른 확인이 필요합니다 — 오늘 안에 아래 이벤트를 조사하고 "대응 방안"을 적용하세요.',
  MEDIUM: '관찰이 필요합니다 — 아래 이벤트가 반복되거나 심해지는지 지켜보고, 필요하면 "대응 방안"을 적용하세요.',
  LOW: '참고용입니다 — 즉시 조치는 필요하지 않지만 기록해두는 것이 좋습니다.',
  INFO: '특별한 위협이 발견되지 않았습니다 — 별도 조치가 필요하지 않습니다.',
}

const EVENTS_TABLE_HELP = '한 줄 = 탐지된 이벤트 하나입니다. "분류"는 위협 종류, "대상"은 영향을 받은 시스템/계정, "대응 방안"은 AI가 제안하는 조치입니다 — 심각도가 높은 순으로 먼저 처리하고, 각 행의 [방법 보기]에서 어디서 확인하고 어떻게 적용·검증하는지 확인하세요.'

// affected_resource/description에 ssh·nginx 같은 리눅스 계열 단서 또는 Windows/AD 계열 단서가
// 있는지 보고 OS를 추정 — Brute Force 등 OS별로 명령이 갈리는 카테고리에서 "둘 다 보여주고
// 알아서 고르라"는 대신 어느 쪽이 맞을지 힌트를 준다(추정 실패 시 null, 두 명령 다 원문에 남아있어
// 여전히 선택 가능).
function guessOS(ev) {
  const text = `${ev.affected_resource ?? ''} ${ev.description ?? ''}`.toLowerCase()
  if (/\bssh\b|linux|unix|nginx|apache|\/var\/log|ubuntu|centos|debian/.test(text)) return 'linux'
  if (/window|\.exe\b|active directory|\bws-|iis|powershell/.test(text)) return 'windows'
  return null
}

function osHint(ev) {
  const os = guessOS(ev)
  if (os === 'linux') return '\n\n💡 "대상"에 SSH 등 리눅스/유닉스 계열 서비스가 표시되어 있어 Linux 명령이 맞을 가능성이 높습니다.'
  if (os === 'windows') return '\n\n💡 "대상"으로 미루어 Windows 서버로 보입니다 — Windows 명령을 사용하세요.'
  return '\n\n💡 대상 시스템이 Linux/Windows 중 무엇인지 먼저 확인한 뒤 맞는 명령을 사용하세요.'
}

// 카테고리별 "① 어디서 확인 ② 어떻게 적용 ③ 적용됐는지 확인" 가이드. AI가 만들어내는 category는
// 자유 텍스트라 미리 다 알 수 없으므로, mock_data.py의 8개 고정 카테고리는 구체적인 명령까지
// 담아 안내하고 나머지는 default로 일반적인 절차를 안내한다. source_ip/affected_resource를
// 실제 값으로 채워 넣어 그 이벤트에 딱 맞는 문장이 되도록 함수 형태로 정의했다.
const CATEGORY_GUIDE = {
  'Brute Force': {
    verify: (ev) => `대상(${ev.affected_resource ?? '해당 서버'})의 인증 로그에서 소스 IP(${ev.source_ip ?? '-'})를 검색해 실제 로그인 실패 기록이 있는지 확인하세요.\nLinux: grep "${ev.source_ip ?? '<IP>'}" /var/log/auth.log\nWindows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Where-Object Message -match "${ev.source_ip ?? '<IP>'}"${osHint(ev)}`,
    apply: (ev) => `방화벽에서 해당 IP를 차단하세요.\nLinux: sudo iptables -A INPUT -s ${ev.source_ip ?? '<IP>'} -j DROP\nWindows: New-NetFirewallRule -DisplayName "Block ${ev.source_ip ?? 'IP'}" -RemoteAddress ${ev.source_ip ?? '<IP>'} -Action Block -Direction Inbound\n반복되면 fail2ban 설치를 검토하고, 대상 계정 비밀번호를 재설정하세요.${osHint(ev)}`,
    confirm: (ev) => `규칙이 등록됐는지 확인: iptables -L -n | grep ${ev.source_ip ?? '<IP>'} (Windows는 Get-NetFirewallRule)\n이후 로그를 다시 확인해 같은 IP의 추가 시도가 없는지 확인하세요.`,
  },
  'SQL Injection': {
    verify: (ev) => `웹서버 접근 로그(${ev.affected_resource ?? '해당 애플리케이션'})에서 소스 IP(${ev.source_ip ?? '-'})의 요청에 실제로 SQL 구문이 포함됐는지 확인하세요.\ntail -f /var/log/nginx/access.log | grep "${ev.source_ip ?? '<IP>'}"`,
    apply: '해당 쿼리를 파라미터화(Prepared Statement)로 코드 수정하고, 방화벽/WAF에서 해당 IP를 임시 차단하거나 이 패턴을 룰로 추가하세요.',
    confirm: '테스트 환경에서 동일한 payload로 재요청해 더 이상 통과하지 않는지 확인하고, 웹 취약점 스캐너(/webscan)로 재검증하세요.',
  },
  'Malware': {
    verify: (ev) => `${ev.affected_resource ?? '해당 시스템'}에서 백신/EDR 콘솔의 탐지 이력을 확인하거나, 위협 분석 랩(/threat)으로 의심 프로세스를 직접 조사하세요.`,
    apply: '해당 시스템을 네트워크에서 격리하고 백신/EDR로 전체 검사·치료를 수행하세요. 필요하면 재이미징(OS 재설치)하세요.',
    confirm: '재검사 결과가 클린인지 확인하고, 이후 일정 기간 모니터링해 재발하지 않는지 지켜보세요.',
  },
  'Port Scan': {
    verify: (ev) => `방화벽/IDS 로그에서 소스 IP(${ev.source_ip ?? '-'})의 연결 시도 패턴을 확인하세요.`,
    apply: '방화벽에서 해당 IP를 차단하고, 인프라 취약점 스캐너(/infra-scan)의 네트워크 스캔 탭으로 불필요하게 열린 포트가 없는지 점검하세요.',
    confirm: 'nmap 등으로 실제 열린 포트를 재점검하고, 방화벽 규칙이 반영됐는지 확인하세요.',
  },
  'Privilege Escalation': {
    verify: (ev) => `${ev.affected_resource ?? '해당 계정/시스템'}의 권한 변경 이력을 감사 로그(Windows Security 4672/4673, Linux sudo 로그)에서 확인하세요.`,
    apply: '해당 계정의 불필요한 권한을 즉시 회수하고 의심스러우면 계정을 비활성화하세요. 클라우드 IAM 정책 감사기(/iam-audit)로 전체 권한 구조도 점검하세요.',
    confirm: '권한을 다시 조회해 회수가 반영됐는지 확인하고, 이후 동일 계정의 이상 행위가 없는지 모니터링하세요.',
  },
  'Data Exfiltration': {
    verify: (ev) => `방화벽/프록시 로그에서 ${ev.affected_resource ?? '해당 시스템'}발 아웃바운드 트래픽량과 목적지를 확인하세요.`,
    apply: '해당 목적지로의 아웃바운드 트래픽을 방화벽에서 차단하고, 유출 경로가 된 시스템/계정을 격리하세요.',
    confirm: '차단 후 실제로 해당 목적지와의 트래픽이 끊겼는지 네트워크 모니터링으로 확인하세요.',
  },
  'Policy Violation': {
    verify: (ev) => `${ev.affected_resource ?? '해당 시스템'}의 실제 설정을 확인해 위반 여부를 대조하세요 — 방화벽 정책 감사기(/firewall-audit), IAM 정책 감사기(/iam-audit) 등을 활용하면 좋습니다.`,
    apply: '위반된 정책 항목을 수정하고 관련 담당자에게 통보하세요.',
    confirm: '수정한 설정을 관련 감사 도구로 재점검해 위반이 해소됐는지 확인하세요.',
  },
  'Authentication': {
    verify: (ev) => `${ev.affected_resource ?? '인증 서비스'}의 로그인 로그에서 실제 인증 시도 기록을 확인하세요.`,
    apply: '의심스러운 로그인이면 해당 계정 비밀번호를 재설정하고 MFA를 적용하세요.',
    confirm: '재설정 후 정상 로그인이 되는지, 의심 IP로부터 추가 시도가 없는지 확인하세요.',
  },
  default: {
    verify: (ev) => `"대상"(${ev.affected_resource ?? '-'})과 "소스 IP"(${ev.source_ip ?? '-'})가 가리키는 실제 시스템에 접속해, 같은 시간대의 로그(이벤트 로그/접근 로그/방화벽 로그 등)에서 이 기록과 대조해보세요.`,
    apply: () => '왼쪽 "대응 방안"에 적힌 조치를 해당 시스템에 관리자 권한으로 직접 수행하세요 — 이 도구는 조치를 자동으로 실행하지 않습니다.',
    confirm: () => '조치 후 같은 로그를 다시 확인하거나, 새로 수집한 로그를 이 앱에 다시 분석시켜 같은 위협이 재발하지 않는지 확인하세요.',
  },
}

function getCategoryGuide(ev) {
  const guide = CATEGORY_GUIDE[ev.category] ?? CATEGORY_GUIDE.default
  const resolve = (field) => (typeof field === 'function' ? field(ev) : field)
  return { verify: resolve(guide.verify), apply: resolve(guide.apply), confirm: resolve(guide.confirm) }
}

const SEVERITY_HINTS = {
  total: '지금까지 이 대시보드가 분석한 로그에서 나온 전체 이벤트 수(정상 트래픽 포함, 파일 업로드+텍스트 분석+실시간 모니터링 합산)입니다.',
  critical: '실제 침해나 심각한 공격 정황(예: 성공한 침입, 대규모 데이터 유출)입니다. 지금 바로 확인해 해당 계정·시스템을 격리·차단하는 등 즉시 조치하세요.',
  high: '진행 중인 공격 시도나 심각한 취약점 노출(예: 반복된 브루트포스, SQL 인젝션 시도)입니다. 오늘 안에 원인을 조사하고 필요한 조치를 취하세요.',
  medium: '의심스럽지만 아직 확정되지 않은 활동입니다. 즉시 조치보다는 반복되거나 심해지는지 추이를 지켜보며 관찰하세요.',
  low: '영향이 제한적이거나 정보성에 가까운 이상 징후입니다. 참고용으로 기록해두는 정도면 충분합니다.',
}

const SOURCE_LABELS = {
  live_monitor: '실시간 모니터링',
  manual_input: '텍스트 직접 입력',
}

function formatSourceLabel(filename) {
  return SOURCE_LABELS[filename] ?? filename ?? '텍스트 분석'
}

const SAMPLE_LOG_FILES = [
  {
    id: 'linux_auth',
    label: 'Linux 인증 로그 (SSH 브루트포스 포함)',
    file: '/samples/dashboard/linux-auth-log-sample.txt',
    where: 'Linux 서버에서 SSH/로그인 인증 기록을 남기는 로그입니다.',
    command: 'sudo tail -n 200 /var/log/auth.log   # Debian/Ubuntu\nsudo tail -n 200 /var/log/secure     # RHEL/CentOS',
  },
  {
    id: 'web_access',
    label: '웹 서버 접근 로그 (SQL 인젝션·스캔 포함)',
    file: '/samples/dashboard/web-access-log-sample.txt',
    where: 'nginx/Apache가 모든 HTTP 요청을 기록하는 접근 로그입니다.',
    command: 'tail -n 200 /var/log/nginx/access.log\ntail -n 200 /var/log/apache2/access.log',
  },
  {
    id: 'windows_security',
    label: 'Windows 보안 이벤트 로그 (로그온 실패+인코딩된 PowerShell)',
    file: '/samples/dashboard/windows-security-events-sample.txt',
    where: '대상 Windows PC/서버에서 PowerShell(관리자 권한 권장)로 조회합니다.',
    command: "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4688} -MaxEvents 200 | Format-Table -AutoSize",
  },
]

function formatTimestamp(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  } catch {
    return ''
  }
}

const PIE_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

function EventsTable({ events }) {
  const [expanded, setExpanded] = useState(null)

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-700">
          <tr>
            <th className="text-left px-4 py-3 text-slate-300">심각도</th>
            <th className="text-left px-4 py-3 text-slate-300">분류</th>
            <th className="text-left px-4 py-3 text-slate-300">설명</th>
            <th className="text-left px-4 py-3 text-slate-300">대상</th>
            <th className="text-left px-4 py-3 text-slate-300">소스 IP</th>
            <th className="text-left px-4 py-3 text-slate-300">대응 방안</th>
            <th className="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 && (
            <tr><td colSpan={7} className="text-center py-8 text-slate-500">이벤트 없음</td></tr>
          )}
          {events.map((ev, i) => {
            const isOpen = expanded === i
            const guide = getCategoryGuide(ev)
            return (
              <Fragment key={i}>
                <tr className="border-t border-slate-700 hover:bg-slate-750">
                  <td className="px-4 py-3"><SeverityBadge severity={ev.severity} /></td>
                  <td className="px-4 py-3 text-slate-300">{ev.category}</td>
                  <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{ev.description}</td>
                  <td className="px-4 py-3 text-slate-400 max-w-[10rem] truncate">{ev.affected_resource ?? '-'}</td>
                  <td className="px-4 py-3 font-mono text-slate-400">{ev.source_ip ?? '-'}</td>
                  <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{ev.remediation}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => setExpanded(isOpen ? null : i)}
                      className="text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2 whitespace-nowrap"
                    >
                      {isOpen ? '접기' : '방법 보기'}
                    </button>
                  </td>
                </tr>
                {isOpen && (
                  <tr className="bg-slate-900/60 border-t border-slate-700">
                    <td colSpan={7} className="px-4 py-4 space-y-3">
                      {ev._mode === 'mock' ? (
                        <div className="bg-slate-700/40 border border-slate-600 rounded-lg p-2.5 flex gap-2">
                          <FlaskConical size={13} className="text-slate-400 shrink-0 mt-0.5" />
                          <p className="text-xs text-slate-300">
                            <span className="font-medium text-slate-200">이 이벤트는 Mock 데모 데이터입니다.</span> 실제로 발생한 사건이 아니라 도구 사용법을 익히기 위한 가상의 예시라, 아래 확인 방법대로 실제 시스템을 조회해도 당연히 아무 기록이 없습니다(정상입니다 — "server-prod-01" 등도 실존하지 않는 예시 이름입니다). 실제 로그를 분석하려면 "분석" 탭에서 진짜 로그 파일을 업로드하거나 붙여넣어 보세요.
                          </p>
                        </div>
                      ) : (
                        <div className="bg-blue-950/30 border border-blue-500/20 rounded-lg p-2.5 flex gap-2">
                          <Info size={13} className="text-blue-400 shrink-0 mt-0.5" />
                          <p className="text-xs text-slate-300">
                            아래 명령들은 <span className="text-blue-300 font-medium">"대상"에 표시된 시스템({ev.affected_resource ?? '해당 시스템'})에 직접 접속(SSH·원격 데스크톱·관리 콘솔 등)한 뒤 그 시스템에서 실행</span>하는 것입니다 — 지금 이 화면을 보고 있는 PC에서 실행하는 것이 아닙니다. 그 시스템에 접근 권한이 없다면 담당자에게 요청하세요.
                          </p>
                        </div>
                      )}
                      <div className="grid md:grid-cols-3 gap-3">
                        <div className="bg-slate-800 rounded-lg p-3">
                          <p className="text-xs font-semibold text-cyan-400 mb-1.5 flex items-center gap-1"><Search size={12} /> ① 어디서 확인하나요</p>
                          <p className="text-xs text-slate-300 whitespace-pre-wrap">{guide.verify}</p>
                        </div>
                        <div className="bg-slate-800 rounded-lg p-3">
                          <p className="text-xs font-semibold text-amber-400 mb-1.5 flex items-center gap-1"><Wrench size={12} /> ② 어떻게 적용하나요</p>
                          <p className="text-xs text-slate-300 whitespace-pre-wrap">{guide.apply}</p>
                        </div>
                        <div className="bg-slate-800 rounded-lg p-3">
                          <p className="text-xs font-semibold text-green-400 mb-1.5 flex items-center gap-1"><CheckCircle2 size={12} /> ③ 적용됐는지 확인</p>
                          <p className="text-xs text-slate-300 whitespace-pre-wrap">{guide.confirm}</p>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default function Dashboard() {
  const [analyses, setAnalyses] = useState([])
  const [loading, setLoading] = useState(false)
  const [textInput, setTextInput] = useState('')
  const [activeTab, setActiveTab] = useState('overview')
  const [isMock, setIsMock] = useState(null)
  const [selectedAnalysis, setSelectedAnalysis] = useState(null)

  const [liveConnected, setLiveConnected] = useState(false)
  const [liveEvents, setLiveEvents] = useState([])
  const [injectText, setInjectText] = useState('')
  const [profiles, setProfiles] = useState([])
  const [profile, setProfile] = useState('generic')
  const [source, setSource] = useState('simulated') // 'simulated' | 'real'
  const [severityFilter, setSeverityFilter] = useState(null)
  const wsRef = useRef(null)

  const startLiveMonitoring = () => {
    if (wsRef.current) return
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/monitor/ws`)
    ws.onopen = () => {
      setLiveConnected(true)
      ws.send(JSON.stringify({ type: 'set_source', source }))
      ws.send(JSON.stringify({ type: 'set_profile', profile }))
    }
    ws.onclose = () => { setLiveConnected(false); wsRef.current = null }
    ws.onerror = () => { setLiveConnected(false) }
    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data)
      if (data.type !== 'event') return
      setLiveEvents(prev => [data, ...prev].slice(0, 30))
      setAnalyses(prev => [...prev, data])
    }
    wsRef.current = ws
  }

  const stopLiveMonitoring = () => {
    wsRef.current?.close()
    wsRef.current = null
    setLiveConnected(false)
  }

  const changeProfile = (newProfile) => {
    setProfile(newProfile)
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'set_profile', profile: newProfile }))
    }
  }

  const changeSource = (newSource) => {
    setSource(newSource)
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'set_source', source: newSource }))
    }
  }

  const sendInjectedLine = () => {
    if (!injectText.trim() || wsRef.current?.readyState !== WebSocket.OPEN) return
    wsRef.current.send(JSON.stringify({ type: 'inject', line: injectText.trim() }))
    setInjectText('')
  }

  useEffect(() => {
    axios.get('/api/monitor/profiles').then(res => setProfiles(res.data.profiles)).catch(() => {})
    return () => { wsRef.current?.close() }
  }, [])

  const fetchThreats = async () => {
    const res = await axios.get('/api/threats')
    setAnalyses(res.data.analyses)
  }

  const fetchMode = async () => {
    try {
      const res = await axios.get('/api/mode')
      setIsMock(res.data.effective_mode === 'mock')
    } catch {
      setIsMock(true)
    }
  }

  useEffect(() => {
    fetchMode()
    fetchThreats()
  }, [])

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/analyze/upload', form)
      setSelectedAnalysis(res.data)
      setActiveTab('detail')
      await fetchThreats()
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
      e.target.value = ''
    }
  }

  const handleTextAnalyze = async () => {
    if (!textInput.trim()) return
    setLoading(true)
    try {
      const res = await axios.post('/api/analyze/text', { content: textInput })
      setSelectedAnalysis(res.data)
      setActiveTab('detail')
      await fetchThreats()
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const handleClear = async () => {
    if (!confirm('모든 분석 결과를 삭제할까요?')) return
    await axios.delete('/api/threats')
    setAnalyses([])
    setSelectedAnalysis(null)
  }

  // Aggregate stats across all analyses
  const totalStats = analyses.reduce(
    (acc, a) => {
      const s = a.statistics ?? {}
      acc.critical += s.critical ?? 0
      acc.high += s.high ?? 0
      acc.medium += s.medium ?? 0
      acc.low += s.low ?? 0
      acc.info += s.info ?? 0
      acc.total += s.total_events ?? 0
      return acc
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  )

  const pieData = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .map((k) => ({ name: k, value: totalStats[k.toLowerCase()] }))
    .filter((d) => d.value > 0)

  const allEvents = analyses.flatMap((a) => (a.events ?? []).map((ev) => ({ ...ev, _mode: a.mode, _source: formatSourceLabel(a.filename) })))
  const filteredEvents = severityFilter ? allEvents.filter((ev) => ev.severity === severityFilter) : allEvents

  const toggleSeverityFilter = (level) => {
    setSeverityFilter((prev) => (prev === level ? null : level))
    setActiveTab('events')
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* Sub-header */}
      <header className="border-b border-slate-700 px-6 py-3 flex items-center gap-3">
        <div>
          <h1 className="text-base font-semibold">보안 로그 분석 대시보드</h1>
          <p className="text-xs text-slate-400 max-w-3xl">
            서버·방화벽·웹서버·애플리케이션 등 <b className="text-slate-300">어떤 시스템의 로그든</b> 텍스트로 붙여넣거나 파일로 업로드하면,
            AI가 브루트포스·SQL 인젝션·포트 스캔·악성코드 등 <b className="text-slate-300">위협 패턴(이벤트)</b>을 찾아 심각도별로 분류합니다.
            "실시간" 탭은 실제 로그 소스 없이 합성 로그로 동작을 보여주는 데모입니다.
          </p>
        </div>
        <div className="ml-auto flex gap-2">
          <button onClick={fetchThreats} className="p-2 rounded-lg hover:bg-slate-700 text-slate-400">
            <RefreshCw size={18} />
          </button>
          <button onClick={handleClear} className="p-2 rounded-lg hover:bg-slate-700 text-red-400">
            <Trash2 size={18} />
          </button>
        </div>
      </header>

      <div className="p-6 space-y-6">
        {/* Guide */}
        <GuidePanel title="보안 로그 분석 대시보드 사용 가이드" steps={DASHBOARD_STEPS} tips={DASHBOARD_TIPS} />

        {/* Stat Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard label="전체 이벤트" value={totalStats.total} color="border-slate-600" hint={SEVERITY_HINTS.total} />
          <StatCard label="Critical" value={totalStats.critical} color="border-red-600" hint={SEVERITY_HINTS.critical} onClick={() => toggleSeverityFilter('CRITICAL')} active={severityFilter === 'CRITICAL'} />
          <StatCard label="High" value={totalStats.high} color="border-orange-500" hint={SEVERITY_HINTS.high} onClick={() => toggleSeverityFilter('HIGH')} active={severityFilter === 'HIGH'} />
          <StatCard label="Medium" value={totalStats.medium} color="border-yellow-500" hint={SEVERITY_HINTS.medium} onClick={() => toggleSeverityFilter('MEDIUM')} active={severityFilter === 'MEDIUM'} />
          <StatCard label="Low" value={totalStats.low} color="border-blue-500" hint={SEVERITY_HINTS.low} onClick={() => toggleSeverityFilter('LOW')} active={severityFilter === 'LOW'} />
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-slate-700">
          {['overview', 'events', 'analyze', 'live', 'detail'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors flex items-center gap-1.5 ${
                activeTab === tab
                  ? 'border-b-2 border-blue-400 text-blue-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab === 'live' && liveConnected && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />}
              {tab === 'overview' ? '개요' : tab === 'events' ? '이벤트' : tab === 'analyze' ? '분석' : tab === 'live' ? '실시간' : '결과'}
            </button>
          ))}
        </div>

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <h2 className="text-sm font-semibold text-slate-400 mb-4">위협 분포</h2>
              {pieData.length > 0 ? (
                <div style={{ width: '100%', height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={PIE_COLORS[entry.name]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-slate-500 text-center py-16">분석 결과 없음</p>
              )}
            </div>
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <h2 className="text-sm font-semibold text-slate-400 mb-1">최근 분석 ({analyses.length}건)</h2>
              <p className="text-[11px] text-slate-500 mb-3">
                항목 하나 = 분석 1건(업로드/텍스트 분석 1회 또는 실시간 모니터링 주기 1회)입니다. 최신 순으로 표시되며, 클릭하면 "결과" 탭에서 전체 내용을 볼 수 있습니다.
              </p>
              <div className="space-y-2 max-h-52 overflow-y-auto">
                {analyses.length === 0 && <p className="text-slate-500 text-sm">없음</p>}
                {[...analyses].reverse().map((a) => (
                  <button
                    key={a.id}
                    onClick={() => { setSelectedAnalysis(a); setActiveTab('detail') }}
                    className="w-full text-left p-2 rounded-lg hover:bg-slate-700 flex items-start gap-2"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
                        <span>{formatSourceLabel(a.filename)}</span>
                        {a.target_label && <span>({a.target_label})</span>}
                        {a.created_at && <span>· {formatTimestamp(a.created_at)}</span>}
                      </div>
                      <p className="text-sm truncate">{a.summary || '요약 없음'}</p>
                    </div>
                    <SeverityBadge severity={a.threat_level} />
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Events Tab */}
        {activeTab === 'events' && (
          <div className="space-y-3">
            {severityFilter && (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-slate-400">필터:</span>
                <span className="flex items-center gap-1.5 bg-slate-700 rounded-full pl-3 pr-1.5 py-1">
                  <SeverityBadge severity={severityFilter} />
                  <button onClick={() => setSeverityFilter(null)} className="p-0.5 rounded-full hover:bg-slate-600 text-slate-400">
                    <X size={12} />
                  </button>
                </span>
                <span className="text-xs text-slate-500">{filteredEvents.length}건 표시 중 (개요 탭의 등급 카드를 다시 클릭하면 해제됩니다)</span>
              </div>
            )}
            <div className="bg-blue-950/30 border border-blue-500/20 rounded-xl p-3 flex gap-2">
              <Info size={13} className="text-blue-400 shrink-0 mt-0.5" />
              <p className="text-[11px] text-slate-300">{EVENTS_TABLE_HELP}</p>
            </div>
            <EventsTable events={filteredEvents} />
          </div>
        )}

        {/* Analyze Tab */}
        {activeTab === 'analyze' && (
          <div className="space-y-6">
            <div className="bg-blue-950/30 border border-blue-500/20 rounded-xl p-4">
              <p className="text-xs font-semibold text-blue-400 mb-2 flex items-center gap-1.5"><Info size={13} /> 어떤 로그를 올려야 하나요? 어디서 수집하나요?</p>
              <p className="text-[11px] text-slate-400 mb-3">
                로그온/인증 기록, 웹 서버 접근 로그, 방화벽 로그처럼 "누가 언제 무엇을 했는지"가 담긴 텍스트라면 무엇이든 분석할 수 있습니다.
                아래는 자주 쓰이는 소스 3종의 실제 수집 명령과, 그 형태를 흉내 낸 예시 파일입니다 — 예시 파일을 내려받아 그대로 업로드해보면 바로 분석 결과를 볼 수 있습니다.
              </p>
              <div className="grid md:grid-cols-3 gap-3">
                {SAMPLE_LOG_FILES.map((s) => (
                  <div key={s.id} className="bg-slate-900/60 border border-slate-700 rounded-lg p-3 space-y-2">
                    <p className="text-xs font-medium text-slate-200">{s.label}</p>
                    <p className="text-[11px] text-slate-500">{s.where}</p>
                    <div className="flex items-start gap-1.5">
                      <pre className="flex-1 bg-slate-950 border border-slate-700 rounded p-1.5 overflow-x-auto">
                        <code className="text-[10px] text-cyan-300 font-mono whitespace-pre">{s.command}</code>
                      </pre>
                      <CopyButton text={s.command} />
                    </div>
                    <a href={s.file} download className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 underline underline-offset-2">
                      <Download size={11} /> 예시 파일 다운로드
                    </a>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* File Upload */}
              <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 className="font-semibold mb-4 flex items-center gap-2"><Upload size={18} /> 로그 파일 업로드</h2>
                <label className="block border-2 border-dashed border-slate-600 rounded-xl p-8 text-center cursor-pointer hover:border-blue-500 transition-colors">
                  <input type="file" accept={UPLOAD_ACCEPT} className="hidden" onChange={handleFileUpload} />
                  <p className="text-slate-400">.log / .txt / .csv / .json / .docx / .pdf / .xlsx</p>
                  <p className="text-xs text-slate-500 mt-1">클릭하여 파일 선택 (업로드 즉시 자동 분석)</p>
                </label>
              </div>

              {/* Text Input */}
              <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h2 className="font-semibold mb-4 flex items-center gap-2"><AlertTriangle size={18} /> 텍스트 직접 입력</h2>
                <textarea
                  value={textInput}
                  onChange={(e) => setTextInput(e.target.value)}
                  placeholder="로그 내용을 여기에 붙여넣기..."
                  className="w-full h-36 bg-slate-900 border border-slate-600 rounded-lg p-3 text-sm font-mono resize-none focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={handleTextAnalyze}
                  disabled={loading || !textInput.trim()}
                  className="mt-3 w-full py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg font-medium transition-colors"
                >
                  {loading ? '분석 중...' : '분석'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Live Monitoring Tab */}
        {activeTab === 'live' && (
          <div className="space-y-4">
            {source === 'simulated' ? (
              <div className="bg-amber-950/20 border border-amber-500/20 rounded-xl p-4 flex gap-2">
                <Info size={14} className="text-amber-400 shrink-0 mt-0.5" />
                <p className="text-xs text-slate-300">
                  <b className="text-amber-300">지금은 시뮬레이션입니다</b> — 프로필을 골라도 실제 시스템에 접속하지 않고, 서버가 골라진 유형(웹 서버·사내망 등)과
                  비슷한 <b className="text-amber-300">가상의 로그를 계속 만들어내는 데모</b>입니다. 아래 "수집 대상"을 "실제 이 PC(Windows)"로 바꾸면
                  이 PC의 진짜 신호를 조회합니다. 다른 서버를 대상으로 하려면
                  <a href="/attack-monitor" className="underline underline-offset-2 hover:text-amber-200"> 실시간 공격 모니터링 & 대응</a>의 원격 대상 지정 기능을 이용하세요.
                </p>
              </div>
            ) : (
              <div className="bg-green-950/20 border border-green-500/20 rounded-xl p-4 flex gap-2">
                <Info size={14} className="text-green-400 shrink-0 mt-0.5" />
                <p className="text-xs text-slate-300">
                  <b className="text-green-300">지금은 이 PC의 실제 신호를 조회합니다</b>(로그온 실패·Defender 탐지·리스닝 포트 변화 등, 20초 주기) — 시뮬레이션이 아닙니다.
                  관리자 권한이 없으면 일부 항목(방화벽 로깅 등)은 조회되지 않을 수 있습니다. 다른 서버를 대상으로 하려면
                  <a href="/attack-monitor" className="underline underline-offset-2 hover:text-green-200"> 실시간 공격 모니터링 & 대응</a>에서 원격 대상을 지정하세요.
                </p>
              </div>
            )}

            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 space-y-3">
              <div>
                <p className="text-xs font-semibold text-slate-400 mb-1.5">수집 대상</p>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    onClick={() => changeSource('simulated')}
                    className={`text-xs font-medium px-3 py-1.5 rounded-full transition-colors ${
                      source === 'simulated' ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    시뮬레이션 (가상 데이터)
                  </button>
                  <button
                    onClick={() => changeSource('real')}
                    className={`text-xs font-medium px-3 py-1.5 rounded-full transition-colors ${
                      source === 'real' ? 'bg-green-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    실제 이 PC (Windows)
                  </button>
                </div>
              </div>

              {source === 'simulated' && (
                <div>
                  <p className="text-xs font-semibold text-slate-400 mb-1.5">가상 대상 시스템 (시뮬레이션 유형 선택)</p>
                  <p className="text-[11px] text-slate-500 mb-2">
                    <span className="text-slate-400 font-medium">어떻게 활용하나요: </span>
                    프로필마다 만들어내는 로그의 성격이 다릅니다 — "웹 서버"는 nginx 접근 로그 위주로 SQL 인젝션·스캔 시도가,
                    "사내망 업무 시스템"은 파일서버·VPN·AD 로그 위주로 권한 오남용·내부 확산 시도가 섞여 나옵니다.
                    이 도구(AI 또는 오프라인 규칙)가 서로 다른 환경의 로그에서 실제로 무엇을 위협으로 분류하는지 비교해보고 싶을 때 골라서 사용하세요.
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {profiles.map((p) => (
                      <button
                        key={p.id}
                        onClick={() => changeProfile(p.id)}
                        className={`text-xs font-medium px-3 py-1.5 rounded-full transition-colors ${
                          profile === p.id ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                        }`}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-slate-700">
                <div className="flex items-center gap-2">
                  <Radio size={18} className={liveConnected ? 'text-red-400' : 'text-slate-500'} />
                  <span className="text-sm font-medium">
                    {liveConnected ? `모니터링 중 — ${source === 'real' ? '20초' : '8초'}마다 자동 분석` : '모니터링 중지됨'}
                  </span>
                  {liveConnected && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
                </div>
                <button
                  onClick={liveConnected ? stopLiveMonitoring : startLiveMonitoring}
                  className={`ml-auto flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    liveConnected ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
                  }`}
                >
                  {liveConnected ? <><Square size={14} /> 모니터링 중지</> : <><Play size={14} /> 모니터링 시작</>}
                </button>
              </div>
            </div>

            {source === 'simulated' && (
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <p className="text-xs font-semibold text-slate-400 mb-1">이벤트 주입 (다음 분석 주기에 포함됨, 시뮬레이션 전용)</p>
                <p className="text-[11px] text-slate-500 mb-2">
                  <span className="text-slate-400 font-medium">어떻게 활용하나요: </span>
                  실제 시스템에 영향을 주지 않고, 궁금한 로그 한 줄을 입력해 [전송]을 누르면 다음 분석 주기(최대 8초 후)에 합성 로그 배치에 섞여 들어갑니다.
                  예를 들어 직접 본 의심스러운 로그나 특정 공격 패턴 문자열을 넣어보면, 이 도구가 그것을 어떤 심각도·분류로 판정하고 어떤 대응 방안을 제시하는지 곧바로 확인할 수 있습니다 —
                  "분석" 탭에서 파일을 올리지 않고도 한 줄만 빠르게 테스트해볼 때 유용합니다.
                </p>
                <div className="flex gap-2">
                  <input
                    value={injectText}
                    onChange={e => setInjectText(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && sendInjectedLine()}
                    placeholder='예: sshd: Failed password for root from 1.2.3.4 port 22 ssh2'
                    disabled={!liveConnected}
                    className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                  <button
                    onClick={sendInjectedLine}
                    disabled={!liveConnected || !injectText.trim()}
                    className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-40 rounded-lg text-sm"
                  >
                    <Send size={14} /> 전송
                  </button>
                </div>
              </div>
            )}

            <div className="space-y-2">
              {liveEvents.length === 0 && (
                <p className="text-slate-500 text-center py-12">
                  {liveConnected ? '첫 분석 주기를 기다리는 중...' : '[모니터링 시작]을 누르면 실시간 피드가 여기 표시됩니다.'}
                </p>
              )}
              {liveEvents.map((ev, i) => (
                <div key={i} className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                  <div className="flex items-center gap-2 mb-2">
                    <SeverityBadge severity={ev.threat_level} />
                    <span className="text-xs text-slate-500">{ev.events?.length ?? 0}개 이벤트</span>
                    {ev.target_label && <span className="text-[10px] text-slate-500">· {ev.target_label}</span>}
                    {ev.mode && (
                      <span className={`text-[10px] font-semibold ${(MODE_BADGE[ev.mode] ?? MODE_BADGE.offline).color}`}>
                        {(MODE_BADGE[ev.mode] ?? MODE_BADGE.offline).label}
                      </span>
                    )}
                    <span className="ml-auto text-xs text-slate-500">{new Date().toLocaleTimeString('ko-KR')}</span>
                  </div>
                  {ev.mode && (
                    <p className="text-[11px] text-slate-500 mb-1.5">{ev.fallback_reason || MODE_EXPLANATION[ev.mode]}</p>
                  )}
                  <p className="text-sm text-slate-300">{ev.summary}</p>
                  {ev.events?.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {ev.events.map((e, j) => (
                        <div key={j} className="text-xs text-slate-400 flex gap-2">
                          <SeverityBadge severity={e.severity} />
                          <span>{e.category}: {e.description}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Detail Tab */}
        {activeTab === 'detail' && (
          <div className="space-y-4">
            {!selectedAnalysis ? (
              <p className="text-slate-500 text-center py-12">분석 결과를 선택하거나 로그를 분석하세요.</p>
            ) : (
              <>
                <ModeBanner result={selectedAnalysis} />
                <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="flex items-center gap-1.5 text-xs text-slate-500">
                        <span>{formatSourceLabel(selectedAnalysis.filename)}</span>
                        {selectedAnalysis.target_label && <span>({selectedAnalysis.target_label})</span>}
                        {selectedAnalysis.created_at && <span>· {formatTimestamp(selectedAnalysis.created_at)}</span>}
                      </div>
                      <p className="text-sm text-slate-300 mt-1">{selectedAnalysis.summary}</p>
                    </div>
                    <SeverityBadge severity={selectedAnalysis.threat_level} />
                  </div>
                  <div className="mt-3 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                    <AlertTriangle size={13} className="text-amber-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-slate-300">
                      <span className="text-amber-300 font-medium">지금 해야 할 일: </span>
                      {THREAT_ACTION_GUIDANCE[selectedAnalysis.threat_level] ?? THREAT_ACTION_GUIDANCE.INFO}
                    </p>
                  </div>
                </div>
                <div className="bg-blue-950/30 border border-blue-500/20 rounded-xl p-3 flex gap-2">
                  <Info size={13} className="text-blue-400 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-slate-300">{EVENTS_TABLE_HELP}</p>
                </div>
                <EventsTable events={(selectedAnalysis.events ?? []).map((ev) => ({ ...ev, _mode: selectedAnalysis.mode, _source: formatSourceLabel(selectedAnalysis.filename) }))} />
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
