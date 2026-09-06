import { useState } from 'react'
import axios from 'axios'
import { Search, Trash2, Copy, CheckCircle, XCircle, AlertTriangle, HelpCircle, Globe, Hash, Mail, Wifi, Cloud, Server, Terminal, WifiOff, FlaskConical, Info, Download, ShieldAlert } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import FileUploadButton from '../components/FileUploadButton'
import CollectionGuide from '../components/CollectionGuide'

const VERDICT_CONFIG = {
  MALICIOUS:  { color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30',    icon: XCircle,       label: '악성' },
  SUSPICIOUS: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', icon: AlertTriangle, label: '의심' },
  CLEAN:      { color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30',  icon: CheckCircle,   label: '정상' },
  UNKNOWN:    { color: 'text-slate-400',  bg: 'bg-slate-700/50 border-slate-600',     icon: HelpCircle,    label: '불명' },
}

const TYPE_CONFIG = {
  ip:      { icon: Wifi,   label: 'IP',     color: 'text-blue-400'   },
  domain:  { icon: Globe,  label: '도메인',  color: 'text-purple-400' },
  hash:    { icon: Hash,   label: '해시',   color: 'text-orange-400' },
  email:   { icon: Mail,   label: '이메일', color: 'text-pink-400'   },
  unknown: { icon: Search, label: '?',      color: 'text-slate-500'  },
}

const CONF_COLOR = (c) => c >= 80 ? 'text-red-400' : c >= 50 ? 'text-yellow-400' : 'text-slate-400'

const MODE_BADGE = {
  cloud:      { icon: Cloud,        label: '외부 AI API로 분석됨', color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  local:      { icon: Server,       label: '로컬 LLM으로 분석됨',    color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/30' },
  claude_cli: { icon: Terminal,     label: 'Claude Code CLI로 분석됨(구독)', color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/30' },
  offline:    { icon: WifiOff,      label: '오프라인 규칙 기반으로 분석됨(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  mock:       { icon: FlaskConical, label: 'Mock 데모 데이터 (학습용, 실제 분석 아님)', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
}

function ModeBanner({ mode, fallbackReason, engineNote }) {
  if (!mode) return null
  const cfg = MODE_BADGE[mode] ?? MODE_BADGE.offline
  const Icon = cfg.icon
  // "(폐쇄망)"은 실제로 인터넷이 안 되는 경우를 위한 표현인데, fallbackReason이 있다는 건
  // 인터넷은 되지만 AI 호출 자체가 실패(크레딧 소진 등)해서 대체됐다는 뜻이라 그대로 두면
  // "내 네트워크가 문제"라고 오해할 수 있다 — 이 경우엔 라벨에서 그 표현을 바꿔준다.
  const label = (mode === 'offline' && fallbackReason)
    ? cfg.label.replace('(폐쇄망)', '(AI 호출 실패로 대체)')
    : cfg.label
  return (
    <div className={`border rounded-xl p-3 flex items-start gap-2 ${cfg.bg}`}>
      <Icon size={14} className={`${cfg.color} shrink-0 mt-0.5`} />
      <div>
        <p className={`text-xs font-semibold ${cfg.color}`}>{label}</p>
        {fallbackReason && <p className="text-xs text-slate-400 mt-1">{fallbackReason}</p>}
        {engineNote && <p className="text-xs text-slate-400 mt-1">{engineNote}</p>}
      </div>
    </div>
  )
}

const IOC_STEPS = [
  '텍스트 박스에 분석할 IoC를 한 줄에 하나씩 입력합니다. (IP, 도메인, 해시, 이메일 혼합 가능)',
  '[IoC 분석] 버튼을 클릭합니다.',
  '결과 테이블에서 각 IoC의 판정(악성·의심·정상), 신뢰도, 카테고리를 확인합니다.',
  '행을 클릭하면 상세 설명과 권장 조치를 볼 수 있습니다.',
  '우측 상단 통계 카드로 전체 위협 현황을 한눈에 파악합니다.',
]
const IOC_TIPS = [
  'IP 주소: 192.168.1.1 형식',
  '도메인/URL: example.com 또는 https://example.com 형식',
  '파일 해시: MD5(32자리), SHA1(40자리), SHA256(64자리) 16진수',
  '이메일 주소: user@domain.com 형식',
  '한 번에 최대 50개까지 일괄 분석 가능합니다.',
  '폐쇄망(인터넷 없음)에서도 동작하지만, 오프라인에서는 사설 IP·타이포스쿼팅 패턴·해시 형식처럼 로컬에서 확인 가능한 것만 판정하고 나머지는 정직하게 "불명"으로 표시합니다 — 자세한 내용은 위 안내 박스 참고.',
]

const SAMPLE_IOCS = `185.220.101.45
paypa1-secure.verify-now.com
44d88612fea8a8f36de82e1278abb02f
admin@secure-bank-alert.net
8.8.8.8
https://malware-download.ru/payload.exe
d41d8cd98f00b204e9800998ecf8427e
noreply@github.com`

// "어디에서 예시와 같은 내용을 가져올 수 있는지" 질문에 대한 답 — 실제로 IoC를 수집하는
// 출처와 방법. App3/7/24 등에서 쓰던 CollectionGuide 컴포넌트를 그대로 재사용.
const IOC_COLLECTION_ITEMS = [
  {
    category: 'IP 주소',
    where: '방화벽/IDS·IPS 로그의 출발지 IP, 웹서버 access log, SSH·RDP 로그온 실패 이벤트, VPN 접속 로그, 클라우드 VPC Flow Log',
    how: '의심스러운 접근 시도나 비정상 트래픽의 출발지 IP를 로그에서 찾아 붙여넣으세요. App 1(대시보드)이나 App 23(실시간 공격 모니터링)이 이미 이 PC에서 탐지한 source_ip를 그대로 가져와도 됩니다.',
    commands: [
      '# Windows — 최근 로그온 실패(4625) 이벤트에서 IP 추출',
      "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |",
      "  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} } | Select-Object '#text'",
      '',
      '# Linux — SSH 인증 실패 로그에서 IP 추출',
      "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort -u",
    ],
    note: '위 Windows 명령이 "지정한 선택 조건과 일치하는 이벤트를 찾을 수 없습니다" 오류를 내는 건 흔한 정상 상황입니다 — 실제로 로그온 실패가 없었을 수도 있지만, 이 PC에 로그온 실패 감사 정책 자체가 꺼져 있어서 애초에 4625 이벤트가 기록되지 않는 경우도 많습니다(이 프로젝트에서 실시간 공격 모니터링(App23) 점검 중 실제로 확인된 사례). 지금 당장 실제 신호로 테스트하고 싶다면 App23의 "실제 시스템 모니터링" 탭에서 이 PC의 현재 상태를 바로 조회하는 방법도 있습니다.',
  },
  {
    category: '도메인 / URL',
    where: '이메일 본문의 링크, 프록시·DNS 로그, 브라우저 히스토리, 사용자가 신고한 피싱 메일',
    how: '이메일이나 메시지 안의 의심스러운 링크, 또는 접속 로그에 남은 낯선 도메인을 붙여넣으세요.',
    commands: ['# Windows — 최근 DNS 조회 캐시', 'Get-DnsClientCache | Select-Object Name, Data'],
  },
  {
    category: '파일 해시',
    where: '의심스러운 다운로드 파일·이메일 첨부파일, EDR/백신 알림',
    how: '실행하지 말고, 해시값만 계산해 붙여넣으세요.',
    commands: ['# Windows', 'Get-FileHash -Algorithm SHA256 <파일경로>', '', '# Linux / macOS', 'sha256sum <파일경로>'],
    note: '파일 자체를 업무 PC에서 직접 실행해 확인하지 마세요 — 해시값만 계산하거나 온라인 샌드박스(any.run 등)를 이용하세요.',
  },
  {
    category: '이메일 주소',
    where: '피싱 의심 메일의 발신자, 스팸 신고함',
    how: '메일 헤더에서 실제 발신 주소(From, Reply-To)를 확인해 붙여넣으세요 — 표시 이름이 아니라 실제 주소여야 합니다.',
  },
  {
    category: '실제로 알려진 악성 사례로 테스트하고 싶다면',
    where: 'abuse.ch(URLhaus·ThreatFox·Feodo Tracker), VirusTotal, AbuseIPDB, AlienVault OTX 같은 공개 위협 인텔리전스 피드',
    how: '아래 [실제 악성 사례 가져오기] 버튼을 누르면 abuse.ch URLhaus가 방금 막 새로 보고받은 실제 악성 URL을 자동으로 가져와 입력창을 채웁니다 — 직접 사이트에 방문할 필요 없이 이 앱에서 바로 테스트해볼 수 있습니다.',
    note: '가져온 URL은 실제 악성코드 배포지일 수 있습니다 — 절대 브라우저로 직접 열지 말고, 텍스트로만 다루세요.',
  },
]

// "VirusTotal/AbuseIPDB/WHOIS에서 확인하세요"라고만 하면 실제로 어떻게 하는지 모른다는
// 지적에 대한 답 — 사이트 주소와 클릭 순서까지 구체적으로 명시. SUSPICIOUS/UNKNOWN 양쪽에서
// 재사용한다.
const EXTERNAL_CHECK_STEPS = [
  '해시·URL 확인: virustotal.com에 접속해 상단 검색창에 해시값 또는 URL을 그대로 붙여넣고 Enter를 누르세요 — 여러 백신 엔진 중 몇 개가 악성으로 탐지했는지 나옵니다(빨간 표시가 많을수록 위험).',
  'IP 확인: abuseipdb.com에 접속해 "Check an IP Address" 검색창에 IP를 입력하세요 — "Confidence of Abuse"(악용 신뢰도) 퍼센트와 신고 이력이 나옵니다.',
  '도메인 확인: who.is 또는 whois.com에 도메인을 입력하면 등록일·등록자 정보가 나옵니다(최근에 막 등록된 도메인일수록 의심). 터미널에서 확인하려면 취약점 스캐너(App3)의 정보 수집 가이드에 있는 whois 안내(Windows에는 기본 포함돼 있지 않음 — Sysinternals whois64.exe 또는 WSL 권장)를 참고하세요.',
]

// "분석 결과를 보고 다음으로 어떻게 대응해야 하는지" — 판정(verdict)별로 실제 무엇을,
// 어디서 해야 하는지 구체화. 기존 item.recommendation(AI/오프라인 엔진이 그때그때 생성하는
// 한 문장)과 달리, 판정 등급 자체에 대한 일반적이지만 구체적인 절차를 고정으로 제공한다.
const VERDICT_ACTION_GUIDE = {
  MALICIOUS: {
    summary: '악성으로 확정된 지표입니다 — 즉시 대응하세요.',
    steps: [
      'IP: 방화벽/보안그룹에서 즉시 차단하세요 (Windows: New-NetFirewallRule -Direction Inbound -RemoteAddress <IP> -Action Block, 방화벽 정책 감사기(App16)로 규칙 반영 여부 점검).',
      '도메인·URL: 사내 DNS 싱크홀/웹 프록시 차단 목록에 추가하세요. 이 URL로 직접 접속(브라우저로 열기)하지 마세요.',
      '파일 해시: 해당 해시를 EDR/백신 격리(차단) 목록에 추가하고, 이 해시가 실행된 적 있는 모든 호스트를 전체 검사하세요.',
      '이메일: 발신 주소를 메일 게이트웨이 차단 목록에 추가하고, 같은 발신자의 다른 수신 메일도 회수(quarantine)하세요.',
      '피해가 의심되면 여기서 멈추지 말고 인시던트 리스폰스(App5)로 넘어가 격리·조사·복구 절차를 진행하세요.',
    ],
  },
  SUSPICIOUS: {
    summary: '확정된 악성은 아니지만 주의가 필요합니다.',
    steps: [
      '해당 지표와 관련된 트래픽·접근을 모니터링 대상에 추가하세요(즉시 차단보다는 관찰).',
      '외부 AI API 또는 로컬 LLM이 실제로 응답 가능한 상태에서 다시 분석해보세요 — 지금 오프라인 모드라면 휴리스틱(타이포스쿼팅 패턴 등)만으로 판단해 확정력이 낮습니다. 어떤 모드인지는 화면 상단 AI 모드 배지에서 확인할 수 있습니다.',
      ...EXTERNAL_CHECK_STEPS,
    ],
  },
  CLEAN: {
    summary: '구조적으로 안전이 확인됐습니다 — 추가 조치가 필요 없습니다.',
    steps: ['사설 IP 대역 등 위협 지표가 될 수 없는 것으로 확인된 경우입니다. 별도 조치 없이 넘어가도 됩니다.'],
  },
  UNKNOWN: {
    summary: '판정할 수 없는 상태입니다 — "안전하다"는 뜻이 아니라 "확인 못 했다"는 뜻입니다.',
    steps: [
      '외부 AI API 또는 로컬 LLM이 실제로 응답 가능한 상태에서 다시 분석해보세요 — 지금은 그중 어느 것도 쓸 수 없어(오프라인 모드) 정보가 부족한 채로 판정했을 수 있습니다. 화면 상단 AI 모드 배지를 눌러 지금 어떤 모드인지, 클릭해서 전환할 수도 있습니다.',
      ...EXTERNAL_CHECK_STEPS,
      '실제 침해가 의심되는 상황이라면 판정을 기다리지 말고 예방적으로 모니터링을 강화하거나 격리를 검토하세요.',
    ],
  },
}

function StatBadge({ label, count, color }) {
  return (
    <div className={`flex flex-col items-center px-4 py-2 rounded-lg bg-slate-800 border ${color}`}>
      <span className="text-xl font-bold">{count}</span>
      <span className="text-xs text-slate-400">{label}</span>
    </div>
  )
}

function IoCRow({ item, onClick, selected }) {
  const vcfg = VERDICT_CONFIG[item.verdict] ?? VERDICT_CONFIG.UNKNOWN
  const tcfg = TYPE_CONFIG[item.ioc_type] ?? TYPE_CONFIG.unknown
  const Icon = vcfg.icon
  const TypeIcon = tcfg.icon

  return (
    <div
      onClick={onClick}
      className={`cursor-pointer border rounded-xl p-3 transition-all ${vcfg.bg} ${selected ? 'ring-2 ring-blue-500' : 'hover:brightness-110'}`}
    >
      <div className="flex items-center gap-3">
        <Icon size={16} className={`${vcfg.color} shrink-0`} />
        <TypeIcon size={13} className={`${tcfg.color} shrink-0`} />
        <span className="font-mono text-xs text-slate-200 flex-1 truncate">{item.ioc}</span>
        <span className="text-xs text-slate-400 hidden sm:block">{item.category}</span>
        <span className={`text-xs font-bold ${CONF_COLOR(item.confidence)} shrink-0`}>{item.confidence}%</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${vcfg.color} bg-black/20 shrink-0`}>{vcfg.label}</span>
      </div>
    </div>
  )
}

function IoCDetail({ item }) {
  const vcfg = VERDICT_CONFIG[item.verdict] ?? VERDICT_CONFIG.UNKNOWN
  const tcfg = TYPE_CONFIG[item.ioc_type] ?? TYPE_CONFIG.unknown
  const VIcon = vcfg.icon

  return (
    <div className={`border rounded-xl p-5 space-y-3 ${vcfg.bg}`}>
      <div className="flex items-start gap-3">
        <VIcon size={22} className={`${vcfg.color} mt-0.5 shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-bold ${vcfg.color}`}>{vcfg.label}</span>
            <span className="text-xs text-slate-400">신뢰도 {item.confidence}%</span>
            <span className={`text-xs px-1.5 py-0.5 rounded bg-black/20 ${tcfg.color}`}>{tcfg.label}</span>
          </div>
          <p className="font-mono text-xs text-slate-300 mt-1 break-all">{item.ioc}</p>
        </div>
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-400 mb-1">카테고리</p>
        <p className="text-sm text-slate-200">{item.category}</p>
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-400 mb-1">분석 결과</p>
        <p className="text-sm text-slate-300 leading-relaxed">{item.description}</p>
      </div>

      {item.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {item.tags.map((t, i) => (
            <span key={i} className="text-xs px-2 py-0.5 bg-slate-700 rounded-full text-slate-300">{t}</span>
          ))}
        </div>
      )}

      <div className="bg-slate-800/60 rounded-lg p-3">
        <p className="text-xs font-semibold text-blue-400 mb-1">권장 조치</p>
        <p className="text-xs text-slate-300 leading-relaxed">{item.recommendation}</p>
      </div>

      {VERDICT_ACTION_GUIDE[item.verdict] && (
        <div className="bg-slate-800/60 rounded-lg p-3">
          <p className="text-xs font-semibold text-blue-400 mb-1 flex items-center gap-1.5">
            <ShieldAlert size={13} /> 구체적으로 어떻게 대응하나요
          </p>
          <p className="text-xs text-slate-300 mb-1.5">{VERDICT_ACTION_GUIDE[item.verdict].summary}</p>
          <ul className="space-y-1 list-disc list-inside">
            {VERDICT_ACTION_GUIDE[item.verdict].steps.map((s, i) => (
              <li key={i} className="text-xs text-slate-400 leading-relaxed">{s}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default function IoCAnalyzer() {
  const [content, setContent]     = useState('')
  const [loading, setLoading]     = useState(false)
  const [results, setResults]     = useState([])
  const [selected, setSelected]   = useState(null)
  const [copied, setCopied]       = useState(false)
  const [fetchingReal, setFetchingReal] = useState(false)
  const [realFetchError, setRealFetchError] = useState('')

  const analyze = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResults([])
    setSelected(null)
    try {
      const res = await axios.post('/api/ioc/analyze', { content: body })
      setResults(res.data.results)
      if (res.data.results.length > 0) setSelected(0)
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const loadSample = () => {
    setContent(SAMPLE_IOCS)
    setResults([])
    setSelected(null)
  }

  const loadRealExamples = async () => {
    setFetchingReal(true)
    setRealFetchError('')
    try {
      const res = await axios.get('/api/ioc/real-examples', { params: { limit: 6 } })
      setContent(res.data.iocs.join('\n'))
      setResults([])
      setSelected(null)
    } catch (err) {
      setRealFetchError(err.response?.data?.detail ?? err.message)
    } finally {
      setFetchingReal(false)
    }
  }

  const copyResult = () => {
    if (!results.length) return
    const text = results.map(r =>
      `[${r.verdict}] ${r.ioc} (${r.ioc_type}) - ${r.category} - 신뢰도 ${r.confidence}%\n  ${r.description}`
    ).join('\n\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const counts = results.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Search className="text-cyan-400" size={26} /> IoC 분석기
          </h1>
          <p className="text-slate-400 text-sm mt-1">IP, 도메인, 파일 해시, 이메일을 입력하면 AI가 알려진 악성 지표인지 판별합니다.</p>
        </div>

        <div className="bg-cyan-950/30 border border-cyan-500/20 rounded-xl p-4 flex gap-3">
          <Info className="text-cyan-400 shrink-0 mt-0.5" size={18} />
          <div className="text-sm text-slate-300 space-y-2">
            <p>
              <span className="font-semibold text-cyan-300">IoC(Indicator of Compromise, 침해 지표)란? </span>
              시스템이 공격당했거나 악성 행위와 관련됐음을 나타내는 흔적입니다 — 악성코드가 통신하는 IP, 피싱에
              쓰인 도메인, 멀웨어 파일의 해시값, 피싱 메일 발신 주소 등이 대표적인 예입니다.
            </p>
            <p>
              <span className="font-semibold text-cyan-300">어느 경우에 사용하나요? </span>
              로그·이메일·알림 등에서 낯선 IP·도메인·발신자를 발견해 알려진 악성 지표인지 빠르게 확인하고 싶을 때,
              사고 대응 중 공격자가 남긴 흔적을 식별해 차단 등 후속 조치를 판단할 때, 위협 인텔리전스 보고서에서
              얻은 IoC 목록을 한 번에 일괄 검증하고 싶을 때 사용하세요. AI 보안 분석 대시보드나 실시간 공격
              모니터링에서 발견된 출발지 IP를 여기 붙여넣어 추가로 확인하는 용도로도 씁니다.
            </p>
            <p>
              <span className="font-semibold text-cyan-300">폐쇄망(인터넷 없는 환경)에서도 되나요? </span>
              됩니다 — 다만 정직하게 알려드리면, IoC의 악성 여부 판정은 원래 VirusTotal·AbuseIPDB 같은 위협
              인텔리전스 데이터베이스 대조가 필요한 작업이라 인터넷 없이는 확정적으로 판단할 수 없습니다. 오프라인
              모드에서는 사설 IP 대역, 알려진 브랜드 타이포스쿼팅 패턴, 해시 형식 유효성처럼 로컬에서 구조적으로
              확인 가능한 것만 판정하고, 나머지는 지어내지 않고 정직하게 "불명(UNKNOWN)"으로 표시합니다. 공인
              IP·일반 도메인·파일 평판처럼 확정적 판정이 필요하면 인터넷이 되는 환경에서 다시 조회하세요.
            </p>
            <p>
              <span className="font-semibold text-cyan-300">여기서 말하는 "AI"가 정확히 뭔가요? </span>
              상황에 따라 셋 중 하나입니다 — <b>외부 AI API</b>(인터넷으로 Anthropic Claude API를 호출, 이
              프로젝트에서 "AI"의 기본값), <b>로컬 LLM</b>(사내망에 별도로 구축해둔 오픈소스 AI 서버 호출, 일반
              인터넷 없이도 동작), <b>오프라인 규칙 기반</b>(AI가 아니라 정해진 패턴 매칭, 위 설명이 이것). 지금
              어떤 게 쓰이고 있는지는 화면 상단(NavBar)의 AI 모드 배지를 눌러보면 각 모드의 설명과 함께 바로
              확인할 수 있습니다.
            </p>
          </div>
        </div>

        <GuidePanel title="IoC 분석기 사용 가이드" steps={IOC_STEPS} tips={IOC_TIPS} />

        <CollectionGuide
          items={IOC_COLLECTION_ITEMS}
          accentColor="text-cyan-300"
          title="어디에서 IoC를 가져올 수 있나요"
        />

        <div className="grid lg:grid-cols-5 gap-6">
          {/* Input */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex justify-between items-center gap-2 flex-wrap">
              <p className="text-sm font-medium text-slate-300">IoC 목록 입력 <span className="text-slate-500 font-normal">(한 줄에 하나)</span></p>
              <div className="flex items-center gap-2 shrink-0">
                <button onClick={loadSample} className="text-xs text-cyan-400 hover:text-cyan-300">예시 불러오기</button>
                <button
                  onClick={loadRealExamples}
                  disabled={fetchingReal}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 disabled:text-slate-600"
                  title="abuse.ch URLhaus에서 방금 보고된 실제 악성 URL을 가져옵니다"
                >
                  <Download size={12} className={fetchingReal ? 'animate-pulse' : ''} />
                  {fetchingReal ? '가져오는 중...' : '실제 악성 사례 가져오기'}
                </button>
                <FileUploadButton onExtracted={(text) => { setContent(text); analyze(text) }} />
              </div>
            </div>
            {realFetchError && (
              <p className="text-xs text-amber-400">{realFetchError} — 대신 [예시 불러오기]를 사용하세요.</p>
            )}

            <textarea
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={"185.220.101.45\npaypa1-secure.verify-now.com\n44d88612fea8a8f36de82e1278abb02f\nadmin@phish.net"}
              rows={14}
              className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-xs font-mono resize-none focus:outline-none focus:border-cyan-500 placeholder-slate-600"
            />

            <button
              onClick={() => analyze()}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Search size={16} />
              {loading ? '분석 중...' : 'IoC 분석'}
            </button>
            <p className="text-[11px] text-slate-500 -mt-1.5">
              상황에 따라 외부 AI API·로컬 LLM·오프라인 규칙 중 하나로 분석됩니다 — 지금 어떤 모드인지는
              화면 상단(NavBar)의 AI 모드 배지에서 항상 확인할 수 있고, 분석 후에는 결과 상단 배너에도
              표시됩니다.
            </p>

            {/* Stats */}
            {results.length > 0 && (
              <div className="grid grid-cols-4 gap-2">
                <StatBadge label="악성" count={counts.MALICIOUS ?? 0} color="border-red-500/40" />
                <StatBadge label="의심" count={counts.SUSPICIOUS ?? 0} color="border-yellow-500/40" />
                <StatBadge label="정상" count={counts.CLEAN ?? 0} color="border-green-500/40" />
                <StatBadge label="불명" count={counts.UNKNOWN ?? 0} color="border-slate-600" />
              </div>
            )}

            {results.length > 0 && (() => {
              const worst = counts.MALICIOUS ? 'MALICIOUS' : counts.SUSPICIOUS ? 'SUSPICIOUS' : counts.UNKNOWN ? 'UNKNOWN' : 'CLEAN'
              const g = VERDICT_ACTION_GUIDE[worst]
              const vcfg = VERDICT_CONFIG[worst]
              return (
                <div className={`border rounded-xl p-3 ${vcfg.bg}`}>
                  <p className={`text-xs font-semibold ${vcfg.color}`}>지금 뭘 해야 하나요: {g.summary}</p>
                  <p className="text-[11px] text-slate-400 mt-1">항목을 클릭하면 그 지표에 맞는 구체적인 대응 절차가 나옵니다.</p>
                </div>
              )
            })()}
          </div>

          {/* Results */}
          <div className="lg:col-span-3 space-y-3">
            {!results.length && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <Search size={40} className="text-slate-600" />
                <p className="text-sm text-slate-500">IoC를 입력하고 분석 버튼을 클릭하세요</p>
                <p className="text-xs text-slate-600">IP · 도메인 · 파일 해시 · 이메일을 혼합해서 입력 가능</p>
              </div>
            )}

            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 위협 지표를 분석 중...</p>
              </div>
            )}

            {results.length > 0 && (
              <>
                <ModeBanner
                  mode={results[0]?.mode}
                  fallbackReason={results[0]?.fallback_reason}
                  engineNote={results[0]?.engine_note}
                />
                <div className="flex justify-between items-center">
                  <p className="text-sm font-semibold text-slate-300">분석 결과 ({results.length}개)</p>
                  <button
                    onClick={copyResult}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs font-medium transition-colors"
                  >
                    <Copy size={12} /> {copied ? '복사됨!' : '결과 복사'}
                  </button>
                </div>

                {/* IoC list */}
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {results.map((item, i) => (
                    <IoCRow key={i} item={item} selected={selected === i} onClick={() => setSelected(i)} />
                  ))}
                </div>

                {/* Detail */}
                {selected !== null && results[selected] && (
                  <IoCDetail item={results[selected]} />
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
