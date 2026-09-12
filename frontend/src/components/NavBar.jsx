import { useState, useEffect, useRef } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import axios from 'axios'
import {
  Shield, Mail, ShieldAlert, Search, Siren, Globe, FlaskConical, Syringe, Cpu, Swords,
  ScrollText, BrainCircuit, ShieldCheck, Bell, Trash2, Send, Database, ShieldQuestion, Radar,
  KeyRound, ScanSearch, Container, MailCheck, Gauge, ChevronDown, Zap, Landmark,
  LayoutGrid, Server, Network, Cloud, Fingerprint, Router,
} from 'lucide-react'
import ModeSelector from './ModeSelector'

// 그룹 구조: "대상"(서버/네트워크/보안장비/클라우드) 축과 "기능"(취약점분석/모의해킹/
// 사고대응·포렌식) 축이 섞여 있어 한 축으로만 나누면 억지 분류가 생김(예: 방화벽
// 감사기는 네트워크+보안장비+클라우드를 동시에 다룸, IoC 분석기·CVE 조회는 대상이
// 아예 없는 범용 도구). 그래서 대상이 뚜렷한 앱은 대상 축 그룹으로, 대상이 없거나
// 여러 대상을 넘나드는 범용/분석형 도구는 별도 그룹(공통/취약점분석)으로 분리함.
// 폐쇄망·인터넷망 구분은 메뉴 축으로 두지 않음 — 이미 ModeSelector가 앱별 cloud/
// local/offline/mock을 런타임에 감지해 배지로 보여주므로, 메뉴를 또 쪼개면 같은
// 앱이 중복 노출되거나 두 표시가 어긋날 수 있음 (2026-09-06).
const groups = [
  {
    key: 'common',
    label: '공통',
    icon: LayoutGrid,
    links: [
      { to: '/', icon: Shield, label: '보안 대시보드' },
      { to: '/risk-dashboard', icon: Gauge, label: '통합 리스크 대시보드' },
      { to: '/devices', icon: Router, label: '장비 관리 & 자동 점검' },
      { to: '/cve-lookup', icon: Database, label: 'CVE 조회', requiresInternet: true },
      { to: '/ioc', icon: Search, label: 'IoC 분석기' },
      { to: '/phishing', icon: Mail, label: '피싱 탐지기' },
      { to: '/policy', icon: ScrollText, label: '보안 정책 생성기' },
    ],
  },
  {
    key: 'server',
    label: '서버',
    icon: Server,
    links: [
      { to: '/webscan', icon: Globe, label: '웹 취약점 스캐너' },
      { to: '/container-audit', icon: Container, label: '컨테이너/Dockerfile 감사기' },
      { to: '/secret-scan', icon: ScanSearch, label: '시크릿 스캐너' },
      { to: '/infra-scan', icon: Radar, label: '인프라 취약점 스캐너', requiresInternet: true },
    ],
  },
  {
    key: 'network',
    label: '네트워크·보안장비',
    icon: Network,
    links: [
      { to: '/firewall-audit', icon: ShieldQuestion, label: '방화벽 정책 감사기' },
      { to: '/dns-security', icon: MailCheck, label: 'DNS/이메일 보안 점검', requiresInternet: true },
    ],
  },
  {
    key: 'cloud',
    label: '클라우드',
    icon: Cloud,
    links: [
      { to: '/iam-audit', icon: KeyRound, label: 'IAM 정책 감사기' },
    ],
  },
  {
    key: 'vuln-analysis',
    label: '취약점분석',
    icon: ShieldAlert,
    links: [
      { to: '/vuln', icon: ShieldAlert, label: '취약점 스캐너' },
      { to: '/model-audit', icon: BrainCircuit, label: 'AI 모델 감사' },
      { to: '/injection', icon: Syringe, label: '인젝션 탐지기' },
    ],
  },
  {
    key: 'pentest',
    label: '모의해킹',
    icon: Swords,
    links: [
      { to: '/pwn-lab', icon: Cpu, label: 'Pwn/Reverse 실습실' },
      { to: '/web-arena', icon: Swords, label: 'Web CTF 아레나' },
      { to: '/pentest-lab', icon: ShieldCheck, label: '모의 해킹 랩' },
      { to: '/phishing-sim', icon: Send, label: '피싱 모의훈련 생성기' },
    ],
  },
  {
    key: 'ir-forensics',
    label: '사고대응·포렌식',
    icon: Siren,
    links: [
      { to: '/incident', icon: Siren, label: '인시던트 대응' },
      { to: '/attack-monitor', icon: Zap, label: '실시간 공격 모니터링 & 대응' },
      { to: '/threat', icon: FlaskConical, label: '위협 분석 랩' },
      { to: '/forensics', icon: Fingerprint, label: '포렌식 실습·분석 센터' },
    ],
  },
  {
    key: 'compliance',
    label: '컴플라이언스',
    icon: Landmark,
    links: [
      { to: '/fsi-csp-audit', icon: Landmark, label: '금융보안원 클라우드 CSP 평가' },
      { to: '/kese-kit', icon: ShieldCheck, label: 'KISA 보안 가이드라인 종합 점검' },
    ],
  },
]

function findGroupKeyByPath(pathname) {
  const g = groups.find(g => g.links.some(l => l.to === pathname))
  return g ? g.key : groups[0].key
}

function AlertBell() {
  const [alerts, setAlerts] = useState([])
  const [isMock, setIsMock] = useState(true)
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  const fetchAlerts = () => {
    axios.get('/api/alerts').then(r => {
      setAlerts(r.data.alerts)
      setIsMock(r.data.is_mock)
    }).catch(() => {})
  }

  useEffect(() => {
    fetchAlerts()
    const interval = setInterval(fetchAlerts, 20000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const onClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  const clearAlerts = async () => {
    await axios.delete('/api/alerts')
    setAlerts([])
  }

  return (
    <div className="relative ml-auto" ref={ref}>
      <button
        onClick={() => { setOpen(o => !o); if (!open) fetchAlerts() }}
        className="relative flex items-center justify-center w-9 h-9 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200"
      >
        <Bell size={17} />
        {alerts.length > 0 && (
          <span className="absolute top-1 right-1 min-w-[15px] h-[15px] px-0.5 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
            {alerts.length > 9 ? '9+' : alerts.length}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-96 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700">
            <span className="text-sm font-semibold">알림 ({alerts.length})</span>
            <button onClick={clearAlerts} className="text-slate-500 hover:text-red-400">
              <Trash2 size={13} />
            </button>
          </div>
          <div className="max-h-80 overflow-y-auto">
            {alerts.length === 0 && (
              <p className="text-sm text-slate-500 text-center py-8">Critical 탐지 시 여기에 알림이 쌓입니다.</p>
            )}
            {alerts.map(a => (
              <div key={a.id} className="px-4 py-2.5 border-b border-slate-700/50 last:border-0">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className="text-[10px] font-bold bg-red-500/20 text-red-400 rounded px-1.5 py-0.5">{a.severity}</span>
                  <span className="text-xs text-slate-400">{a.app_label}</span>
                </div>
                <p className="text-xs text-slate-300 line-clamp-2">{a.summary}</p>
              </div>
            ))}
          </div>
          <div className="px-4 py-2 bg-slate-900/60 text-[11px] text-slate-500">
            {isMock
              ? 'Mock 모드 — Slack/이메일 미설정, 실제 전송 없이 로그만 기록됨'
              : 'Live 모드 — 설정된 채널로 실제 전송됨'}
          </div>
        </div>
      )}
    </div>
  )
}

export default function NavBar() {
  const location = useLocation()
  const [openGroup, setOpenGroup] = useState(() => findGroupKeyByPath(location.pathname))

  useEffect(() => {
    setOpenGroup(findGroupKeyByPath(location.pathname))
  }, [location.pathname])

  const activeGroupKey = findGroupKeyByPath(location.pathname)
  const currentGroup = groups.find(g => g.key === openGroup)

  const toggleGroup = (key) => {
    setOpenGroup(prev => (prev === key ? null : key))
  }

  return (
    <nav className="bg-slate-900 border-b border-slate-700">
      <div className="px-6 flex items-center gap-1">
        <div className="flex items-center gap-2 pr-6 py-3 border-r border-slate-700 mr-2 shrink-0 whitespace-nowrap">
          <Shield className="text-blue-400" size={20} />
          <span className="font-bold text-sm">AI Security Suite</span>
          <ModeSelector />
        </div>
        {/* overflow-x-auto는 이 그룹 탭 구간에만 건다 — 브랜드/모드 셀렉터/알림 종처럼 아래로
            펼쳐지는 드롭다운을 가진 요소를 같은 스크롤 컨테이너 안에 두면, overflow-x가 auto인
            축과 짝을 맞추려 overflow-y도 auto로 강제되어 절대 위치 드롭다운이 세로로 잘려
            보이지 않게 된다(스크린샷에는 안 보이지만 DOM에는 존재하는 상태가 됨). */}
        <div className="flex items-center gap-1 overflow-x-auto flex-1 min-w-0">
          {groups.map(({ key, label, icon: Icon }) => {
            const isOpen = openGroup === key
            const isActiveGroup = activeGroupKey === key
            return (
              <button
                key={key}
                onClick={() => toggleGroup(key)}
                className={`flex items-center gap-1.5 px-4 py-3 text-sm transition-colors border-b-2 shrink-0 whitespace-nowrap ${
                  isOpen || isActiveGroup
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon size={15} />{label}
                <ChevronDown size={13} className={`transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              </button>
            )
          })}
        </div>
        <AlertBell />
      </div>

      {currentGroup && (
        <div className="px-6 flex items-center gap-1 overflow-x-auto border-t border-slate-800 bg-slate-950/40">
          {currentGroup.links.map(({ to, icon: Icon, label, requiresInternet }) => (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                `flex items-center gap-1.5 px-4 py-2.5 text-sm transition-colors border-b-2 shrink-0 whitespace-nowrap ${
                  isActive
                    ? 'border-blue-400 text-blue-300'
                    : 'border-transparent text-slate-500 hover:text-slate-200'
                }`
              }
            >
              <Icon size={14} />{label}
              {requiresInternet && (
                <span title="외부 인터넷 연결 필요 (폐쇄망에서는 동작하지 않음)" className="text-xs opacity-70">
                  🌐
                </span>
              )}
            </NavLink>
          ))}
        </div>
      )}
    </nav>
  )
}
