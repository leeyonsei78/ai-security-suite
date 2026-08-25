import { useState, useEffect, useRef } from 'react'
import { NavLink } from 'react-router-dom'
import axios from 'axios'
import {
  Shield, Mail, ShieldAlert, Search, Siren, Globe, FlaskConical, Syringe, Cpu, Swords,
  ScrollText, BrainCircuit, ShieldCheck, Bell, Trash2,
} from 'lucide-react'

const links = [
  { to: '/', icon: Shield, label: '보안 대시보드' },
  { to: '/phishing', icon: Mail, label: '피싱 탐지기' },
  { to: '/vuln', icon: ShieldAlert, label: '취약점 스캐너' },
  { to: '/ioc', icon: Search, label: 'IoC 분석기' },
  { to: '/incident', icon: Siren, label: '인시던트 대응' },
  { to: '/webscan', icon: Globe, label: '웹 스캐너' },
  { to: '/threat', icon: FlaskConical, label: '위협 분석 랩' },
  { to: '/injection', icon: Syringe, label: '인젝션 탐지기' },
  { to: '/pwn-lab', icon: Cpu, label: 'Pwn/Reverse 실습실' },
  { to: '/web-arena', icon: Swords, label: 'Web CTF 아레나' },
  { to: '/policy', icon: ScrollText, label: '보안 정책 생성기' },
  { to: '/model-audit', icon: BrainCircuit, label: 'AI 모델 감사' },
  { to: '/pentest-lab', icon: ShieldCheck, label: '모의 해킹 랩' },
]

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

export default function NavBar({ isMock }) {
  return (
    <nav className="bg-slate-900 border-b border-slate-700 px-6 py-0 flex items-center gap-1 overflow-x-auto">
      <div className="flex items-center gap-2 pr-6 py-3 border-r border-slate-700 mr-2 shrink-0 whitespace-nowrap">
        <Shield className="text-blue-400" size={20} />
        <span className="font-bold text-sm">AI Security Suite</span>
        {isMock !== null && (
          <span className={`text-xs font-bold px-1.5 py-0.5 rounded ml-1 ${isMock ? 'bg-amber-500/20 text-amber-400' : 'bg-green-500/20 text-green-400'}`}>
            {isMock ? 'MOCK' : 'LIVE'}
          </span>
        )}
      </div>
      {links.map(({ to, icon: Icon, label, disabled }) =>
        disabled ? (
          <span key={to} className="flex items-center gap-1.5 px-4 py-3 text-sm text-slate-600 cursor-not-allowed shrink-0 whitespace-nowrap">
            <Icon size={15} />{label}
            <span className="text-xs bg-slate-700 px-1 rounded">준비중</span>
          </span>
        ) : (
          <NavLink
            key={to}
            to={to}
            end
            className={({ isActive }) =>
              `flex items-center gap-1.5 px-4 py-3 text-sm transition-colors border-b-2 shrink-0 whitespace-nowrap ${
                isActive
                  ? 'border-blue-400 text-blue-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`
            }
          >
            <Icon size={15} />{label}
          </NavLink>
        )
      )}
      <AlertBell />
    </nav>
  )
}
