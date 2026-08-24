import { NavLink } from 'react-router-dom'
import { Shield, Mail, ShieldAlert, Search, Siren, Globe, FlaskConical, Syringe, Cpu } from 'lucide-react'

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
]

export default function NavBar({ isMock }) {
  return (
    <nav className="bg-slate-900 border-b border-slate-700 px-6 py-0 flex items-center gap-1">
      <div className="flex items-center gap-2 pr-6 py-3 border-r border-slate-700 mr-2">
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
          <span key={to} className="flex items-center gap-1.5 px-4 py-3 text-sm text-slate-600 cursor-not-allowed">
            <Icon size={15} />{label}
            <span className="text-xs bg-slate-700 px-1 rounded">준비중</span>
          </span>
        ) : (
          <NavLink
            key={to}
            to={to}
            end
            className={({ isActive }) =>
              `flex items-center gap-1.5 px-4 py-3 text-sm transition-colors border-b-2 ${
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
    </nav>
  )
}
