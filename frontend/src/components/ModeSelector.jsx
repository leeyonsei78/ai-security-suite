import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import { Cloud, Server, WifiOff, FlaskConical, ChevronDown, Check } from 'lucide-react'

const MODE_CONFIG = {
  cloud:   { icon: Cloud,        label: 'Claude Cloud', color: 'text-green-400',  bg: 'bg-green-500/20' },
  local:   { icon: Server,       label: '로컬 LLM',      color: 'text-blue-400',   bg: 'bg-blue-500/20' },
  offline: { icon: WifiOff,      label: '오프라인(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/20' },
  mock:    { icon: FlaskConical, label: 'Mock 데모',      color: 'text-slate-400',  bg: 'bg-slate-500/20' },
}

const ORDER = ['cloud', 'local', 'offline', 'mock']

export default function ModeSelector() {
  const [status, setStatus] = useState(null)
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  const fetchStatus = () => {
    axios.get('/api/mode').then(r => setStatus(r.data)).catch(() => {})
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const onClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  const choose = async (mode) => {
    try {
      const res = await axios.post('/api/mode/override', { mode })
      setStatus(res.data)
    } catch (err) {
      alert('모드 변경 실패: ' + (err.response?.data?.detail ?? err.message))
    }
    setOpen(false)
  }

  if (!status) return null

  const cfg = MODE_CONFIG[status.effective_mode] ?? MODE_CONFIG.offline
  const Icon = cfg.icon

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold ${cfg.bg} ${cfg.color} hover:brightness-125 transition`}
        title="AI 실행 모드 (클릭해서 변경)"
      >
        <Icon size={13} />
        {cfg.label}
        <ChevronDown size={11} />
      </button>

      {open && (
        <div className="absolute left-0 top-full mt-1 w-72 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="px-3 py-2 border-b border-slate-700">
            <p className="text-xs font-semibold text-slate-300">AI 실행 모드</p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              자동(기본값)은 Claude Cloud → 로컬 LLM → 오프라인 순으로 사용 가능한 걸 고릅니다.
              Mock은 실제 분석이 아닌 학습용 샘플 데이터입니다.
            </p>
          </div>

          <button
            onClick={() => choose(null)}
            className="w-full text-left px-3 py-2 hover:bg-slate-700/60 flex items-center justify-between"
          >
            <span className="text-xs text-slate-200">자동 감지</span>
            {status.override === null && <Check size={13} className="text-blue-400" />}
          </button>

          <div className="border-t border-slate-700" />

          {ORDER.map(key => {
            const m = status.modes[key]
            const c = MODE_CONFIG[key]
            const MIcon = c.icon
            const selected = status.override === key
            const disabled = !m.selectable
            return (
              <button
                key={key}
                onClick={() => !disabled && choose(key)}
                disabled={disabled}
                className={`w-full text-left px-3 py-2 flex items-center justify-between gap-2 ${
                  disabled ? 'opacity-40 cursor-not-allowed' : 'hover:bg-slate-700/60'
                }`}
                title={disabled ? `사용하려면 설정이 필요합니다 (${key === 'local' ? '.env의 LOCAL_LLM_BASE_URL' : key === 'cloud' ? '.env의 ANTHROPIC_API_KEY' : ''})` : ''}
              >
                <span className="flex items-center gap-1.5">
                  <MIcon size={13} className={c.color} />
                  <span className="text-xs text-slate-200">{c.label}</span>
                  {m.configured && !m.reachable && key !== 'offline' && key !== 'mock' && (
                    <span className="text-[10px] text-red-400">(연결 안 됨)</span>
                  )}
                </span>
                {selected && <Check size={13} className="text-blue-400" />}
              </button>
            )
          })}

          {status.modes.local.base_url && (
            <div className="px-3 py-2 border-t border-slate-700 text-[10px] text-slate-500 font-mono break-all">
              로컬 LLM: {status.modes.local.base_url} ({status.modes.local.model || '모델 미지정'})
            </div>
          )}
        </div>
      )}
    </div>
  )
}
