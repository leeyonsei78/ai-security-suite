import { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import {
  Siren, ChevronDown, ChevronUp, CheckSquare, Square,
  Send, Bot, User, Clock, Users, AlertTriangle, Cloud, Server, WifiOff, FlaskConical,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import FileUploadButton from '../components/FileUploadButton'

const MODE_BADGE = {
  cloud:   { icon: Cloud,        label: 'Claude Cloud로 분석됨', color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  local:   { icon: Server,       label: '로컬 LLM으로 분석됨',    color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/30' },
  offline: { icon: WifiOff,      label: '오프라인 규칙 기반으로 분석됨(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  mock:    { icon: FlaskConical, label: 'Mock 데모 데이터 (학습용, 실제 분석 아님)', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
}

function ModeBanner({ result }) {
  if (!result?.mode) return null
  const cfg = MODE_BADGE[result.mode] ?? MODE_BADGE.offline
  const Icon = cfg.icon
  return (
    <div className={`border rounded-xl p-3 flex items-start gap-2 ${cfg.bg}`}>
      <Icon size={14} className={`${cfg.color} shrink-0 mt-0.5`} />
      <div>
        <p className={`text-xs font-semibold ${cfg.color}`}>{cfg.label}</p>
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

const INCIDENT_TYPES = [
  { id: 'ransomware',      label: '랜섬웨어',       emoji: '🔒', desc: '파일 암호화·몸값 요구' },
  { id: 'data_breach',     label: '데이터 유출',    emoji: '📤', desc: '개인정보·기밀 데이터 외부 노출' },
  { id: 'ddos',            label: 'DDoS 공격',      emoji: '🌊', desc: '서비스 가용성 장애' },
  { id: 'phishing',        label: '피싱 공격',      emoji: '🎣', desc: '이메일·메시지 기반 사기' },
  { id: 'malware',         label: '악성코드',       emoji: '🦠', desc: '바이러스·트로이목마·스파이웨어' },
  { id: 'insider_threat',  label: '내부자 위협',    emoji: '🕵️', desc: '직원·계약자의 악의적 행위' },
]

const SEVERITIES = [
  { id: 'CRITICAL', label: 'Critical', color: 'border-red-500 text-red-400 bg-red-500/10' },
  { id: 'HIGH',     label: 'High',     color: 'border-orange-500 text-orange-400 bg-orange-500/10' },
  { id: 'MEDIUM',   label: 'Medium',   color: 'border-yellow-500 text-yellow-400 bg-yellow-500/10' },
  { id: 'LOW',      label: 'Low',      color: 'border-blue-500 text-blue-400 bg-blue-500/10' },
]

const PHASE_COLORS = {
  red:    { border: 'border-red-500/30',    bg: 'bg-red-500/5',    dot: 'bg-red-500',    text: 'text-red-400' },
  orange: { border: 'border-orange-500/30', bg: 'bg-orange-500/5', dot: 'bg-orange-500', text: 'text-orange-400' },
  yellow: { border: 'border-yellow-500/30', bg: 'bg-yellow-500/5', dot: 'bg-yellow-500', text: 'text-yellow-400' },
  purple: { border: 'border-purple-500/30', bg: 'bg-purple-500/5', dot: 'bg-purple-500', text: 'text-purple-400' },
  blue:   { border: 'border-blue-500/30',   bg: 'bg-blue-500/5',   dot: 'bg-blue-500',   text: 'text-blue-400' },
  green:  { border: 'border-green-500/30',  bg: 'bg-green-500/5',  dot: 'bg-green-500',  text: 'text-green-400' },
}

const IR_STEPS = [
  '왼쪽 패널에서 인시던트 유형을 선택합니다 (랜섬웨어·데이터 유출·DDoS 등).',
  '심각도(Critical~Low)와 상황 설명을 입력합니다.',
  '[대응 계획 생성] 버튼을 클릭하면 AI가 단계별 대응 계획을 생성합니다.',
  '오른쪽 패널에서 각 단계(즉시조치→조사→봉쇄→제거→복구→사후조치)를 확인합니다.',
  '단계별 체크리스트를 클릭해 완료 항목을 체크하며 진행 상황을 추적합니다.',
  '하단 채팅창에 추가 질문을 입력하면 AI가 상황별 조언을 제공합니다.',
]
const IR_TIPS = [
  '심각도 Critical: 즉각적인 서비스 중단·데이터 유출 등 최고 위험 상황',
  '체크리스트는 브라우저 내에서만 유지됩니다. 완료 현황은 스크린샷으로 보관하세요.',
  'Live 모드(API 키 있음)에서는 실제 상황 설명을 입력하면 더 정확한 대응 계획이 생성됩니다.',
]

function PhaseCard({ phase, checks, onCheck }) {
  const [open, setOpen] = useState(true)
  const pc = PHASE_COLORS[phase.color] ?? PHASE_COLORS.blue
  const done = phase.steps.filter((_, i) => checks[i]).length

  return (
    <div className={`border rounded-xl overflow-hidden ${pc.border} ${pc.bg}`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 p-4 hover:bg-white/5 transition-colors"
      >
        <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${pc.dot}`} />
        <span className="font-semibold text-sm flex-1 text-left">{phase.name}</span>
        <span className="text-xs text-slate-500 shrink-0">{phase.timeframe}</span>
        <span className={`text-xs font-bold ${pc.text} shrink-0`}>{done}/{phase.steps.length}</span>
        {open ? <ChevronUp size={14} className="text-slate-400 shrink-0" /> : <ChevronDown size={14} className="text-slate-400 shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 border-t border-white/10 pt-3">
          {phase.steps.map((step, i) => (
            <button
              key={i}
              onClick={() => onCheck(i)}
              className="w-full flex items-start gap-2.5 text-left hover:bg-white/5 rounded-lg p-1.5 transition-colors group"
            >
              {checks[i]
                ? <CheckSquare size={15} className={`shrink-0 mt-0.5 ${pc.text}`} />
                : <Square size={15} className="shrink-0 mt-0.5 text-slate-500 group-hover:text-slate-300" />}
              <span className={`text-xs leading-relaxed ${checks[i] ? 'line-through text-slate-500' : 'text-slate-300'}`}>
                {step}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function ChatBubble({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex gap-2.5 ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className={`w-7 h-7 rounded-full shrink-0 flex items-center justify-center ${isUser ? 'bg-blue-600' : 'bg-slate-600'}`}>
        {isUser ? <User size={13} /> : <Bot size={13} />}
      </div>
      <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
        isUser ? 'bg-blue-600 text-white rounded-tr-sm' : 'bg-slate-700 text-slate-200 rounded-tl-sm'
      }`}>
        {msg.content}
      </div>
    </div>
  )
}

export default function IncidentResponse() {
  const [incidentType, setIncidentType] = useState('ransomware')
  const [severity, setSeverity]         = useState('HIGH')
  const [description, setDescription]   = useState('')
  const [loading, setLoading]           = useState(false)
  const [plan, setPlan]                 = useState(null)
  const [sessionId, setSessionId]       = useState(null)
  const [checks, setChecks]             = useState({})
  const [chatMsgs, setChatMsgs]         = useState([])
  const [chatInput, setChatInput]       = useState('')
  const [chatLoading, setChatLoading]   = useState(false)
  const chatEndRef = useRef(null)

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [chatMsgs])

  const generate = async (descriptionOverride) => {
    const body = descriptionOverride ?? description
    if (!body.trim()) return
    setLoading(true)
    setPlan(null)
    setChecks({})
    setChatMsgs([])
    setSessionId(null)
    try {
      const res = await axios.post('/api/incident/create', {
        incident_type: incidentType, severity, description: body,
      })
      setPlan(res.data)
      setSessionId(res.data.session_id)
      const initChecks = {}
      res.data.phases?.forEach((ph, pi) => {
        ph.steps.forEach((_, si) => { initChecks[`${pi}-${si}`] = false })
      })
      setChecks(initChecks)
    } catch (err) {
      alert('생성 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const sendChat = async () => {
    if (!chatInput.trim() || !sessionId) return
    const msg = chatInput.trim()
    setChatInput('')
    setChatMsgs(m => [...m, { role: 'user', content: msg }])
    setChatLoading(true)
    try {
      const res = await axios.post('/api/incident/chat', { session_id: sessionId, message: msg })
      setChatMsgs(m => [...m, { role: 'assistant', content: res.data.reply }])
    } catch {
      setChatMsgs(m => [...m, { role: 'assistant', content: '응답 실패. 다시 시도해 주세요.' }])
    } finally {
      setChatLoading(false)
    }
  }

  const totalSteps = plan ? plan.phases.reduce((a, p) => a + p.steps.length, 0) : 0
  const doneSteps  = Object.values(checks).filter(Boolean).length
  const progress   = totalSteps ? Math.round((doneSteps / totalSteps) * 100) : 0

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Siren className="text-red-400" size={26} /> 인시던트 리스폰스 어시스턴트
          </h1>
          <p className="text-slate-400 text-sm mt-1">보안 사고 유형을 선택하면 AI가 단계별 대응 계획과 체크리스트를 생성합니다.</p>
        </div>

        <GuidePanel title="인시던트 리스폰스 어시스턴트 사용 가이드" steps={IR_STEPS} tips={IR_TIPS} />

        <div className="grid lg:grid-cols-5 gap-6">
          {/* Left: Form */}
          <div className="lg:col-span-2 space-y-5">

            {/* Incident type */}
            <div>
              <p className="text-sm font-semibold text-slate-300 mb-2">인시던트 유형</p>
              <div className="grid grid-cols-2 gap-2">
                {INCIDENT_TYPES.map(t => (
                  <button
                    key={t.id}
                    onClick={() => setIncidentType(t.id)}
                    className={`flex flex-col items-start p-3 rounded-xl border text-left transition-all ${
                      incidentType === t.id
                        ? 'border-red-500 bg-red-500/10 text-white'
                        : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className="text-xl mb-1">{t.emoji}</span>
                    <span className="text-xs font-semibold">{t.label}</span>
                    <span className="text-[10px] text-slate-500 leading-tight mt-0.5">{t.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Severity */}
            <div>
              <p className="text-sm font-semibold text-slate-300 mb-2">심각도</p>
              <div className="flex gap-2">
                {SEVERITIES.map(s => (
                  <button
                    key={s.id}
                    onClick={() => setSeverity(s.id)}
                    className={`flex-1 py-2 rounded-lg border text-xs font-bold transition-all ${
                      severity === s.id ? s.color : 'border-slate-700 text-slate-500 hover:border-slate-500'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Description */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-semibold text-slate-300">상황 설명</p>
                <FileUploadButton onExtracted={(text) => { setDescription(text); generate(text) }} />
              </div>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder={`예시:\n오전 9시경 영업팀 PC에서 파일이 암호화되기 시작했습니다. 바탕화면에 랜섬노트(.txt)가 생성됐으며, 같은 서브넷의 파일 서버도 피해를 입었습니다. 현재 약 30대 PC가 감염된 것으로 추정됩니다.`}
                rows={7}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm resize-none focus:outline-none focus:border-red-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={() => generate()}
              disabled={loading || !description.trim()}
              className="w-full py-3 bg-red-700 hover:bg-red-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Siren size={16} />
              {loading ? '대응 계획 생성 중...' : '대응 계획 생성'}
            </button>
          </div>

          {/* Right: Plan + Chat */}
          <div className="lg:col-span-3 space-y-4">
            {!plan && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <Siren size={40} className="text-slate-600" />
                <p className="text-sm text-slate-500">인시던트 유형과 상황을 입력하고 대응 계획을 생성하세요</p>
              </div>
            )}

            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <div className="w-10 h-10 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 대응 계획을 수립 중...</p>
              </div>
            )}

            {plan && (
              <>
                <ModeBanner result={plan} />
                {/* Summary card */}
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-3">
                  <div className="flex items-start gap-3">
                    <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
                    <p className="text-sm text-slate-200 leading-relaxed">{plan.summary}</p>
                  </div>
                  <div className="flex gap-4 text-xs text-slate-400 flex-wrap">
                    <span className="flex items-center gap-1"><Clock size={12} /> {plan.estimated_time}</span>
                    <span className="flex items-center gap-1"><Users size={12} /> {plan.key_contacts?.join(' · ')}</span>
                  </div>

                  {/* Progress */}
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">진행률</span>
                      <span className={`font-bold ${progress === 100 ? 'text-green-400' : 'text-slate-300'}`}>
                        {doneSteps} / {totalSteps} ({progress}%)
                      </span>
                    </div>
                    <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-green-500 rounded-full transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Phases */}
                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                  {plan.phases?.map((phase, pi) => (
                    <PhaseCard
                      key={phase.id}
                      phase={phase}
                      checks={Object.fromEntries(
                        phase.steps.map((_, si) => [si, checks[`${pi}-${si}`] ?? false])
                      )}
                      onCheck={(si) => setChecks(c => ({ ...c, [`${pi}-${si}`]: !c[`${pi}-${si}`] }))}
                    />
                  ))}
                </div>

                {/* Chat */}
                <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
                    <Bot size={15} className="text-blue-400" />
                    <span className="text-sm font-semibold">AI 어시스턴트</span>
                    <span className="text-xs text-slate-500 ml-auto">추가 질문을 입력하세요</span>
                  </div>

                  <div className="h-52 overflow-y-auto p-4 space-y-3">
                    {chatMsgs.length === 0 && (
                      <p className="text-xs text-slate-500 text-center pt-6">
                        "몸값을 지불해야 할까요?", "백업이 없으면 어떻게 하나요?" 등 질문하세요.
                      </p>
                    )}
                    {chatMsgs.map((m, i) => <ChatBubble key={i} msg={m} />)}
                    {chatLoading && (
                      <div className="flex gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-slate-600 flex items-center justify-center shrink-0">
                          <Bot size={13} />
                        </div>
                        <div className="bg-slate-700 rounded-2xl rounded-tl-sm px-4 py-2.5">
                          <div className="flex gap-1">
                            {[0,1,2].map(i => (
                              <div key={i} className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"
                                style={{ animationDelay: `${i * 0.15}s` }} />
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={chatEndRef} />
                  </div>

                  <div className="p-3 border-t border-slate-700 flex gap-2">
                    <input
                      value={chatInput}
                      onChange={e => setChatInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendChat()}
                      placeholder="질문 입력 후 Enter..."
                      className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                    />
                    <button
                      onClick={sendChat}
                      disabled={!chatInput.trim() || chatLoading}
                      className="p-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 rounded-lg transition-colors"
                    >
                      <Send size={15} />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
