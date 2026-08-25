import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Send, ShieldAlert, Mail, Download, Trash2, Eye, EyeOff, AlertTriangle, Gauge,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const SIM_STEPS = [
  '시나리오 유형을 선택합니다 (IT 비밀번호 만료 / 택배 배송 / 급여명세서 / 경영진 사칭 / 클라우드 공유 / 보안팀 사칭).',
  '난이도를 선택합니다 — 초급일수록 위험 신호가 명확하고, 고급일수록 실제 업무 메일과 구분하기 어렵습니다.',
  '(선택) 조직 컨텍스트를 입력하면 AI가 그에 맞춰 이메일 내용을 조정합니다 (Live 모드에서만 반영).',
  '[모의훈련 이메일 생성]을 누르면 이메일 초안과 함께 그 안에 심어진 위험 신호(정답지)가 생성됩니다.',
  '훈련 진행 시에는 [정답지 숨기기]로 피훈련자에게 이메일만 먼저 보여준 뒤, 교육 시점에 정답지를 공개하세요.',
  '[Markdown 다운로드]로 이메일 초안 + 정답지 + 진행 유의사항이 담긴 문서를 저장할 수 있습니다.',
]
const SIM_TIPS = [
  '여기서 생성되는 발신 도메인은 전부 가상(.example)입니다 — 실제 발송에는 조직의 정식 모의훈련 플랫폼 도메인으로 교체해야 합니다.',
  '실제 임직원 대상 발송 전에는 반드시 보안팀·인사팀·법무팀 승인을 받으세요.',
  '클릭한 임직원을 처벌하기보다, 위 정답지를 활용해 즉시 피드백을 주는 것이 학습 효과가 더 큽니다.',
]

const SCENARIO_ICONS = {
  it_password_reset: '🔑',
  parcel_delivery: '📦',
  hr_payroll: '💰',
  ceo_fraud: '👔',
  cloud_share: '📁',
  security_alert: '🛡️',
}

const DIFFICULTY_COLOR = {
  beginner: 'bg-green-600',
  intermediate: 'bg-amber-600',
  advanced: 'bg-red-600',
}

export default function PhishingSimGenerator() {
  const [scenarios, setScenarios] = useState([])
  const [difficulties, setDifficulties] = useState([])
  const [scenarioType, setScenarioType] = useState('it_password_reset')
  const [difficulty, setDifficulty] = useState('beginner')
  const [context, setContext] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [showAnswers, setShowAnswers] = useState(true)
  const [history, setHistory] = useState([])

  useEffect(() => {
    axios.get('/api/phishing-sim/scenarios').then(r => {
      setScenarios(r.data.scenarios)
      setDifficulties(r.data.difficulties)
    }).catch(() => {})
  }, [])

  const generate = async () => {
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/phishing-sim/generate', { scenario_type: scenarioType, difficulty, context })
      setResult(res.data)
      setShowAnswers(true)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('생성 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/phishing-sim/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `phishing-sim-${id}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Send className="text-rose-400" size={26} /> 피싱 모의훈련 이메일 생성기
          </h1>
          <p className="text-slate-400 text-sm mt-1">사내 보안 인식 훈련용 피싱 시뮬레이션 이메일과 위험 신호 정답지를 AI로 생성합니다.</p>
        </div>

        <GuidePanel title="피싱 모의훈련 이메일 생성기 사용 가이드" steps={SIM_STEPS} tips={SIM_TIPS} />

        <div className="bg-amber-950/20 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle size={18} className="text-amber-400 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-200 leading-relaxed">
            이 도구는 <b>사내 승인된 보안 인식 훈련 목적</b>으로만 사용하세요. 실제 발송 전 반드시 보안팀·인사팀·법무팀의 승인을 받아야 하며,
            실제 임직원의 자격증명이나 금융정보를 수집하는 랜딩 페이지로 연결해서는 안 됩니다. 여기 생성된 발신 도메인은 전부 가상(.example)입니다 —
            실제 캠페인에는 조직이 보유한 정식 모의훈련 플랫폼 도메인으로 교체하세요. 승인받지 않은 대상에게 발송하는 것은 실제 피싱 공격과 동일하게 취급될 수 있습니다.
          </p>
        </div>

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">시나리오 유형</p>
              <div className="grid grid-cols-1 gap-2">
                {scenarios.map(({ id, label }) => (
                  <button
                    key={id}
                    onClick={() => setScenarioType(id)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium text-left transition-colors ${
                      scenarioType === id ? 'bg-rose-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    <span>{SCENARIO_ICONS[id] ?? '✉️'}</span>{label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2 flex items-center gap-1.5"><Gauge size={13} /> 난이도</p>
              <div className="flex gap-2">
                {difficulties.map(({ id, label }) => (
                  <button
                    key={id}
                    onClick={() => setDifficulty(id)}
                    className={`flex-1 px-2 py-2 rounded-lg text-[11px] font-medium transition-colors ${
                      difficulty === id ? `${DIFFICULTY_COLOR[id]} text-white` : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">조직 컨텍스트 (선택)</p>
              <textarea
                value={context}
                onChange={e => setContext(e.target.value)}
                placeholder="예: 핀테크 스타트업, 직원 200명, 최근 재택근무 확대 중"
                rows={4}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-3 text-sm resize-none focus:outline-none focus:border-rose-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={generate}
              disabled={loading}
              className="w-full py-3 bg-rose-600 hover:bg-rose-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '생성 중...' : '모의훈련 이메일 생성'}
            </button>
          </div>

          {/* Result Panel */}
          <div className="md:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <Mail size={32} className="text-slate-600" />
                <p className="text-sm">생성된 모의훈련 이메일이 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-rose-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 모의훈련 이메일을 생성 중...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                {/* Email preview */}
                <div className="bg-white text-slate-900 rounded-xl overflow-hidden shadow-lg">
                  <div className="bg-slate-100 px-4 py-3 border-b border-slate-300 space-y-1">
                    <p className="text-sm"><span className="text-slate-500">보낸사람:</span> <b>{result.sender_display_name}</b> <span className="text-slate-500">&lt;no-reply@{result.sender_domain}&gt;</span></p>
                    <p className="text-sm font-bold">{result.subject}</p>
                  </div>
                  <div className="px-4 py-4 space-y-3">
                    <p className="text-sm whitespace-pre-line leading-relaxed">{result.body}</p>
                    <div className="inline-block bg-blue-600 text-white text-xs font-semibold px-4 py-2 rounded">
                      {result.cta_text}
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <button
                    onClick={() => setShowAnswers(a => !a)}
                    className="flex items-center gap-1.5 text-xs bg-slate-700 hover:bg-slate-600 rounded-lg px-3 py-1.5"
                  >
                    {showAnswers ? <EyeOff size={13} /> : <Eye size={13} />}
                    {showAnswers ? '정답지 숨기기 (훈련용 화면)' : '정답지 보기'}
                  </button>
                  <button
                    onClick={() => downloadReport(result.id)}
                    className="flex items-center gap-1.5 text-xs bg-rose-600/20 text-rose-300 border border-rose-600/40 rounded-lg px-3 py-1.5 hover:bg-rose-600/30"
                  >
                    <Download size={13} /> Markdown 다운로드
                  </button>
                </div>

                {showAnswers && (
                  <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                    <p className="text-xs font-semibold text-rose-400 mb-3 flex items-center gap-1.5">
                      <ShieldAlert size={13} /> 포함된 위험 신호 (정답지)
                    </p>
                    <div className="space-y-2">
                      {result.red_flags?.map((f, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="shrink-0 w-5 h-5 rounded-full bg-rose-600/30 text-rose-300 flex items-center justify-center font-bold text-[10px]">{i + 1}</span>
                          <div>
                            <p className="text-xs font-semibold text-slate-200">{f.signal}</p>
                            <p className="text-xs text-slate-400">{f.explanation}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                    {result.difficulty_rationale && (
                      <p className="text-xs text-slate-500 italic mt-3 pt-3 border-t border-slate-700">난이도 설계 근거: {result.difficulty_rationale}</p>
                    )}
                  </div>
                )}

                {result.context_note && (
                  <p className="text-[11px] text-slate-500 italic">{result.context_note}</p>
                )}
              </div>
            )}

            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 생성 ({history.length}건)</p>
                  <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                    <Trash2 size={13} />
                  </button>
                </div>
                <div className="space-y-2">
                  {history.map((h, i) => (
                    <button
                      key={i}
                      onClick={() => { setResult(h); setShowAnswers(true) }}
                      className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <span>{SCENARIO_ICONS[h.scenario_type] ?? '✉️'}</span>
                      <span className="text-xs text-slate-300 truncate flex-1">{h.subject}</span>
                      <span className="text-[10px] text-slate-500 shrink-0">{h.difficulty}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
