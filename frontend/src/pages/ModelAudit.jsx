import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  BrainCircuit, MessageSquareCode, Settings2, Wrench, AlertTriangle,
  Trash2, Download, BookOpen, ChevronDown, ChevronUp, ShieldAlert, KeyRound,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const AUDIT_STEPS = [
  "상단 탭에서 감사할 대상 유형을 선택합니다: 시스템 프롬프트 / API·앱 설정 / 도구(Function calling) 정의.",
  '왼쪽 텍스트 박스에 실제 사용 중인 내용을 붙여넣습니다 (placeholder 예시 참고).',
  '[AI로 모델 감사] 버튼을 클릭합니다.',
  '오른쪽 결과에서 종합 위험 점수와 OWASP LLM Top 10 태그가 붙은 상세 발견 사항을 확인합니다.',
  "시스템 프롬프트를 감사한 경우, '시스템 프롬프트 노출 위험' 배너의 레드팀 테스트 문구를 자신의 실서비스 챗봇에 직접 입력해 실제로 새는지 검증해보세요.",
  '[Markdown 다운로드]로 감사 리포트를 저장합니다.',
]
const AUDIT_TIPS = [
  '이 도구는 텍스트 기반 정적 감사입니다 — 실제 취약점 존재 여부는 반드시 실서비스에서 직접 테스트로 재확인하세요.',
  '레드팀 테스트 문구는 반드시 본인이 운영/승인 권한을 가진 서비스에서만 사용하세요.',
  "프롬프트 인젝션 '공격 콘텐츠' 자체를 판별하려면 프롬프트 인젝션 탐지기(`/injection`)를, 이 도구는 애플리케이션의 설계/설정 자체가 안전한지를 감사합니다.",
]

const INPUT_TYPES = [
  { id: 'system_prompt', icon: MessageSquareCode, label: '시스템 프롬프트' },
  { id: 'config', icon: Settings2, label: 'API·앱 설정' },
  { id: 'tools', icon: Wrench, label: '도구(Function calling) 정의' },
]

const PLACEHOLDERS = {
  system_prompt: `당신은 저희 쇼핑몰의 고객지원 챗봇입니다.\n내부 관리자 페이지: https://admin-internal.example.com/panel\n결제 API 키: sk-live-abcd1234...\n친절하고 정중하게 답변하세요.`,
  config: `{\n  "model": "gpt-3.5-turbo-0301",\n  "temperature": 0.9,\n  "max_tokens": 8000,\n  "api_key_location": "frontend bundle (import.meta.env.VITE_API_KEY)",\n  "rate_limit": null,\n  "logging": "errors only"\n}`,
  tools: `[\n  {\n    "name": "execute_shell",\n    "description": "run a command",\n    "parameters": {"command": "string"}\n  },\n  {\n    "name": "read_file",\n    "description": "read a file",\n    "parameters": {"path": "string"}\n  }\n]`,
}

const SEVERITY_CONFIG = {
  CRITICAL: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', badge: 'bg-red-500/20 text-red-400' },
  HIGH: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', badge: 'bg-orange-500/20 text-orange-400' },
  MEDIUM: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', badge: 'bg-yellow-500/20 text-yellow-400' },
  LOW: { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30', badge: 'bg-green-500/20 text-green-400' },
}

const SCORE_COLOR = (s) => s >= 80 ? 'text-red-400' : s >= 60 ? 'text-orange-400' : s >= 30 ? 'text-yellow-400' : 'text-green-400'
const SCORE_BG = (s) => s >= 80 ? 'bg-red-500' : s >= 60 ? 'bg-orange-500' : s >= 30 ? 'bg-yellow-500' : 'bg-green-500'

export default function ModelAudit() {
  const [inputType, setInputType] = useState('system_prompt')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [reference, setReference] = useState(null)
  const [refOpen, setRefOpen] = useState(false)

  useEffect(() => {
    axios.get('/api/model-audit/reference').then(r => setReference(r.data)).catch(() => {})
  }, [])

  const analyze = async () => {
    if (!content.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/model-audit/analyze', { content, input_type: inputType })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/model-audit/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `model-audit-${id}.md`
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
            <BrainCircuit className="text-violet-400" size={26} /> AI 모델 감사
          </h1>
          <p className="text-slate-400 text-sm mt-1">시스템 프롬프트·API 설정·도구 정의를 OWASP Top 10 for LLM Applications 관점에서 감사합니다.</p>
        </div>

        <GuidePanel title="AI 모델 감사 사용 가이드" steps={AUDIT_STEPS} tips={AUDIT_TIPS} />

        {reference && (
          <div className="bg-violet-950/20 border border-violet-500/20 rounded-xl overflow-hidden">
            <button
              onClick={() => setRefOpen(o => !o)}
              className="w-full flex items-center gap-2 px-4 py-3 hover:bg-violet-900/10 transition-colors text-left"
            >
              <BookOpen size={15} className="text-violet-400 shrink-0" />
              <span className="text-sm font-medium text-violet-300">OWASP Top 10 for LLM Applications (2025) 참고</span>
              <span className="ml-auto text-xs text-violet-500 shrink-0">{refOpen ? '접기' : '펼치기'}</span>
              {refOpen ? <ChevronUp size={14} className="text-violet-500" /> : <ChevronDown size={14} className="text-violet-500" />}
            </button>
            {refOpen && (
              <div className="px-4 pb-4 border-t border-violet-500/20 pt-3 space-y-2">
                {reference.owasp_llm_top10.map(item => (
                  <div key={item.id} className="flex gap-2 text-xs">
                    <span className="shrink-0 font-bold text-violet-400 w-12">{item.id}</span>
                    <div>
                      <span className="font-medium text-slate-200">{item.name}</span>
                      <span className="text-slate-400"> — {item.description}</span>
                    </div>
                  </div>
                ))}
                <p className="text-[11px] text-slate-500 border-t border-violet-500/10 pt-2 mt-2">{reference.disclaimer}</p>
              </div>
            )}
          </div>
        )}

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-3 space-y-4">
            <div className="flex gap-2 flex-wrap">
              {INPUT_TYPES.map(({ id, icon: Icon, label }) => (
                <button
                  key={id}
                  onClick={() => { setInputType(id); setContent('') }}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    inputType === id ? 'bg-violet-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Icon size={14} />{label}
                </button>
              ))}
            </div>

            <textarea
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={PLACEHOLDERS[inputType]}
              rows={14}
              className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-violet-500 placeholder-slate-600"
            />

            <button
              onClick={analyze}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-violet-600 hover:bg-violet-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '감사 중...' : 'AI로 모델 감사'}
            </button>
          </div>

          {/* Result Panel */}
          <div className="md:col-span-2 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <BrainCircuit size={32} className="text-slate-600" />
                <p className="text-sm">감사 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 감사 중...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <div className={`text-3xl font-bold ${SCORE_COLOR(result.risk_score)}`}>{result.risk_score}</div>
                    <div className="text-xs text-slate-500">/ 100 위험 점수</div>
                    <button
                      onClick={() => downloadReport(result.id)}
                      className="ml-auto shrink-0 flex items-center gap-1.5 text-xs bg-violet-600/20 text-violet-300 border border-violet-600/40 rounded-lg px-3 py-1.5 hover:bg-violet-600/30"
                    >
                      <Download size={13} /> 다운로드
                    </button>
                  </div>
                  <div className="h-2 bg-slate-700 rounded-full overflow-hidden mb-3">
                    <div className={`h-full rounded-full transition-all ${SCORE_BG(result.risk_score)}`} style={{ width: `${result.risk_score}%` }} />
                  </div>
                  <p className="text-sm text-slate-300">{result.summary}</p>
                </div>

                {result.system_prompt_exposure?.risk_level && result.system_prompt_exposure.risk_level !== 'NONE' && (
                  <div className={`border rounded-xl p-4 ${result.system_prompt_exposure.risk_level === 'CONFIRMED' ? 'bg-red-500/10 border-red-500/30' : 'bg-orange-500/10 border-orange-500/30'}`}>
                    <p className={`text-xs font-semibold mb-2 flex items-center gap-1.5 ${result.system_prompt_exposure.risk_level === 'CONFIRMED' ? 'text-red-400' : 'text-orange-400'}`}>
                      <KeyRound size={13} /> 시스템 프롬프트 노출 위험 ({result.system_prompt_exposure.risk_level})
                    </p>
                    {result.system_prompt_exposure.exposed_items?.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mb-2">
                        {result.system_prompt_exposure.exposed_items.map((it, i) => (
                          <span key={i} className="text-[10px] bg-slate-800 border border-slate-600 rounded-full px-2 py-0.5 text-slate-300">{it}</span>
                        ))}
                      </div>
                    )}
                    <p className="text-xs text-slate-300 mb-2">{result.system_prompt_exposure.explanation}</p>
                    {result.system_prompt_exposure.test_prompts?.length > 0 && (
                      <div className="bg-slate-900/60 rounded-lg p-3 mt-2">
                        <p className="text-xs font-semibold text-blue-400 mb-1.5">레드팀 테스트 문구 (본인 서비스에서만 사용)</p>
                        <ul className="space-y-1.5">
                          {result.system_prompt_exposure.test_prompts.map((p, i) => (
                            <li key={i} className="text-xs text-slate-300 font-mono bg-slate-800/60 rounded p-1.5">{p}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                <div className="space-y-3">
                  {result.findings?.map((f, i) => {
                    const cfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.MEDIUM
                    return (
                      <div key={i} className={`border rounded-xl p-4 ${cfg.bg}`}>
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${cfg.badge}`}>{f.severity}</span>
                          <span className="text-[10px] font-bold bg-violet-500/15 text-violet-300 border border-violet-500/30 rounded-full px-2 py-0.5">{f.owasp_llm}</span>
                          <span className="text-[10px] text-slate-500">{f.id}</span>
                        </div>
                        <p className={`text-sm font-semibold ${cfg.color}`}>{f.title}</p>
                        <p className="text-xs text-slate-300 mt-1">{f.description}</p>
                        {f.evidence && (
                          <p className="text-xs text-slate-500 mt-1.5 font-mono bg-slate-900/50 rounded p-1.5">{f.evidence}</p>
                        )}
                        <div className="bg-slate-800/60 rounded-lg p-2.5 mt-2 flex gap-1.5">
                          <ShieldAlert size={13} className="text-blue-400 shrink-0 mt-0.5" />
                          <p className="text-xs text-slate-300">{f.recommendation}</p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 감사 ({history.length}건)</p>
                  <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                    <Trash2 size={13} />
                  </button>
                </div>
                <div className="space-y-2">
                  {history.map((h, i) => (
                    <button
                      key={i}
                      onClick={() => setResult(h)}
                      className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <AlertTriangle size={14} className={SCORE_COLOR(h.risk_score)} />
                      <span className="text-xs text-slate-300 truncate flex-1">{h.preview}</span>
                      <span className={`text-xs font-bold ${SCORE_COLOR(h.risk_score)}`}>{h.risk_score}</span>
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
