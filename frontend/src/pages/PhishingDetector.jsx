import { useState } from 'react'
import axios from 'axios'
import { Mail, Link, FileText, AlertTriangle, CheckCircle, ShieldAlert, XCircle, Trash2, Cloud, Server, WifiOff, FlaskConical } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import FileUploadButton from '../components/FileUploadButton'

const PHISHING_STEPS = [
  '상단 탭에서 분석할 콘텐츠 유형을 선택합니다: 이메일 본문 / URL / 텍스트',
  '왼쪽 텍스트 박스에 분석할 내용을 붙여넣습니다. (placeholder 예시 참고)',
  '[AI로 피싱 분석] 버튼을 클릭합니다.',
  '오른쪽 결과 패널에서 판정(MALICIOUS·PHISHING·SUSPICIOUS·SAFE)과 위험 점수(0~100)를 확인합니다.',
  '"위험 신호" 목록으로 어떤 패턴이 감지됐는지, "권장 조치"로 대응 방법을 확인합니다.',
  '하단 "최근 분석" 목록에서 이전 결과를 클릭해 다시 볼 수 있습니다.',
]
const PHISHING_TIPS = [
  'MALICIOUS(80~100): 악성코드 배포 또는 확인된 피싱 — 즉시 차단',
  'PHISHING(60~79): 강한 피싱 신호, 자격증명 탈취 시도 가능성 높음',
  'SUSPICIOUS(30~59): 일부 의심 패턴, 주의해서 처리',
  'SAFE(0~29): 유의미한 위협 없음',
  'URL 탭에는 여러 URL을 줄바꿈으로 구분해 한 번에 입력할 수 있습니다.',
]

const VERDICT_CONFIG = {
  MALICIOUS: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', icon: XCircle, label: '악성' },
  PHISHING:  { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', icon: ShieldAlert, label: '피싱' },
  SUSPICIOUS:{ color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', icon: AlertTriangle, label: '의심' },
  SAFE:      { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30', icon: CheckCircle, label: '안전' },
}

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

const SCORE_COLOR = (s) => s >= 80 ? 'text-red-400' : s >= 60 ? 'text-orange-400' : s >= 30 ? 'text-yellow-400' : 'text-green-400'
const SCORE_BG   = (s) => s >= 80 ? 'bg-red-500' : s >= 60 ? 'bg-orange-500' : s >= 30 ? 'bg-yellow-500' : 'bg-green-500'

const INPUT_TYPES = [
  { id: 'email', icon: Mail, label: '이메일 본문' },
  { id: 'url', icon: Link, label: 'URL' },
  { id: 'text', icon: FileText, label: '텍스트' },
]

const PLACEHOLDERS = {
  email: `From: support@paypa1.com\nSubject: [긴급] 계정 정지 안내\n\n귀하의 계정이 비정상 접근으로 인해 24시간 내 정지됩니다.\n지금 바로 확인하세요: http://secure-paypa1.verify-now.com/login`,
  url: `https://secure-paypa1.verify-now.com/login\nhttps://google.com\nhttp://bit.ly/3xAbc12`,
  text: `귀하의 은행 계좌가 해킹되었습니다. 지금 즉시 아래 링크를 클릭해 비밀번호를 변경하세요.`,
}

export default function PhishingDetector() {
  const [inputType, setInputType] = useState('email')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])

  const analyze = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/phishing/analyze', { content: body, input_type: inputType })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const cfg = result ? VERDICT_CONFIG[result.verdict] : null

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-5xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Mail className="text-orange-400" size={26} /> 피싱/악성 콘텐츠 탐지기
          </h1>
          <p className="text-slate-400 text-sm mt-1">이메일 본문, URL, 텍스트를 분석해 피싱·악성 여부를 판단합니다.</p>
        </div>

        <GuidePanel title="피싱/악성 콘텐츠 탐지기 사용 가이드" steps={PHISHING_STEPS} tips={PHISHING_TIPS} />

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-3 space-y-4">
            {/* Type selector */}
            <div className="flex gap-2 items-center">
              {INPUT_TYPES.map(({ id, icon: Icon, label }) => (
                <button
                  key={id}
                  onClick={() => { setInputType(id); setContent('') }}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    inputType === id ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Icon size={14} />{label}
                </button>
              ))}
              <FileUploadButton className="ml-auto" onExtracted={(text) => { setContent(text); analyze(text) }} />
            </div>

            {/* Textarea */}
            <textarea
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={PLACEHOLDERS[inputType]}
              rows={12}
              className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-blue-500 placeholder-slate-600"
            />

            <button
              onClick={() => analyze()}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '분석 중...' : 'AI로 피싱 분석'}
            </button>
          </div>

          {/* Result Panel */}
          <div className="md:col-span-2 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <ShieldAlert size={32} className="text-slate-600" />
                <p className="text-sm">분석 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 분석 중...</p>
              </div>
            )}
            {result && cfg && (
              <>
              <ModeBanner result={result} />
              <div className={`border rounded-xl p-5 space-y-4 ${cfg.bg}`}>
                {/* Verdict */}
                <div className="flex items-center gap-3">
                  <cfg.icon size={28} className={cfg.color} />
                  <div>
                    <div className={`text-xl font-bold ${cfg.color}`}>{cfg.label}</div>
                    <div className="text-xs text-slate-400">{result.verdict}</div>
                  </div>
                  <div className="ml-auto text-right">
                    <div className={`text-3xl font-bold ${SCORE_COLOR(result.score)}`}>{result.score}</div>
                    <div className="text-xs text-slate-500">/ 100</div>
                  </div>
                </div>

                {/* Score bar */}
                <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full transition-all ${SCORE_BG(result.score)}`} style={{ width: `${result.score}%` }} />
                </div>

                {/* Summary */}
                <p className="text-sm text-slate-300">{result.summary}</p>

                {/* Indicators */}
                {result.indicators?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-red-400 mb-1">위험 신호</p>
                    <ul className="space-y-1">
                      {result.indicators.map((ind, i) => (
                        <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                          <span className="text-red-400 mt-0.5 shrink-0">•</span>{ind}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.safe_indicators?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-green-400 mb-1">안전 신호</p>
                    <ul className="space-y-1">
                      {result.safe_indicators.map((ind, i) => (
                        <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                          <span className="text-green-400 mt-0.5 shrink-0">•</span>{ind}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Recommendation */}
                <div className="bg-slate-800/60 rounded-lg p-3">
                  <p className="text-xs font-semibold text-blue-400 mb-1">권장 조치</p>
                  <p className="text-xs text-slate-300">{result.recommendation}</p>
                </div>
              </div>
              </>
            )}

            {/* History */}
            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 분석 ({history.length}건)</p>
                  <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                    <Trash2 size={13} />
                  </button>
                </div>
                <div className="space-y-2">
                  {history.map((h, i) => {
                    const hcfg = VERDICT_CONFIG[h.verdict]
                    return (
                      <button
                        key={i}
                        onClick={() => setResult(h)}
                        className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors"
                      >
                        <hcfg.icon size={14} className={hcfg.color} />
                        <span className="text-xs text-slate-300 truncate flex-1">{h.preview}</span>
                        <span className={`text-xs font-bold ${SCORE_COLOR(h.score)}`}>{h.score}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
