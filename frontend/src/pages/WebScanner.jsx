import { useState } from 'react'
import axios from 'axios'
import {
  Globe, Shield, ShieldAlert, ShieldCheck, Lock, LockOpen,
  ChevronDown, ChevronUp, Trash2, ExternalLink,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const SEV = {
  CRITICAL: { color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30',    dot: 'bg-red-500',    label: '심각' },
  HIGH:     { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', dot: 'bg-orange-500', label: '높음' },
  MEDIUM:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', dot: 'bg-yellow-500', label: '중간' },
  LOW:      { color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30',  dot: 'bg-green-500',  label: '낮음' },
}

const SCORE_COLOR = s => s >= 70 ? 'text-red-400' : s >= 40 ? 'text-yellow-400' : 'text-green-400'
const SCORE_BG    = s => s >= 70 ? 'bg-red-500'   : s >= 40 ? 'bg-yellow-500'   : 'bg-green-500'

const GUIDE_STEPS = [
  '상단 입력창에 스캔할 웹사이트 URL을 입력합니다. (https:// 없이 도메인만 입력해도 됩니다)',
  '[웹 취약점 스캔] 버튼을 클릭합니다.',
  '오른쪽 패널에서 위험 점수와 취약점 목록을 확인합니다.',
  '각 취약점 카드를 클릭하면 설명과 권장 조치를 볼 수 있습니다.',
  'SSL 인증서 상태, 서버 정보 노출, 민감 경로 노출 여부를 별도로 확인합니다.',
]
const GUIDE_TIPS = [
  'Mock 모드에서는 실제 요청 없이 샘플 결과를 반환합니다.',
  'Live 모드에서는 실제 HTTP 요청으로 헤더·경로·SSL을 점검합니다.',
  '본인 소유 또는 허가받은 사이트만 스캔하세요 — 승인 체크박스를 확인해야 스캔이 실행됩니다.',
  '점검 항목: 보안 헤더 7종, 민감 경로 12개, SSL/TLS, 서버 정보 노출',
]

// google.com은 바로 위 안내문("허가받은 사이트만")과 모순되는 예시라 제외하고,
// 로컬 테스트 레인지(Juice Shop, test-range/)를 기본 예시로 둔다.
const SAMPLE_URLS = ['http://localhost:3000', 'https://example.com', 'http://testphp.vulnweb.com']

function FindingCard({ f, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const s = SEV[f.severity] ?? SEV.LOW
  return (
    <div className={`border rounded-xl overflow-hidden ${s.bg}`}>
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 p-3.5 text-left hover:bg-white/5 transition-colors">
        <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
        <span className="text-xs font-mono text-slate-500 shrink-0">{f.id}</span>
        <span className="text-sm font-medium flex-1 truncate">{f.title}</span>
        <span className="text-xs text-slate-500 hidden sm:block shrink-0">{f.category}</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded bg-black/20 ${s.color} shrink-0`}>{s.label}</span>
        {open ? <ChevronUp size={13} className="text-slate-500 shrink-0" /> : <ChevronDown size={13} className="text-slate-500 shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 pt-2 space-y-2 border-t border-white/10">
          <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>
          <div className="bg-slate-800/60 rounded-lg p-2.5">
            <p className="text-xs font-semibold text-blue-400 mb-0.5">권장 조치</p>
            <p className="text-xs text-slate-300">{f.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  )
}

function SSLBadge({ ssl }) {
  if (!ssl || ssl.valid === null) return null
  const ok = ssl.valid && ssl.expires_in_days > 30
  const warn = ssl.valid && ssl.expires_in_days <= 30
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${
      ok ? 'border-green-500/30 bg-green-500/10 text-green-300' :
      warn ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300' :
      'border-red-500/30 bg-red-500/10 text-red-300'
    }`}>
      {ok ? <Lock size={13} /> : <LockOpen size={13} />}
      <span className="font-semibold">SSL</span>
      <span>{ssl.issuer ?? '알 수 없음'}</span>
      {ssl.expires_in_days != null && <span>· {ssl.expires_in_days}일 남음</span>}
      {ssl.protocol && <span>· {ssl.protocol}</span>}
    </div>
  )
}

export default function WebScanner() {
  const [url, setUrl]         = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [history, setHistory] = useState([])

  const scan = async (target) => {
    const u = (target ?? url).trim()
    if (!u) return
    if (!authorized) {
      alert('스캔 전에 "이 사이트를 소유하고 있거나 스캔할 권한이 있음" 체크박스를 확인해주세요.')
      return
    }
    setUrl(u)
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/webscan/scan', { url: u, authorized })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 8))
    } catch (err) {
      alert('스캔 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const counts = result?.counts ?? {}

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="text-teal-400" size={26} /> 웹 취약점 스캐너
          </h1>
          <p className="text-slate-400 text-sm mt-1">URL을 입력하면 보안 헤더·SSL·노출 경로를 점검하고 취약점을 분석합니다.</p>
        </div>

        <GuidePanel title="웹 취약점 스캐너 사용 가이드" steps={GUIDE_STEPS} tips={GUIDE_TIPS} />

        <div className="bg-red-950/20 border border-red-500/30 rounded-xl p-3 flex gap-2">
          <ShieldAlert size={16} className="text-red-400 shrink-0 mt-0.5" />
          <p className="text-xs text-red-200">
            본인이 소유하고 있거나 명시적으로 승인받은 사이트에만 사용하세요. 무단 스캔은 대상 사이트 약관 위반이나
            법적 문제로 이어질 수 있습니다.
          </p>
        </div>

        {/* URL input */}
        <div className="flex gap-3">
          <div className="flex-1 flex items-center bg-slate-800 border border-slate-600 rounded-xl px-4 gap-2 focus-within:border-teal-500 transition-colors">
            <Globe size={16} className="text-slate-500 shrink-0" />
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && scan()}
              placeholder="https://example.com"
              className="flex-1 bg-transparent py-3 text-sm focus:outline-none placeholder-slate-600"
            />
          </div>
          <button
            onClick={() => scan()}
            disabled={loading || !url.trim() || !authorized}
            className="px-6 py-3 bg-teal-700 hover:bg-teal-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold text-sm transition-colors flex items-center gap-2 shrink-0"
          >
            <ShieldAlert size={15} />
            {loading ? '스캔 중...' : '웹 취약점 스캔'}
          </button>
        </div>

        <label className="flex items-start gap-2 text-xs text-slate-300 cursor-pointer">
          <input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-0.5" />
          <span>이 사이트를 소유하고 있거나 스캔할 권한이 있음을 확인합니다.</span>
        </label>

        {/* Sample URLs */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-slate-500">예시:</span>
          {SAMPLE_URLS.map(u => (
            <button key={u} onClick={() => scan(u)}
              className="text-xs text-teal-400 hover:text-teal-300 underline underline-offset-2">
              {u}
            </button>
          ))}
        </div>

        <div className="grid lg:grid-cols-5 gap-6">
          {/* History */}
          {history.length > 0 && (
            <div className="lg:col-span-2 bg-slate-800 border border-slate-700 rounded-xl p-4 self-start">
              <div className="flex justify-between items-center mb-3">
                <p className="text-xs font-semibold text-slate-400">최근 스캔 ({history.length}건)</p>
                <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                  <Trash2 size={13} />
                </button>
              </div>
              <div className="space-y-1.5">
                {history.map((h, i) => (
                  <button key={i} onClick={() => setResult(h)}
                    className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors">
                    <span className={`text-xs font-bold ${SCORE_COLOR(h.risk_score)}`}>{h.risk_score}</span>
                    <span className="text-xs text-slate-300 truncate flex-1">{h.url}</span>
                    <ExternalLink size={11} className="text-slate-500 shrink-0" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Results */}
          <div className={`space-y-4 ${history.length > 0 ? 'lg:col-span-3' : 'lg:col-span-5'}`}>
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <Globe size={40} className="text-slate-600" />
                <p className="text-sm text-slate-500">URL을 입력하고 스캔 버튼을 클릭하세요</p>
              </div>
            )}

            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <div className="w-10 h-10 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">웹사이트 보안을 점검 중...</p>
                <p className="text-xs text-slate-500">헤더 분석 · 경로 탐지 · SSL 확인</p>
              </div>
            )}

            {result && (
              <>
                {/* Score */}
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="text-center shrink-0">
                      <div className={`text-4xl font-bold ${SCORE_COLOR(result.risk_score)}`}>{result.risk_score}</div>
                      <div className="text-xs text-slate-500">위험 점수</div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="h-2.5 bg-slate-700 rounded-full overflow-hidden mb-2">
                        <div className={`h-full rounded-full ${SCORE_BG(result.risk_score)}`}
                          style={{ width: `${result.risk_score}%` }} />
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed">{result.summary}</p>
                    </div>
                  </div>

                  {/* Counts */}
                  <div className="grid grid-cols-4 gap-2">
                    {Object.entries(SEV).map(([k, s]) => (
                      <div key={k} className={`rounded-lg p-2.5 text-center border ${s.bg}`}>
                        <div className={`text-xl font-bold ${s.color}`}>{counts[k] ?? 0}</div>
                        <div className="text-xs text-slate-400">{s.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* SSL + Server info */}
                  <div className="flex flex-wrap gap-2">
                    <SSLBadge ssl={result.ssl} />
                    {result.server_info?.server && (
                      <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-300 text-xs">
                        <ShieldAlert size={13} /> Server: {result.server_info.server}
                      </div>
                    )}
                    {result.server_info?.x_powered_by && (
                      <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-300 text-xs">
                        <ShieldAlert size={13} /> X-Powered-By: {result.server_info.x_powered_by}
                      </div>
                    )}
                    {result.exposed_paths?.length > 0 && (
                      <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 text-xs">
                        <LockOpen size={13} /> 노출 경로: {result.exposed_paths.join(', ')}
                      </div>
                    )}
                    {result.exposed_paths?.length === 0 && (
                      <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-green-500/30 bg-green-500/10 text-green-300 text-xs">
                        <ShieldCheck size={13} /> 민감 경로 노출 없음
                      </div>
                    )}
                  </div>
                </div>

                {/* Findings */}
                <div>
                  <p className="text-sm font-semibold text-slate-300 mb-2">
                    취약점 목록 ({result.findings?.length ?? 0}개)
                  </p>
                  <div className="space-y-2">
                    {result.findings?.map((f, i) => (
                      <FindingCard key={f.id} f={f} defaultOpen={i === 0} />
                    ))}
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
