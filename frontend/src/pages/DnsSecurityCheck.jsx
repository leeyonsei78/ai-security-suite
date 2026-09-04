import { useState, useEffect } from 'react'
import axios from 'axios'
import { MailCheck, Search, Download, Trash2 } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'

const CHECK_STEPS = [
  '점검할 도메인을 입력합니다 (예: example.com — https:// 없이 도메인만).',
  '[점검 실행] 버튼을 클릭하면 실시간으로 SPF/DMARC/DKIM/DNSSEC 레코드를 조회합니다.',
  '각 항목의 상태와 권장 조치를 확인합니다.',
  'SPF/DMARC를 처음 도입한다면 DMARC는 p=none(모니터링)부터 시작해 점진적으로 quarantine → reject로 강화하세요.',
]
const CHECK_TIPS = [
  '이 도구는 Claude AI를 쓰지 않고 Google Public DNS로 실시간 조회합니다 — 항상 실제 데이터로 동작합니다.',
  'DKIM은 흔히 쓰이는 셀렉터만 확인하는 best-effort 점검입니다. "못 찾음"이 "미적용 확정"을 의미하지는 않습니다.',
  '피싱 탐지/모의훈련도 함께 보려면 피싱 탐지기(App 2)·피싱 모의훈련 생성기(App 14)를 이용해보세요.',
]

const STATUS_LABELS = {
  MISSING: '없음', WEAK: '약함', OK: '적절', MISCONFIGURED: '설정 오류', INCOMPLETE: '불완전',
  MONITOR_ONLY: '모니터링 전용', FOUND: '발견됨', NOT_FOUND_COMMON: '흔한 셀렉터에서 못 찾음',
  LIKELY_ENABLED: '적용 추정', NOT_DETECTED: '미확인',
}

export default function DnsSecurityCheck() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)

  useEffect(() => {
    axios.get('/api/dns-security/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const check = async () => {
    const d = domain.trim()
    if (!d) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/dns-security/check', { domain: d })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('점검 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/dns-security/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `dns-security-${id}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <MailCheck className="text-emerald-400" size={26} /> DNS/이메일 보안 점검
          </h1>
          <p className="text-slate-400 text-sm mt-1">도메인의 SPF·DMARC·DKIM·DNSSEC 설정을 실시간으로 조회해 이메일 위조 방지 수준을 점검합니다.</p>
        </div>

        <GuidePanel title="DNS/이메일 보안 점검 사용 가이드" steps={CHECK_STEPS} tips={CHECK_TIPS} />

        <div className="flex gap-3">
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && check()}
            placeholder="example.com"
            className="flex-1 bg-slate-800 border border-slate-600 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-emerald-500 placeholder-slate-600"
          />
          <button
            onClick={check}
            disabled={loading || !domain.trim()}
            className="px-6 py-3 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold text-sm transition-colors flex items-center gap-2 shrink-0"
          >
            <Search size={15} />
            {loading ? '점검 중...' : '점검 실행'}
          </button>
        </div>

        {guide?.disclaimer && (
          <p className="text-[11px] text-slate-500 italic">{guide.disclaimer}</p>
        )}

        {loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-32 flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-slate-400">DNS 조회 중...</p>
          </div>
        )}

        {result && !loading && (
          <div className="space-y-4">
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-400">종합 위험도</span>
                  <SeverityBadge severity={result.overall_risk} />
                </div>
                <button
                  onClick={() => downloadReport(result.id)}
                  className="shrink-0 flex items-center gap-1.5 text-xs bg-emerald-600/20 text-emerald-300 border border-emerald-600/40 rounded-lg px-3 py-1.5 hover:bg-emerald-600/30"
                >
                  <Download size={13} /> Markdown 다운로드
                </button>
              </div>
              <p className="text-sm text-slate-300">{result.summary}</p>
            </div>

            <div className="grid sm:grid-cols-2 gap-3">
              {result.checks?.map((c, i) => (
                <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-sm font-semibold text-slate-200">{c.check}</span>
                    <SeverityBadge severity={c.severity} />
                  </div>
                  <p className="text-[11px] text-emerald-300 mb-1">{STATUS_LABELS[c.status] ?? c.status}</p>
                  {c.value && (
                    <p className="text-[11px] font-mono text-slate-400 bg-slate-950/60 rounded-lg px-2 py-1.5 mb-2 overflow-x-auto whitespace-pre-wrap break-all">
                      {c.value}
                    </p>
                  )}
                  <p className="text-xs text-slate-300">{c.description}</p>
                  {c.recommendation && (
                    <p className="text-xs text-amber-300 mt-2">
                      <span className="font-medium">권장 조치: </span>
                      <span className="text-slate-400">{c.recommendation}</span>
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
            <div className="flex justify-between items-center mb-3">
              <p className="text-xs font-semibold text-slate-400">최근 점검 ({history.length}건)</p>
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
                  <SeverityBadge severity={h.overall_risk} />
                  <span className="text-xs text-slate-300 truncate flex-1">{h.domain}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
