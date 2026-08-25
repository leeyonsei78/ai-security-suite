import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'
import {
  Database, Search, ExternalLink, Calendar, Tag, AlertCircle, Loader2, History, Trash2,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const CVE_STEPS = [
  '특정 CVE 번호를 알고 있다면 위쪽 입력창에 CVE-YYYY-NNNNN 형식으로 입력하고 [조회]를 누릅니다.',
  '제품명이나 키워드(예: log4j, openssl)로 찾고 싶다면 아래 검색창을 사용합니다.',
  '결과의 CVSS 점수·심각도·설명·CWE·참고 링크는 전부 NVD(미국 국가 취약점 데이터베이스) 공식 API에서 실시간으로 가져온 실제 데이터입니다.',
  '취약점 스캐너(App 3)에서 AI가 CVE를 언급한 결과라면, 카드 안의 [실시간 CVE 조회] 링크로 바로 여기 넘어와 실제 데이터와 대조할 수 있습니다.',
]
const CVE_TIPS = [
  '이 앱은 Claude AI를 쓰지 않습니다 — Anthropic API 키 유무와 무관하게 항상 실제 NVD 공식 API를 조회합니다.',
  'API 키 없이는 NVD 요청 한도가 30초당 5건으로 제한됩니다. 너무 자주 조회하면 잠시 대기해야 할 수 있습니다.',
  '검색 결과는 최신순이 아니라 NVD 관련도 기준으로 정렬됩니다.',
]

const SEV_STYLE = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  NONE: 'bg-slate-600/20 text-slate-400 border-slate-600/40',
}

function CveDetail({ cve }) {
  const sevStyle = SEV_STYLE[cve.cvss?.base_severity] ?? SEV_STYLE.NONE
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <h3 className="text-lg font-bold font-mono text-slate-100">{cve.id}</h3>
        <div className="flex items-center gap-2">
          {cve.cvss ? (
            <span className={`text-xs font-bold px-2.5 py-1 rounded border ${sevStyle}`} title={cve.cvss.vector}>
              CVSS {cve.cvss.version} — {cve.cvss.base_score} {cve.cvss.base_severity}
            </span>
          ) : (
            <span className="text-xs text-slate-500">CVSS 점수 없음</span>
          )}
          {cve.vuln_status && (
            <span className="text-[10px] bg-slate-700 text-slate-300 px-2 py-1 rounded">{cve.vuln_status}</span>
          )}
        </div>
      </div>

      <p className="text-sm text-slate-300 leading-relaxed">{cve.description}</p>

      {cve.cvss?.vector && (
        <p className="text-xs font-mono text-slate-500">{cve.cvss.vector}</p>
      )}

      <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
        {cve.published && (
          <span className="flex items-center gap-1"><Calendar size={12} /> 공개: {cve.published.slice(0, 10)}</span>
        )}
        {cve.last_modified && (
          <span className="flex items-center gap-1"><Calendar size={12} /> 최종 수정: {cve.last_modified.slice(0, 10)}</span>
        )}
      </div>

      {cve.cwe_ids?.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <Tag size={12} className="text-slate-500" />
          {cve.cwe_ids.map(c => (
            <span key={c} className="text-[11px] bg-purple-500/10 text-purple-300 border border-purple-500/30 rounded-full px-2 py-0.5">{c}</span>
          ))}
        </div>
      )}

      {cve.references?.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-slate-400 mb-1.5">참고 링크</p>
          <ul className="space-y-1">
            {cve.references.map((url, i) => (
              <li key={i}>
                <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 break-all">
                  <ExternalLink size={11} className="shrink-0" /> {url}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-[10px] text-slate-600">출처: {cve.source}</p>
    </div>
  )
}

export default function CveLookup() {
  const [searchParams] = useSearchParams()
  const [cveId, setCveId] = useState('')
  const [keyword, setKeyword] = useState('')
  const [result, setResult] = useState(null)
  const [searchResults, setSearchResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [hasApiKey, setHasApiKey] = useState(false)
  const [history, setHistory] = useState([])

  useEffect(() => {
    axios.get('/api/cve/status').then(r => setHasApiKey(r.data.has_api_key)).catch(() => {})
    axios.get('/api/cve/history').then(r => setHistory(r.data.history)).catch(() => {})
  }, [])

  const lookup = async (id) => {
    const target = (id ?? cveId).trim()
    if (!target) return
    setLoading(true)
    setError('')
    setResult(null)
    setSearchResults(null)
    try {
      const res = await axios.get(`/api/cve/${encodeURIComponent(target)}`)
      setResult(res.data)
      setCveId(target)
      setHistory(h => [res.data, ...h.filter(x => x.id !== res.data.id)].slice(0, 10))
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const q = searchParams.get('cve')
    if (q) lookup(q)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  const search = async () => {
    if (keyword.trim().length < 3) {
      setError('검색어는 3자 이상 입력하세요.')
      return
    }
    setLoading(true)
    setError('')
    setResult(null)
    setSearchResults(null)
    try {
      const res = await axios.get('/api/cve/search', { params: { keyword: keyword.trim(), results_per_page: 10 } })
      setSearchResults(res.data)
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Database className="text-cyan-400" size={26} /> CVE 실시간 조회
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            NVD(미국 국가 취약점 데이터베이스) 공식 API를 실시간으로 조회합니다 — 이 프로젝트에서 Claude AI가 아닌 실제 외부 데이터를 쓰는 유일한 앱입니다.
            {!hasApiKey && <span className="text-amber-400"> (NVD_API_KEY 미설정 — 30초당 5건으로 제한됩니다)</span>}
          </p>
        </div>

        <GuidePanel title="CVE 실시간 조회 사용 가이드" steps={CVE_STEPS} tips={CVE_TIPS} />

        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
          <div>
            <p className="text-xs font-semibold text-slate-400 mb-1.5">CVE 번호로 조회</p>
            <div className="flex gap-2">
              <input
                value={cveId}
                onChange={e => setCveId(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && lookup()}
                placeholder="CVE-2021-44228"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500 placeholder-slate-600"
              />
              <button
                onClick={() => lookup()}
                disabled={loading || !cveId.trim()}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold transition-colors"
              >
                조회
              </button>
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-slate-400 mb-1.5">키워드로 검색 (제품명 등)</p>
            <div className="flex gap-2">
              <input
                value={keyword}
                onChange={e => setKeyword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && search()}
                placeholder="log4j, openssl, wordpress ..."
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 placeholder-slate-600"
              />
              <button
                onClick={search}
                disabled={loading || keyword.trim().length < 3}
                className="flex items-center gap-1.5 px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-500 rounded-lg text-sm font-semibold transition-colors"
              >
                <Search size={14} /> 검색
              </button>
            </div>
          </div>
        </div>

        {loading && (
          <div className="flex items-center justify-center gap-2 text-slate-400 py-8">
            <Loader2 size={18} className="animate-spin" /> NVD API 조회 중...
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start gap-2">
            <AlertCircle size={16} className="text-red-400 shrink-0 mt-0.5" />
            <p className="text-sm text-red-300">{error}</p>
          </div>
        )}

        {result && <CveDetail cve={result} />}

        {searchResults && (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">전체 {searchResults.total_results.toLocaleString()}건 중 {searchResults.results.length}건 표시</p>
            {searchResults.results.map(cve => (
              <button key={cve.id} onClick={() => lookup(cve.id)} className="w-full text-left">
                <div className="bg-slate-800 border border-slate-700 hover:border-cyan-600 rounded-xl p-4 transition-colors">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-slate-200">{cve.id}</span>
                    {cve.cvss ? (
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${SEV_STYLE[cve.cvss.base_severity] ?? SEV_STYLE.NONE}`}>
                        {cve.cvss.base_score} {cve.cvss.base_severity}
                      </span>
                    ) : <span className="text-[10px] text-slate-500">CVSS 없음</span>}
                  </div>
                  <p className="text-xs text-slate-400 mt-1.5">{cve.description}</p>
                </div>
              </button>
            ))}
          </div>
        )}

        {!result && !searchResults && !loading && !error && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-40 flex flex-col items-center justify-center gap-2">
            <Database size={28} className="text-slate-600" />
            <p className="text-sm">CVE 번호를 조회하거나 키워드로 검색해보세요</p>
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
            <div className="flex justify-between items-center mb-3">
              <p className="text-xs font-semibold text-slate-400 flex items-center gap-1.5"><History size={13} /> 최근 조회</p>
              <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                <Trash2 size={13} />
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {history.map((h, i) => (
                <button
                  key={i}
                  onClick={() => lookup(h.id)}
                  className="text-xs font-mono bg-slate-900 border border-slate-700 hover:border-cyan-600 rounded-lg px-2.5 py-1 text-slate-300"
                >
                  {h.id}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
