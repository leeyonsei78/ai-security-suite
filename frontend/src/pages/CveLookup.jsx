import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'
import {
  Database, Search, ExternalLink, Calendar, Tag, AlertCircle, Loader2, History, Trash2,
  Wifi, WifiOff, Upload, RefreshCw,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const CVE_STEPS = [
  '특정 CVE 번호를 알고 있다면 위쪽 입력창에 CVE-YYYY-NNNNN 형식으로 입력하고 [조회]를 누릅니다.',
  '제품명이나 키워드(예: log4j, openssl)로 찾고 싶다면 아래 검색창을 사용합니다.',
  '결과의 CVSS 점수·심각도·설명·CWE·참고 링크는 전부 NVD(미국 국가 취약점 데이터베이스) 공식 API에서 실시간으로 가져온 실제 데이터입니다.',
  '취약점 스캐너(App 3)에서 AI가 CVE를 언급한 결과라면, 카드 안의 [실시간 CVE 조회] 링크로 바로 여기 넘어와 실제 데이터와 대조할 수 있습니다.',
]
const CVE_TIPS = [
  '이 앱은 AI를 전혀 쓰지 않습니다 — API 키 유무와 무관하게 항상 실제 NVD 공식 API를 직접 조회합니다.',
  'API 키 없이는 NVD 요청 한도가 30초당 5건으로 제한됩니다. 너무 자주 조회하면 잠시 대기해야 할 수 있습니다.',
  '검색 결과는 최신순이 아니라 NVD 관련도 기준으로 정렬됩니다.',
  '온라인 상태에서 조회에 성공한 CVE는 특별히 뭔가를 누르지 않아도 자동으로 로컬 캐시에 쌓입니다 — 인터넷이 끊겨도 예전에 조회했던 CVE는 계속 조회할 수 있습니다.',
  '"피드 가져오기"는 아직 한 번도 조회하지 않은 CVE까지 한 번에 대량으로 미리 담아두고 싶을 때 쓰는 별도 기능입니다 — 아래 상태 박스에서 자세히 설명합니다.',
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
        <h3 className="text-lg font-bold font-mono text-slate-100 flex items-center gap-2">
          {cve.id}
          {cve._offline_cache && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 flex items-center gap-1">
              <WifiOff size={10} /> 로컬 캐시
            </span>
          )}
        </h3>
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
  const [status, setStatus] = useState(null)
  const [history, setHistory] = useState([])
  const [importing, setImporting] = useState(false)
  const [importMsg, setImportMsg] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [refreshMsg, setRefreshMsg] = useState('')

  const refreshStatus = () => {
    axios.get('/api/cve/status').then(r => setStatus(r.data)).catch(() => {})
  }

  useEffect(() => {
    refreshStatus()
    axios.get('/api/cve/history').then(r => setHistory(r.data.history)).catch(() => {})
  }, [])

  const hasApiKey = status?.has_api_key ?? false
  const isOffline = status?.network_mode === 'offline'

  const importFeed = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true)
    setImportMsg('')
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/cve/import-feed', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      setImportMsg(`가져오기 완료: 피드 ${res.data.total_in_feed}건 중 ${res.data.imported}건을 로컬 캐시에 저장했습니다.`)
      refreshStatus()
    } catch (err) {
      setImportMsg('가져오기 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setImporting(false)
      e.target.value = ''
    }
  }

  const refreshLatest = async () => {
    setRefreshing(true)
    setRefreshMsg('')
    try {
      const res = await axios.post('/api/cve/refresh', null, { params: { days: 7 } })
      setRefreshMsg(`최신화 완료: 최근 7일간 NVD에서 수정된 ${res.data.total_in_range}건 중 ${res.data.imported}건을 로컬 캐시에 저장했습니다.`)
      refreshStatus()
    } catch (err) {
      setRefreshMsg('최신화 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setRefreshing(false)
    }
  }

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
            NVD(미국 국가 취약점 데이터베이스) 공식 API를 실시간으로 조회합니다 — 이 프로젝트에서 AI를 쓰지 않고 실제 외부 데이터를 직접 조회하는 유일한 앱입니다.
            {!hasApiKey && <span className="text-amber-400"> (NVD_API_KEY 미설정 — 30초당 5건으로 제한됩니다)</span>}
          </p>
        </div>

        <GuidePanel title="CVE 실시간 조회 사용 가이드" steps={CVE_STEPS} tips={CVE_TIPS} />

        <div className={`border rounded-xl p-4 space-y-3 ${isOffline ? 'bg-amber-500/10 border-amber-500/30' : 'bg-slate-800 border-slate-700'}`}>
          <div className="flex items-start gap-3">
            {isOffline ? <WifiOff size={18} className="text-amber-400 shrink-0 mt-0.5" /> : <Wifi size={18} className="text-green-400 shrink-0 mt-0.5" />}
            <div className="flex-1 min-w-0">
              <p className={`text-sm font-semibold ${isOffline ? 'text-amber-400' : 'text-green-400'}`}>
                {isOffline ? '오프라인 모드 — NVD에 연결할 수 없어 로컬 캐시만 조회합니다' : '온라인 — NVD 실시간 조회 중'}
              </p>
              <p className="text-xs text-slate-400 mt-1">
                로컬 캐시 {status?.offline_cache?.cached_count ?? 0}건
                {status?.offline_cache?.last_updated && ` · 마지막 갱신 ${new Date(status.offline_cache.last_updated * 1000).toLocaleString()}`}
              </p>
              {importMsg && <p className="text-xs text-slate-300 mt-1">{importMsg}</p>}
              {refreshMsg && <p className="text-xs text-slate-300 mt-1">{refreshMsg}</p>}
            </div>
            <div className="flex flex-col gap-1.5 shrink-0">
              <button
                onClick={refreshLatest}
                disabled={refreshing || isOffline}
                title={isOffline ? '오프라인 상태에서는 사용할 수 없습니다' : ''}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-800 disabled:text-slate-500 rounded-lg text-xs font-medium transition-colors"
              >
                <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
                {refreshing ? '최신화 중...' : '지금 최신 데이터 가져오기'}
              </button>
              <label className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs font-medium cursor-pointer transition-colors">
                <Upload size={13} />
                {importing ? '가져오는 중...' : '피드 가져오기'}
                <input type="file" accept=".json" className="hidden" onChange={importFeed} disabled={importing} />
              </label>
            </div>
          </div>

          <div className="text-xs text-slate-400 border-t border-slate-700/60 pt-3 space-y-1.5">
            <p>
              <span className="text-slate-300 font-semibold">자동 캐시: </span>
              온라인일 때 조회에 성공한 CVE는 아무것도 누르지 않아도 자동으로 위 "로컬 캐시"에 쌓입니다 — 나중에 인터넷이
              끊기면 이 화면이 자동으로 "오프라인 모드"로 전환되고, 예전에 조회했던 CVE는 계속 조회할 수 있습니다.
            </p>
            <p>
              <span className="text-slate-300 font-semibold">"지금 최신 데이터 가져오기"가 하는 일: </span>
              이 버튼을 누르면 <b>이 앱이 직접</b> NVD에 접속해 최근 7일간 새로 등록되거나 수정된 CVE 전체를 가져와 로컬
              캐시에 저장합니다 — 파일을 찾아 받고 업로드하는 과정 없이, 온라인 상태에서 버튼 한 번으로 최신화됩니다.
              다만 인터넷이 되는 PC에서만 동작합니다(폐쇄망에서는 비활성화).
            </p>
            <p>
              <span className="text-slate-300 font-semibold">"피드 가져오기"가 하는 일: </span>
              위 버튼과 달리 <b>완전히 인터넷이 없는 폐쇄망 PC</b>에서도 데이터를 채울 수 있는 방법입니다. 인터넷이 되는
              다른 PC에서 <span className="font-mono text-slate-300">nvd.nist.gov/vuln/data-feeds</span> 공식 페이지의{' '}
              <span className="font-mono text-slate-300">JSON 2.0</span> 형식 CVE 피드(.json.gz, 원하는 연도 전체)를 내려받아
              압축을 풀고, 조직의 반입(폐쇄망 이관) 승인 절차를 거쳐 이 PC로 옮긴 뒤 업로드하세요. 최근 며칠치를 자동으로
              최신화하는 위 버튼과 달리, 특정 연도 전체처럼 더 넓은 과거 범위를 한 번에 채우고 싶을 때도 유용합니다.
            </p>
          </div>
        </div>

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
