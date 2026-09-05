import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'
import {
  Radar, Package, Network, Trash2, Download, AlertTriangle, ShieldAlert, ExternalLink,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'
import FileUploadButton from '../components/FileUploadButton'

const DEP_STEPS = [
  "매니페스트 형식을 선택합니다 (Python requirements.txt / Node.js package.json).",
  '실제 매니페스트 내용을 붙여넣습니다 (한 번에 최대 8개 패키지까지 스캔됩니다).',
  '[스캔 실행]을 클릭하면 각 패키지 이름+버전으로 NVD를 실시간 검색해 일치 가능성이 있는 CVE를 찾습니다.',
  "결과의 CVE를 클릭하면 'CVE 조회' 페이지에서 NVD 원본 데이터를 바로 확인할 수 있습니다.",
]
const NET_STEPS = [
  '스캔 대상(IP 또는 호스트명)을 입력합니다 — 사설망(10/8, 172.16/12, 192.168/16)과 로컬호스트만 지원됩니다.',
  "소유하거나 테스트 권한이 있는 대상임을 체크박스로 확인합니다.",
  '[스캔 실행]을 클릭하면 흔한 서비스 포트 ~25개에 실제 TCP 연결을 시도하고, 열린 포트의 배너를 수집합니다.',
  '배너에서 얻은 서비스/버전 정보로 NVD를 검색해 알려진 CVE를 함께 보여줍니다.',
]
const TIPS = [
  'NVD 키워드 검색 기반 best-effort 매칭입니다 — 정밀한 SCA/스캔이 필요하면 pip-audit, npm audit, Trivy, nmap -sV 같은 전용 도구를 사용하세요.',
  '패키지/서비스 이름이 흔한 영단어인 경우 무관한 CVE가 섞여 나올 수 있습니다. 각 결과를 실제로 검토하세요.',
  '네트워크 스캔은 승인 없는 대상에는 절대 사용하지 마세요.',
]

function CveList({ cves }) {
  if (!cves?.length) return null
  return (
    <div className="mt-2 space-y-1.5">
      {cves.map(c => {
        const cvss = c.cvss || {}
        return (
          <Link
            key={c.id}
            to={`/cve-lookup?cve=${c.id}`}
            className="flex items-start gap-2 bg-slate-900/60 hover:bg-slate-900 rounded-lg p-2 transition-colors group"
          >
            <SeverityBadge severity={cvss.base_severity || 'INFO'} />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-mono text-slate-300 flex items-center gap-1">
                {c.id} {cvss.base_score && <span className="text-slate-500">({cvss.base_score})</span>}
                <ExternalLink size={11} className="text-slate-600 group-hover:text-slate-400" />
              </p>
              <p className="text-[11px] text-slate-500 line-clamp-2">{c.description}</p>
            </div>
          </Link>
        )
      })}
    </div>
  )
}

function DependencyTab({ guide }) {
  const [manifestType, setManifestType] = useState('pip')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])

  const placeholder = guide?.dependency?.manifest_types?.find(m => m.id === manifestType)?.example ?? ''

  const scan = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/infra-scan/dependency/analyze', { manifest_type: manifestType, content: body })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('스캔 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/infra-scan/dependency/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `dependency-scan-${id}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="grid md:grid-cols-5 gap-6">
      <div className="md:col-span-2 space-y-4">
        <div>
          <p className="text-xs font-semibold text-slate-400 mb-2">매니페스트 형식</p>
          <div className="grid grid-cols-2 gap-2">
            {guide?.dependency?.manifest_types?.map(m => (
              <button
                key={m.id}
                onClick={() => setManifestType(m.id)}
                className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                  manifestType === m.id ? 'bg-violet-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold text-slate-400">매니페스트 내용</p>
            <FileUploadButton onExtracted={(text) => { setContent(text); scan(text) }} />
          </div>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            placeholder={placeholder}
            rows={12}
            className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-violet-500 placeholder-slate-600"
          />
        </div>

        <button
          onClick={() => scan()}
          disabled={loading || !content.trim()}
          className="w-full py-3 bg-violet-600 hover:bg-violet-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
        >
          {loading ? 'NVD 조회 중... (패키지당 최대 수 초)' : '스캔 실행'}
        </button>
        {guide?.dependency?.note && <p className="text-[11px] text-slate-500 italic">{guide.dependency.note}</p>}
      </div>

      <div className="md:col-span-3 space-y-4">
        {!result && !loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
            <Package size={32} className="text-slate-600" />
            <p className="text-sm">스캔 결과가 여기에 표시됩니다</p>
          </div>
        )}
        {loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-slate-400">패키지별로 NVD를 순차 조회 중...</p>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 flex items-center justify-between">
              <div className="text-xs text-slate-400">
                발견 {result.total_packages_found}개 중 {result.packages_scanned}개 스캔
                {result.truncated && <span className="text-amber-400"> (한도 초과, 일부만 스캔됨)</span>}
              </div>
              <button
                onClick={() => downloadReport(result.id)}
                className="flex items-center gap-1.5 text-xs bg-violet-600/20 text-violet-300 border border-violet-600/40 rounded-lg px-3 py-1.5 hover:bg-violet-600/30"
              >
                <Download size={13} /> Markdown 다운로드
              </button>
            </div>

            {result.results?.map((r, i) => (
              <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-sm font-semibold text-slate-200">{r.name}</p>
                  {r.version && <span className="text-xs text-slate-500 font-mono">{r.version}</span>}
                  {!r.pinned && r.version && <span className="text-[10px] bg-slate-700 text-slate-400 rounded px-1.5 py-0.5">버전 범위</span>}
                </div>
                {r.note && <p className="text-xs text-slate-500 italic mb-1">{r.note}</p>}
                {r.matched_cves?.length > 0 ? <CveList cves={r.matched_cves} /> : <p className="text-xs text-slate-500">일치하는 CVE 없음</p>}
              </div>
            ))}
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
            <div className="flex justify-between items-center mb-3">
              <p className="text-xs font-semibold text-slate-400">최근 스캔 ({history.length}건)</p>
              <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400"><Trash2 size={13} /></button>
            </div>
            <div className="space-y-2">
              {history.map((h, i) => (
                <button key={i} onClick={() => setResult(h)} className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors">
                  <Package size={14} className="text-violet-400" />
                  <span className="text-xs text-slate-300 truncate flex-1">{h.preview}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function NetworkTab({ guide }) {
  const [target, setTarget] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])

  const scan = async () => {
    if (!target.trim() || !authorized) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/infra-scan/network/scan', { target, authorized })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('스캔 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/infra-scan/network/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `network-scan-${id}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="grid md:grid-cols-5 gap-6">
      <div className="md:col-span-2 space-y-4">
        <div className="bg-red-950/20 border border-red-500/30 rounded-xl p-3 flex gap-2">
          <ShieldAlert size={16} className="text-red-400 shrink-0 mt-0.5" />
          <p className="text-xs text-red-200">
            소유하거나 테스트 권한이 명확한 대상에만 사용하세요. 사설망({guide?.network?.allowed_ranges?.join(', ')})만 지원되며 공인 IP는 서버에서 차단됩니다.
          </p>
        </div>

        <div>
          <p className="text-xs font-semibold text-slate-400 mb-2">스캔 대상</p>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="예: 192.168.0.1, 10.0.0.5, localhost"
            className="w-full bg-slate-800 border border-slate-600 rounded-xl px-4 py-2.5 text-sm font-mono focus:outline-none focus:border-red-500 placeholder-slate-600"
          />
        </div>

        <label className="flex items-start gap-2 text-xs text-slate-300 cursor-pointer">
          <input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="mt-0.5" />
          <span>이 대상을 소유하고 있거나 테스트할 권한이 있음을 확인합니다.</span>
        </label>

        <button
          onClick={scan}
          disabled={loading || !target.trim() || !authorized}
          className="w-full py-3 bg-red-600 hover:bg-red-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
        >
          {loading ? `포트 스캔 중... (~${guide?.network?.ports_scanned ?? 25}개 포트)` : '스캔 실행'}
        </button>
        {guide?.network?.note && <p className="text-[11px] text-slate-500 italic">{guide.network.note}</p>}
      </div>

      <div className="md:col-span-3 space-y-4">
        {!result && !loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
            <Network size={32} className="text-slate-600" />
            <p className="text-sm">스캔 결과가 여기에 표시됩니다</p>
          </div>
        )}
        {loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-slate-400">실제 TCP 연결로 포트를 확인 중...</p>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 flex items-center justify-between">
              <div className="text-xs text-slate-400">
                {result.target} ({result.resolved_ip}) — {result.ports_scanned}개 포트 중 {result.open_ports?.length ?? 0}개 열림, {result.duration_ms}ms
              </div>
              <button
                onClick={() => downloadReport(result.id)}
                className="flex items-center gap-1.5 text-xs bg-red-600/20 text-red-300 border border-red-600/40 rounded-lg px-3 py-1.5 hover:bg-red-600/30"
              >
                <Download size={13} /> Markdown 다운로드
              </button>
            </div>

            {result.open_ports?.length === 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500">
                <p className="text-sm">열린 포트가 없습니다 (스캔한 ~{result.ports_scanned}개 포트 기준).</p>
              </div>
            )}

            {result.open_ports?.map((r, i) => (
              <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-bold bg-red-500/15 text-red-300 border border-red-500/30 rounded-full px-2 py-0.5">{r.port}/tcp</span>
                  <p className="text-sm font-semibold text-slate-200">{r.service}</p>
                </div>
                {r.banner && <p className="text-xs font-mono text-slate-400 bg-slate-950/60 rounded-lg px-2 py-1.5 mb-1 overflow-x-auto whitespace-pre">{r.banner}</p>}
                {r.note && <p className="text-xs text-slate-500 italic mb-1">{r.note}</p>}
                <CveList cves={r.matched_cves} />
              </div>
            ))}
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
            <div className="flex justify-between items-center mb-3">
              <p className="text-xs font-semibold text-slate-400">최근 스캔 ({history.length}건)</p>
              <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400"><Trash2 size={13} /></button>
            </div>
            <div className="space-y-2">
              {history.map((h, i) => (
                <button key={i} onClick={() => setResult(h)} className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors">
                  <Network size={14} className="text-red-400" />
                  <span className="text-xs text-slate-300 truncate flex-1">{h.target} ({h.resolved_ip})</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function InfraScanner() {
  const [tab, setTab] = useState('dependency')
  const [guide, setGuide] = useState(null)

  useEffect(() => {
    axios.get('/api/infra-scan/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Radar className="text-violet-400" size={26} /> 인프라 취약점 스캐너
          </h1>
          <p className="text-slate-400 text-sm mt-1">패키지 의존성과 실제 네트워크 대상을 대상으로 NVD 실시간 데이터 기반 취약점을 점검합니다.</p>
        </div>

        <GuidePanel title="인프라 취약점 스캐너 사용 가이드" steps={tab === 'dependency' ? DEP_STEPS : NET_STEPS} tips={TIPS} />

        <div className="flex gap-2">
          <button
            onClick={() => setTab('dependency')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === 'dependency' ? 'bg-violet-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
            }`}
          >
            <Package size={15} /> 의존성(SCA) 스캔
          </button>
          <button
            onClick={() => setTab('network')}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === 'network' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
            }`}
          >
            <Network size={15} /> 네트워크 라이브 스캔
          </button>
        </div>

        {guide?.disclaimer && (
          <div className="bg-amber-950/20 border border-amber-500/20 rounded-xl p-3 flex gap-2">
            <AlertTriangle size={14} className="text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-200">{guide.disclaimer}</p>
          </div>
        )}

        {tab === 'dependency' ? <DependencyTab guide={guide} /> : <NetworkTab guide={guide} />}
      </div>
    </div>
  )
}
