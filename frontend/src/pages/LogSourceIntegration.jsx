import { useState, useEffect } from 'react'
import axios from 'axios'
import { Terminal, Trash2, Plus, AlertTriangle, Copy, CheckCircle } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const LOG_STEPS = [
  '아래 폼에 소스 이름(예: "고객사 A rsyslog")을 입력해 등록하면, 그 소스 전용 Ingest Key가 즉시 발급됩니다.',
  '고객사 서버의 rsyslog 또는 syslog-ng 설정에 이 앱의 수집 URL과 발급된 Ingest Key를 넣어 HTTPS로 포워딩하도록 설정합니다 (아래 설정 예시 참고).',
  '설정을 반영(rsyslog/syslog-ng 재시작)하면 그 다음부터 로그가 실시간으로 이 앱의 App 1(대시보드) 분석 파이프라인에 흘러들어갑니다.',
  'CRITICAL로 판정되면 기존 알림 시스템(Slack/이메일)이 자동으로 발동합니다.',
]
const LOG_TIPS = [
  '이 서버는 UDP 514 같은 syslog 포트를 직접 열지 않습니다 — 고객사 쪽 rsyslog/syslog-ng가 이미 파싱한 로그를 HTTPS로 포워딩하는 안전한 방식입니다.',
  '소스마다 서로 다른 Ingest Key가 발급되어 격리됩니다 — 한 소스의 키가 유출돼도 다른 소스에는 영향 없습니다.',
  '로컬 개발 환경(localhost)은 외부 서버가 도달할 수 없으니, 실제 연동은 공인 도메인/고정 IP로 배포된 서버에서 테스트하세요.',
]

export default function LogSourceIntegration() {
  const [sources, setSources] = useState([])
  const [label, setLabel] = useState('')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [copiedKey, setCopiedKey] = useState(null)
  const [copiedUrl, setCopiedUrl] = useState(false)

  const ingestUrl = `${window.location.origin}/api/logs/ingest`

  const fetchSources = () => {
    axios.get('/api/log-sources').then(r => setSources(r.data.sources)).catch(() => {})
  }

  useEffect(() => { fetchSources() }, [])

  const copyUrl = () => {
    navigator.clipboard.writeText(ingestUrl)
    setCopiedUrl(true)
    setTimeout(() => setCopiedUrl(false), 2000)
  }

  const copyKey = (id, key) => {
    navigator.clipboard.writeText(key)
    setCopiedKey(id)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const createSource = async () => {
    if (!label.trim()) return
    setCreating(true)
    setError('')
    try {
      await axios.post('/api/log-sources', { label })
      setLabel('')
      fetchSources()
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setCreating(false)
    }
  }

  const deleteSource = async (id) => {
    await axios.delete(`/api/log-sources/${id}`)
    fetchSources()
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Terminal className="text-cyan-400" size={26} /> 외부 로그 소스 연동 (Syslog)
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            rsyslog/syslog-ng 등 임의의 로그 포워더를 HTTPS로 붙여 App 1(대시보드)에서 실시간 분석합니다.
          </p>
        </div>

        <GuidePanel title="로그 소스 연동 가이드" steps={LOG_STEPS} tips={LOG_TIPS} />

        {/* Ingest URL */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
          <p className="text-sm font-semibold text-slate-300">수집 URL (모든 소스 공통, 소스 구분은 Ingest Key로)</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 truncate">
              {ingestUrl}
            </code>
            <button onClick={copyUrl} className="flex items-center gap-1 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs shrink-0">
              {copiedUrl ? <CheckCircle size={13} /> : <Copy size={13} />} {copiedUrl ? '복사됨' : '복사'}
            </button>
          </div>
          <p className="text-xs text-amber-400 flex items-center gap-1">
            <AlertTriangle size={12} /> 실제 배포 시에는 이 URL이 외부(고객사 서버)에서 접근 가능한 공인 HTTPS 주소여야 합니다.
          </p>
        </div>

        {/* Create form */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
          <p className="text-sm font-semibold text-slate-300">새 로그 소스 등록</p>
          <div className="flex gap-2">
            <input
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="예: 고객사 A rsyslog"
              className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={createSource}
              disabled={creating || !label.trim()}
              className="flex items-center gap-1.5 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold shrink-0"
            >
              <Plus size={14} /> {creating ? '등록 중...' : '등록'}
            </button>
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>

        {/* Source list */}
        <div className="space-y-3">
          <p className="text-sm font-semibold text-slate-300">등록된 소스 ({sources.length}개)</p>
          {sources.length === 0 && (
            <p className="text-sm text-slate-500 text-center py-8">등록된 로그 소스가 없습니다.</p>
          )}
          {sources.map(source => (
            <div key={source.id} className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
              <div className="flex items-start justify-between gap-2">
                <p className="text-sm font-semibold text-slate-200">{source.label}</p>
                <button
                  onClick={() => deleteSource(source.id)}
                  className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-red-400 shrink-0"
                  title="삭제"
                >
                  <Trash2 size={14} />
                </button>
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-300 truncate">
                  {source.ingest_key}
                </code>
                <button
                  onClick={() => copyKey(source.id, source.ingest_key)}
                  className="flex items-center gap-1 px-2 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs shrink-0"
                >
                  {copiedKey === source.id ? <CheckCircle size={12} /> : <Copy size={12} />}
                </button>
              </div>
              {source.last_error && (
                <p className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle size={12} /> {source.last_error}</p>
              )}
              <p className="text-xs text-slate-400">
                수집된 로그 {source.events_ingested ?? 0}건
                {source.last_event_at ? ` · 마지막 수신: ${new Date(source.last_event_at).toLocaleString('ko-KR')}` : ' · 아직 수신 없음'}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
