import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  Container, FileCode, Layers, Trash2, Download,
  AlertTriangle, ListOrdered, BadgeCheck, Upload, FileText, X,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'

const AUDIT_STEPS = [
  '감사할 파일 유형을 선택합니다 (Dockerfile / docker-compose.yml).',
  '해당 파일 내용을 그대로 붙여넣거나 파일로 업로드합니다. 환경 컨텍스트(선택)에 용도를 적으면 더 정확한 분석이 됩니다.',
  '[AI로 감사 실행] 버튼을 클릭합니다.',
  '발견 사항을 심각도 순으로 확인하고, 각 항목의 권장 조치를 반영합니다.',
  '이미지를 빌드한 뒤에는 trivy/docker scout 등으로 실제 알려진 CVE도 함께 스캔하는 것을 권장합니다.',
]
const AUDIT_TIPS = [
  '이 도구는 이미지를 빌드하거나 컨테이너를 실행하지 않습니다 — 텍스트만으로 정적 분석합니다.',
  'App 16(방화벽 정책 감사기)이 네트워크 규칙을, App 18(IAM 정책 감사기)이 권한을 감사한다면, 이 도구는 컨테이너 정의 자체(이미지·실행 옵션)를 감사합니다.',
  '결과는 참고용 초안입니다 — 실제 반영 전 반드시 담당자 검토와 스테이징 환경 검증을 거치세요.',
]

const SOURCE_ICONS = { dockerfile: FileCode, compose: Layers }

const PLACEHOLDERS = {
  dockerfile: `FROM node:latest\n\nENV DB_PASSWORD=SuperSecret123\n\nWORKDIR /app\nCOPY . .\nRUN npm install\n\nCMD ["node", "server.js"]`,
  compose: `services:\n  app:\n    image: myapp:latest\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock`,
}

const SAMPLE_FILES = {
  dockerfile: '/samples/container-audit/Dockerfile.sample.txt',
  compose: '/samples/container-audit/docker-compose.sample.yml',
}

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 // 2MB

export default function ContainerAudit() {
  const [sourceType, setSourceType] = useState('dockerfile')
  const [content, setContent] = useState('')
  const [context, setContext] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)
  const [uploadedFileName, setUploadedFileName] = useState('')
  const fileInputRef = useRef(null)

  useEffect(() => {
    axios.get('/api/container-audit/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const currentSource = guide?.source_types?.find(s => s.id === sourceType)

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      alert(`파일이 너무 큽니다 (${(file.size / 1024 / 1024).toFixed(1)}MB). 텍스트 파일은 보통 2MB를 넘지 않습니다.`)
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      setContent(String(reader.result ?? ''))
      setUploadedFileName(file.name)
    }
    reader.onerror = () => alert('파일을 읽는 중 오류가 발생했습니다. 텍스트 형식의 파일인지 확인해주세요.')
    reader.readAsText(file)
  }

  const clearUploadedFile = () => {
    setUploadedFileName('')
    setContent('')
  }

  const analyze = async () => {
    if (!content.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/container-audit/analyze', { source_type: sourceType, content, context })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('감사 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/container-audit/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `container-audit-${id}.md`
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
            <Container className="text-sky-400" size={26} /> 컨테이너/Dockerfile 감사기
          </h1>
          <p className="text-slate-400 text-sm mt-1">Dockerfile·docker-compose.yml을 붙여넣으면 AI가 root 실행·과도한 권한·이미지에 구워진 시크릿·미고정 베이스 이미지 등을 찾아 수정안을 제시합니다.</p>
        </div>

        <GuidePanel title="컨테이너/Dockerfile 감사기 사용 가이드" steps={AUDIT_STEPS} tips={AUDIT_TIPS} />

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">파일 유형</p>
              <div className="grid grid-cols-2 gap-2">
                {['dockerfile', 'compose'].map(id => {
                  const Icon = SOURCE_ICONS[id]
                  const label = guide?.source_types?.find(s => s.id === id)?.label ?? id
                  return (
                    <button
                      key={id}
                      onClick={() => setSourceType(id)}
                      className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                        sourceType === id ? 'bg-sky-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                      }`}
                    >
                      <Icon size={14} />{label}
                    </button>
                  )
                })}
              </div>
            </div>

            {currentSource && (
              <div className="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-2">
                <p className="text-xs font-medium text-sky-300">가져오는 방법: {currentSource.label}</p>
                <p className="text-[11px] text-slate-500">{currentSource.how_to_export}</p>
                <pre className="bg-slate-900 border border-slate-700 rounded-lg p-2 overflow-x-auto">
                  <code className="text-[11px] text-sky-300 font-mono whitespace-pre">
                    {currentSource.commands.join('\n')}
                  </code>
                </pre>
                {SAMPLE_FILES[sourceType] && (
                  <a
                    href={SAMPLE_FILES[sourceType]}
                    download
                    className="inline-flex items-center gap-1.5 text-[11px] text-sky-400 hover:text-sky-300 underline underline-offset-2"
                  >
                    <Download size={11} /> 예시 파일 다운로드 (바로 업로드해서 테스트 가능)
                  </a>
                )}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-slate-400">파일 내용 (붙여넣기 또는 업로드)</p>
                <div className="flex items-center gap-2">
                  {uploadedFileName && (
                    <span className="flex items-center gap-1 text-[11px] text-slate-500">
                      <FileText size={11} />{uploadedFileName}
                      <button onClick={clearUploadedFile} className="text-slate-500 hover:text-red-400" title="지우기">
                        <X size={11} />
                      </button>
                    </span>
                  )}
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1 text-[11px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg px-2.5 py-1"
                  >
                    <Upload size={11} /> 파일 업로드
                  </button>
                  <input ref={fileInputRef} type="file" accept=".txt,.yml,.yaml,text/plain" onChange={handleFileUpload} className="hidden" />
                </div>
              </div>
              <textarea
                value={content}
                onChange={e => { setContent(e.target.value); setUploadedFileName('') }}
                placeholder={PLACEHOLDERS[sourceType]}
                rows={10}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-sky-500 placeholder-slate-600"
              />
              <p className="text-[10px] text-slate-600 mt-1">업로드한 파일도 텍스트로 이 입력창에 그대로 채워집니다 — 전송 전 내용을 확인·수정할 수 있습니다.</p>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">환경 컨텍스트 (선택)</p>
              <input
                value={context}
                onChange={e => setContext(e.target.value)}
                placeholder="예: 결제 처리 백엔드, 프로덕션 배포용 이미지"
                className="w-full bg-slate-800 border border-slate-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-sky-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={analyze}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-sky-600 hover:bg-sky-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '감사 중...' : 'AI로 감사 실행'}
            </button>

            {guide?.disclaimer && (
              <p className="text-[11px] text-slate-500 italic">{guide.disclaimer}</p>
            )}
          </div>

          {/* Result Panel */}
          <div className="md:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <Container size={32} className="text-slate-600" />
                <p className="text-sm">감사 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 감사 중...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-400">종합 위험도</span>
                      <SeverityBadge severity={result.overall_risk} />
                    </div>
                    <button
                      onClick={() => downloadReport(result.id)}
                      className="shrink-0 flex items-center gap-1.5 text-xs bg-sky-600/20 text-sky-300 border border-sky-600/40 rounded-lg px-3 py-1.5 hover:bg-sky-600/30"
                    >
                      <Download size={13} /> Markdown 다운로드
                    </button>
                  </div>
                  <p className="text-sm text-slate-300">{result.summary}</p>
                  {result.stats && (
                    <div className="flex gap-3 mt-3 text-[11px] text-slate-400">
                      <span>전체 {result.stats.total}건</span>
                      {result.stats.critical > 0 && <span className="text-red-400 font-semibold">CRITICAL {result.stats.critical}</span>}
                      {result.stats.high > 0 && <span className="text-orange-400 font-semibold">HIGH {result.stats.high}</span>}
                      {result.stats.medium > 0 && <span className="text-yellow-400 font-semibold">MEDIUM {result.stats.medium}</span>}
                      {result.stats.low > 0 && <span className="text-blue-400">LOW {result.stats.low}</span>}
                    </div>
                  )}
                </div>

                <div className="space-y-3">
                  {result.findings?.map((f, i) => (
                    <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[10px] font-bold bg-sky-500/15 text-sky-300 border border-sky-500/30 rounded-full px-2 py-0.5">
                          {f.issue_type_label}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-slate-400 bg-slate-950/60 rounded-lg px-2 py-1.5 mb-2 overflow-x-auto whitespace-pre">
                        {f.rule_reference}
                      </p>
                      <p className="text-sm text-slate-300">{f.description}</p>
                      <div className="mt-2 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                        <AlertTriangle size={13} className="text-amber-400 shrink-0 mt-0.5" />
                        <p className="text-xs text-slate-400">
                          <span className="text-amber-300 font-medium">권장 조치: </span>{f.recommendation}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>

                {result.compliance_notes?.length > 0 && (
                  <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                    <p className="text-xs font-semibold text-blue-400 mb-3 flex items-center gap-1.5">
                      <BadgeCheck size={13} /> 컴플라이언스 참고
                    </p>
                    <ul className="space-y-1">
                      {result.compliance_notes.map((c, i) => (
                        <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                          <span className="text-blue-400 mt-0.5 shrink-0">•</span>
                          <span><b className="text-slate-200">{c.framework}:</b> {c.note}</span>
                        </li>
                      ))}
                    </ul>
                    <p className="text-[10px] text-slate-500 mt-2">참고용이며, 정확한 인증기준 충족 여부는 전문가 검토가 필요합니다.</p>
                  </div>
                )}

                <div className="bg-teal-950/20 border border-teal-500/20 rounded-xl p-4 flex items-center gap-2">
                  <ListOrdered size={14} className="text-teal-400 shrink-0" />
                  <p className="text-xs text-slate-300">
                    이미지를 빌드한 뒤 <span className="text-teal-300">trivy image / docker scout cves</span>로 실제 알려진 취약점도 함께 스캔해보세요.
                  </p>
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
                      <SeverityBadge severity={h.overall_risk} />
                      <span className="text-xs text-slate-300 truncate flex-1">{h.preview}</span>
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
