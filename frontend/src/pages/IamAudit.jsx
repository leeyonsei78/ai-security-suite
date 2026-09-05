import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  KeyRound, UserCog, Fingerprint, Trash2, Download,
  AlertTriangle, ListOrdered, BadgeCheck, Upload, FileText, X,
  Cloud, Server, WifiOff, FlaskConical,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'
import CopyButton from '../components/CopyButton'
import { DEFAULT_ACCEPT as UPLOAD_ACCEPT } from '../components/FileUploadButton'

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

const AUDIT_STEPS = [
  '감사할 클라우드 IAM 플랫폼을 선택합니다 (AWS IAM / Azure RBAC / GCP IAM).',
  "선택한 플랫폼에 맞는 명령어로 실제 정책·사용자 정보를 조회합니다 (아래 '정보 가져오는 방법' 참고).",
  '조회 결과를 그대로 복사해 붙여넣거나, 파일로 저장해 업로드합니다. 환경 컨텍스트(선택)에 용도를 적으면 더 정확한 분석이 됩니다.',
  '[AI로 감사 실행] 버튼을 클릭합니다.',
  '발견 사항을 심각도 순으로 확인하고, 각 항목의 권장 조치를 반영합니다.',
  '네트워크/방화벽 규칙도 함께 점검하려면 결과 하단의 방화벽 정책 감사기 링크로 이동합니다.',
]
const AUDIT_TIPS = [
  '방화벽 정책 감사기(App 16)가 "네트워크 규칙"을 감사한다면, 이 도구는 "누가 무엇에 접근할 수 있는가(권한)"를 감사합니다.',
  '정책/사용자 정보 텍스트만으로 분석하며 실제 클라우드 계정에 연결하거나 권한을 변경하지 않습니다.',
  '결과는 참고용 초안입니다 — 실제 반영 전 반드시 담당자 검토와 최소 권한 원칙에 따른 검증을 거치세요.',
]

const SOURCE_ICONS = { aws_iam: KeyRound, azure_rbac: UserCog, gcp_iam: Fingerprint }

const PLACEHOLDERS = {
  aws_iam: `User: deploy-bot\ninline policy "AdminAccess": { "Action": "*", "Resource": "*", "Effect": "Allow" }\n\nUser: jkim — MFADevices: [] (콘솔 로그인 활성화)`,
  azure_rbac: `roleAssignment: principalName=jane.dev@company.com, roleDefinitionName=Owner, scope=/subscriptions/<sub-id>\nuser: jane.dev@company.com — strongAuthenticationMethods: []`,
  gcp_iam: `bindings: { role: "roles/storage.objectViewer", members: ["allUsers"] }\nbindings: { role: "roles/owner", members: ["user:alice@company.com"] }`,
}

const SAMPLE_FILES = {
  aws_iam: '/samples/iam-audit/aws-iam-export.json',
  azure_rbac: '/samples/iam-audit/azure-rbac-export.json',
  gcp_iam: '/samples/iam-audit/gcp-iam-policy.json',
}

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 // 2MB — 정책/사용자 텍스트 용도라 충분히 넉넉한 상한

export default function IamAudit() {
  const [sourceType, setSourceType] = useState('aws_iam')
  const [content, setContent] = useState('')
  const [context, setContext] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)
  const [uploadedFileName, setUploadedFileName] = useState('')
  const [uploading, setUploading] = useState(false)
  const fileInputRef = useRef(null)

  useEffect(() => {
    axios.get('/api/iam-audit/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const currentSource = guide?.source_types?.find(s => s.id === sourceType)

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = '' // 같은 파일을 다시 선택해도 onChange가 발생하도록 초기화
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      alert(`파일이 너무 큽니다 (${(file.size / 1024 / 1024).toFixed(1)}MB).`)
      return
    }
    setUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/extract-text', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      setContent(res.data.text)
      setUploadedFileName(file.name)
      analyze(res.data.text)
    } catch (err) {
      alert('파일을 읽지 못했습니다: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setUploading(false)
    }
  }

  const clearUploadedFile = () => {
    setUploadedFileName('')
    setContent('')
  }

  const analyze = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/iam-audit/analyze', { source_type: sourceType, content: body, context })
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
      const res = await axios.get(`/api/iam-audit/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `iam-audit-${id}.md`
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
            <KeyRound className="text-violet-400" size={26} /> 클라우드 IAM 정책 감사기
          </h1>
          <p className="text-slate-400 text-sm mt-1">기존 IAM 정책·역할·사용자 정보를 붙여넣으면 AI가 과도한 권한·MFA 미적용·오래된 자격증명·권한 상승 경로를 찾아 수정안을 제시합니다.</p>
        </div>

        <GuidePanel title="클라우드 IAM 정책 감사기 사용 가이드" steps={AUDIT_STEPS} tips={AUDIT_TIPS} />

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">감사 대상 플랫폼</p>
              <div className="grid grid-cols-3 gap-2">
                {['aws_iam', 'azure_rbac', 'gcp_iam'].map(id => {
                  const Icon = SOURCE_ICONS[id]
                  const label = guide?.source_types?.find(s => s.id === id)?.label ?? id
                  return (
                    <button
                      key={id}
                      onClick={() => setSourceType(id)}
                      className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                        sourceType === id ? 'bg-violet-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
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
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-violet-300">정보 가져오는 방법: {currentSource.label}</p>
                  <CopyButton text={currentSource.commands.join('\n')} />
                </div>
                <p className="text-[11px] text-slate-500">{currentSource.how_to_export}</p>
                <pre className="bg-slate-900 border border-slate-700 rounded-lg p-2 overflow-x-auto">
                  <code className="text-[11px] text-violet-300 font-mono whitespace-pre">
                    {currentSource.commands.join('\n')}
                  </code>
                </pre>
                {SAMPLE_FILES[sourceType] && (
                  <a
                    href={SAMPLE_FILES[sourceType]}
                    download
                    className="inline-flex items-center gap-1.5 text-[11px] text-violet-400 hover:text-violet-300 underline underline-offset-2"
                  >
                    <Download size={11} /> 예시 파일 다운로드 (바로 업로드해서 테스트 가능)
                  </a>
                )}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-slate-400">IAM 정책/사용자 정보 (붙여넣기 또는 파일 업로드)</p>
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
                    disabled={uploading}
                    className="flex items-center gap-1 text-[11px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg px-2.5 py-1 disabled:opacity-60"
                  >
                    <Upload size={11} /> {uploading ? '읽는 중...' : '파일 업로드'}
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept={UPLOAD_ACCEPT}
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </div>
              </div>
              <textarea
                value={content}
                onChange={e => { setContent(e.target.value); setUploadedFileName('') }}
                placeholder={PLACEHOLDERS[sourceType]}
                rows={10}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-violet-500 placeholder-slate-600"
              />
              <p className="text-[10px] text-slate-600 mt-1">Word/PDF/Excel 파일도 업로드하면 서버가 텍스트를 추출해 채워줍니다(업로드 즉시 자동 감사). 실제 자격증명 값이 포함된 파일이라면 업로드 전 민감한 값은 마스킹하는 것을 권장합니다.</p>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">환경 컨텍스트 (선택)</p>
              <input
                value={context}
                onChange={e => setContext(e.target.value)}
                placeholder="예: 결제 데이터를 다루는 프로덕션 계정, PCI-DSS 적용 대상"
                className="w-full bg-slate-800 border border-slate-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-violet-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={() => analyze()}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-violet-600 hover:bg-violet-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
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
                <KeyRound size={32} className="text-slate-600" />
                <p className="text-sm">감사 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 IAM 정책을 감사 중...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <ModeBanner result={result} />
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-400">종합 위험도</span>
                      <SeverityBadge severity={result.overall_risk} />
                    </div>
                    <button
                      onClick={() => downloadReport(result.id)}
                      className="shrink-0 flex items-center gap-1.5 text-xs bg-violet-600/20 text-violet-300 border border-violet-600/40 rounded-lg px-3 py-1.5 hover:bg-violet-600/30"
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
                        <span className="text-[10px] font-bold bg-violet-500/15 text-violet-300 border border-violet-500/30 rounded-full px-2 py-0.5">
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
                    네트워크/방화벽 규칙도 함께 점검하려면 <a href="/firewall-audit" className="text-teal-300 underline hover:text-teal-200">방화벽 정책 감사기</a>를 이용해보세요.
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
