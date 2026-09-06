import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  FileSearch, Database, HardDrive, Download, ChevronDown, ChevronUp,
  Eye, EyeOff, KeyRound, CheckCircle2, XCircle, Upload, FileText, X,
  AlertTriangle, ListOrdered, Trash2, Cloud, Server, WifiOff, FlaskConical,
  Clock, User, Play, Loader2, ShieldAlert, Fingerprint, BookOpen, Network,
  Info, Terminal, Wifi,
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
        {result.fallback_reason && <p className="text-xs text-slate-400 mt-1">{result.fallback_reason}</p>}
        {result.engine_note && <p className="text-xs text-slate-400 mt-1">{result.engine_note}</p>}
      </div>
    </div>
  )
}

async function downloadBlob(url, filename) {
  const res = await axios.get(url, { responseType: 'blob' })
  const blobUrl = URL.createObjectURL(new Blob([res.data]))
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = filename
  a.click()
  URL.revokeObjectURL(blobUrl)
}

const PAGE_STEPS = [
  '세 가지 탭 중 필요한 것을 선택합니다 — 실습으로 스킬을 익히려면 [실습 랩], 실제 조사 중 수집한 자료를 분석하려면 [아티팩트 감사기], 이 PC에서 실제 증거를 수집하려면 [증거 수집 도구].',
  '[실습 랩]: 챌린지 파일을 다운로드해 실제 도구(Python/Wireshark/압축프로그램)로 분석하고, 찾은 flag를 제출해 확인합니다.',
  '[아티팩트 감사기]: 이벤트 로그·레지스트리 등 텍스트를 붙여넣으면 AI(또는 오프라인 규칙 엔진)가 타임라인과 침해 흔적을 정리합니다.',
  '[증거 수집 도구]: 이 PC에서 실제 PowerShell로 조사에 쓸 아티팩트를 수집하고, SHA-256 해시가 포함된 chain of custody 기록을 남깁니다.',
]
const PAGE_TIPS = [
  '세 탭 모두 서로 독립적입니다 — 실습 랩의 결과는 서버 재시작 시 초기화되고, 아티팩트 감사기/증거 수집 기록은 SQLite에 영속 저장됩니다.',
  '이 도구는 조사를 돕는 참고 자료를 만듭니다 — 법적 절차에 쓰이는 공식 포렌식 보고서를 대체하지 않으며, 자격을 갖춘 담당자의 검토가 필요합니다.',
]

const TABS = [
  { id: 'lab', label: '실습 랩', icon: FileSearch },
  { id: 'audit', label: '아티팩트 감사기', icon: Database },
  { id: 'collection', label: '증거 수집 도구', icon: HardDrive },
]

/* ============================== 실습 랩 ============================== */

function LabChallengeCard({ challenge }) {
  const [hintCount, setHintCount] = useState(0)
  const [solutionOpen, setSolutionOpen] = useState(false)
  const [flagInput, setFlagInput] = useState('')
  const [flagResult, setFlagResult] = useState(null)
  const [checking, setChecking] = useState(false)
  const [downloading, setDownloading] = useState(false)

  const download = async () => {
    setDownloading(true)
    try {
      await downloadBlob(`/api/forensics/lab/challenges/${challenge.id}/download`, challenge.download_filename)
    } catch {
      alert('다운로드 실패')
    } finally {
      setDownloading(false)
    }
  }

  const checkFlag = async () => {
    if (!flagInput.trim()) return
    setChecking(true)
    setFlagResult(null)
    try {
      const res = await axios.post('/api/forensics/lab/verify', { challenge_id: challenge.id, flag: flagInput.trim() })
      setFlagResult(res.data.correct)
    } catch {
      setFlagResult(false)
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="border border-cyan-500/20 bg-cyan-950/10 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Fingerprint size={18} className="text-cyan-400" />
        <span className="text-xs font-bold text-cyan-400">FORENSICS</span>
        <span className="text-xs bg-black/20 px-1.5 py-0.5 rounded">{challenge.difficulty}</span>
        <span className="text-xs text-slate-400">주요 도구: {challenge.tool_focus}</span>
      </div>

      <p className="text-base font-bold text-slate-100">{challenge.title}</p>
      <p className="text-xs text-slate-300 leading-relaxed">{challenge.situation}</p>
      <p className="text-xs text-slate-400 leading-relaxed"><span className="font-semibold text-slate-300">목표: </span>{challenge.objective}</p>

      <button
        onClick={download}
        disabled={downloading}
        className="flex items-center gap-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 text-white px-3 py-2 rounded-lg"
      >
        <Download size={13} /> {downloading ? '다운로드 중...' : `${challenge.download_filename} 다운로드`}
      </button>

      <div>
        <p className="text-xs font-semibold text-slate-300 mb-1.5">분석 단계</p>
        <ol className="space-y-1">
          {challenge.analysis_steps.map((s, i) => (
            <li key={i} className="flex gap-2 text-xs text-slate-300">
              <span className="shrink-0 w-4 h-4 rounded-full bg-black/30 flex items-center justify-center font-bold text-[9px]">{i + 1}</span>
              <span className="font-mono">{s}</span>
            </li>
          ))}
        </ol>
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-300 mb-1.5">힌트 ({hintCount}/{challenge.hints.length})</p>
        <ul className="space-y-1.5 mb-2">
          {challenge.hints.slice(0, hintCount).map((h, i) => (
            <li key={i} className="text-xs text-slate-300 bg-black/20 rounded-lg p-2">💡 {h}</li>
          ))}
        </ul>
        {hintCount < challenge.hints.length && (
          <button onClick={() => setHintCount(c => c + 1)} className="text-xs text-amber-400 hover:text-amber-300">
            힌트 {hintCount + 1} 보기 →
          </button>
        )}
      </div>

      <div>
        <button onClick={() => setSolutionOpen(o => !o)} className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-slate-100">
          {solutionOpen ? <Eye size={13} /> : <EyeOff size={13} />} 모범 답안 {solutionOpen ? '숨기기' : '보기'}
        </button>
        {solutionOpen && (
          <pre className="mt-1.5 bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">{challenge.solution}</pre>
        )}
      </div>

      <div className="bg-slate-900/60 rounded-lg p-3 space-y-2">
        <p className="text-xs font-semibold text-slate-300 flex items-center gap-1"><KeyRound size={12} /> flag 제출</p>
        <div className="flex gap-2">
          <input
            value={flagInput}
            onChange={e => { setFlagInput(e.target.value); setFlagResult(null) }}
            placeholder="예: FORENSIC{...}"
            className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={checkFlag}
            disabled={checking || !flagInput.trim()}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-xs font-semibold"
          >
            확인
          </button>
        </div>
        {flagResult === true && <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 size={13} /> 정답입니다! 축하합니다.</p>}
        {flagResult === false && <p className="text-xs text-red-400 flex items-center gap-1"><XCircle size={13} /> 아직 아닙니다 — 힌트를 더 확인해보세요.</p>}
      </div>
    </div>
  )
}

function LabTab() {
  const [challenges, setChallenges] = useState([])
  const [labSetup, setLabSetup] = useState(null)
  const [setupOpen, setSetupOpen] = useState(true)

  useEffect(() => {
    axios.get('/api/forensics/lab/challenges').then(res => {
      setChallenges(res.data.challenges)
      setLabSetup(res.data.lab_setup)
    })
  }, [])

  return (
    <div className="space-y-6">
      {labSetup && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
          <button onClick={() => setSetupOpen(o => !o)} className="w-full flex items-center gap-2 px-4 py-3 hover:bg-slate-700/40 text-left">
            <BookOpen size={15} className="text-cyan-400 shrink-0" />
            <span className="text-sm font-semibold text-slate-100">{labSetup.title}</span>
            {setupOpen ? <ChevronUp size={14} className="ml-auto text-slate-500" /> : <ChevronDown size={14} className="ml-auto text-slate-500" />}
          </button>
          {setupOpen && (
            <div className="px-4 pb-4 pt-1 space-y-3 border-t border-slate-700">
              <p className="text-xs text-slate-400">{labSetup.intro}</p>
              {labSetup.tools.map((t, i) => (
                <div key={i} className="bg-slate-900/60 rounded-lg p-3">
                  <p className="text-xs font-semibold text-slate-200">{t.name}</p>
                  <p className="text-xs text-slate-400 mt-1">{t.why}</p>
                  <p className="text-[11px] text-slate-500 mt-1">{t.install}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-5">
        {challenges.map(c => <LabChallengeCard key={c.id} challenge={c} />)}
      </div>
    </div>
  )
}

/* ============================== 아티팩트 감사기 ============================== */

const ARTIFACT_ICONS = {
  event_log: Database, browser_history: FileSearch, persistence_artifacts: KeyRound,
  filesystem_timeline: HardDrive, process_list: ListOrdered, cloud_audit_log: Cloud, network_device_log: Network,
}

const AUDIT_PLACEHOLDERS = {
  event_log: `2026-09-01 02:14:03 Event ID 4625 logon failure account=admin\n2026-09-01 02:23:10 Event ID 4688 New Process: powershell.exe -enc SGVsbG8=\n2026-09-01 05:40:55 Event ID 1102 The audit log was cleared`,
  browser_history: `2026-09-02 14:02:11  https://intranet.company.local/portal  사내 포털\n2026-09-02 14:55:30  http://file-share-backup-cdn.net/upload  (낯선 도메인)`,
  persistence_artifacts: `[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"WindowsUpdateHelper"="powershell -w hidden -enc SGVsbG8="`,
  filesystem_timeline: `FullName                              CreationTime          LastWriteTime\nC:\\Users\\a\\AppData\\Local\\Temp\\update.exe  2026-08-28 03:10:02  2026-08-28 03:11:03`,
  process_list: `Id    ProcessName   Path\n4821  svchost.exe   C:\\Users\\Public\\svchost.exe`,
  cloud_audit_log: `{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"additionalEventData":{"MFAUsed":"No"},"eventTime":"2026-09-03T04:11:02Z"}\n{"eventName":"PutUserPolicy","userIdentity":{"userName":"svc-backup"},"eventTime":"2026-09-03T04:13:47Z"}`,
  network_device_log: `%SYS-5-CONFIG_I: Configured from console by netadmin_temp on vty0\naccess-list OUTBOUND permit ip any host 203.0.113.77`,
}

const SAMPLE_FILES = {
  event_log: '/samples/forensics/event_log-windows.txt',
  browser_history: '/samples/forensics/browser_history-sample.txt',
  persistence_artifacts: '/samples/forensics/persistence_artifacts-windows.txt',
  filesystem_timeline: '/samples/forensics/filesystem_timeline-sample.txt',
  process_list: '/samples/forensics/process_list-sample.txt',
  cloud_audit_log: '/samples/forensics/cloud_audit_log-aws.json',
  network_device_log: '/samples/forensics/network_device_log-cisco.txt',
}

function AuditTab() {
  const [artifactType, setArtifactType] = useState('event_log')
  const [variantIndex, setVariantIndex] = useState(0)
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
    axios.get('/api/forensics/audit/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  useEffect(() => { setVariantIndex(0) }, [artifactType])

  const currentType = guide?.artifact_types?.find(t => t.id === artifactType)
  const currentVariant = currentType?.variants?.[variantIndex]

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
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

  const analyze = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/forensics/audit/analyze', { artifact_type: artifactType, content: body, context })
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
      await downloadBlob(`/api/forensics/audit/report/${id}`, `forensics-audit-${id}.md`)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="grid md:grid-cols-5 gap-6">
      <div className="md:col-span-2 space-y-4">
        <div>
          <p className="text-xs font-semibold text-slate-400 mb-2">아티팩트 유형</p>
          <div className="grid grid-cols-1 gap-2">
            {guide?.artifact_types?.map(t => {
              const Icon = ARTIFACT_ICONS[t.id] ?? Database
              return (
                <button
                  key={t.id}
                  onClick={() => setArtifactType(t.id)}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                    artifactType === t.id ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Icon size={14} className="shrink-0" />{t.label}
                </button>
              )
            })}
          </div>
        </div>

        {guide?.command_usage_note && (
          <div className="bg-blue-950/30 border border-blue-500/20 rounded-xl p-3 flex gap-2">
            <Info size={14} className="text-blue-400 shrink-0 mt-0.5" />
            <p className="text-[11px] text-slate-300">{guide.command_usage_note}</p>
          </div>
        )}

        {currentType && (
          <div className="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-3">
            <div>
              <p className="text-xs font-medium text-cyan-300 mb-1">왜 수집하나요?</p>
              <p className="text-[11px] text-slate-400 leading-relaxed">{currentType.why}</p>
            </div>

            {currentType.variants?.length > 1 && (
              <div className="flex flex-wrap gap-1.5">
                {currentType.variants.map((v, i) => (
                  <button
                    key={v.platform}
                    onClick={() => setVariantIndex(i)}
                    className={`text-[11px] font-medium px-2.5 py-1 rounded-full transition-colors ${
                      i === variantIndex ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700'
                    }`}
                  >
                    {v.platform_label}
                  </button>
                ))}
              </div>
            )}

            {currentVariant && (
              <div className="space-y-2">
                <p className="text-[11px] text-slate-500"><span className="text-slate-400 font-medium">어디서 실행하나요: </span>{currentVariant.where}</p>
                <div className="space-y-1.5">
                  {currentVariant.commands.map((cmd, i) => (
                    <div key={i} className="flex items-start gap-1.5">
                      <pre className="flex-1 bg-slate-900 border border-slate-700 rounded-lg p-2 overflow-x-auto">
                        <code className="text-[11px] text-cyan-300 font-mono whitespace-pre">{cmd}</code>
                      </pre>
                      <CopyButton text={cmd} className="mt-0.5" />
                    </div>
                  ))}
                </div>
                {currentVariant.note && (
                  <p className="text-[11px] text-amber-300/90 bg-amber-950/20 border border-amber-500/20 rounded-lg p-2">💡 {currentVariant.note}</p>
                )}
              </div>
            )}

            {SAMPLE_FILES[artifactType] && (
              <a
                href={SAMPLE_FILES[artifactType]}
                download
                className="inline-flex items-center gap-1.5 text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
              >
                <Download size={11} /> 예시 파일 다운로드 (바로 업로드해서 테스트 가능)
              </a>
            )}
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold text-slate-400">아티팩트 내용 (붙여넣기 또는 업로드)</p>
            <div className="flex items-center gap-2">
              {uploadedFileName && (
                <span className="flex items-center gap-1 text-[11px] text-slate-500">
                  <FileText size={11} />{uploadedFileName}
                  <button onClick={() => { setUploadedFileName(''); setContent('') }} className="text-slate-500 hover:text-red-400"><X size={11} /></button>
                </span>
              )}
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="flex items-center gap-1 text-[11px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg px-2.5 py-1 disabled:opacity-60"
              >
                <Upload size={11} /> {uploading ? '읽는 중...' : '파일 업로드'}
              </button>
              <input ref={fileInputRef} type="file" accept={UPLOAD_ACCEPT} onChange={handleFileUpload} className="hidden" />
            </div>
          </div>
          <textarea
            value={content}
            onChange={e => { setContent(e.target.value); setUploadedFileName('') }}
            placeholder={AUDIT_PLACEHOLDERS[artifactType]}
            rows={10}
            className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-cyan-500 placeholder-slate-600"
          />
          <p className="text-[10px] text-slate-600 mt-1">위 명령어를 실행한 결과를 여기에 붙여넣고 [AI로 사건 재구성]을 누르거나, 결과를 텍스트 파일로 저장해 업로드하세요 — 업로드하면 자동으로 분석됩니다.</p>
        </div>

        <div>
          <p className="text-xs font-semibold text-slate-400 mb-2">조사 컨텍스트 (선택)</p>
          <input
            value={context}
            onChange={e => setContext(e.target.value)}
            placeholder="예: IDS 알림을 받은 뒤 수집한 대상 PC의 이벤트 로그"
            className="w-full bg-slate-800 border border-slate-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 placeholder-slate-600"
          />
        </div>

        <button
          onClick={() => analyze()}
          disabled={loading || !content.trim()}
          className="w-full py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
        >
          {loading ? '분석 중...' : 'AI로 사건 재구성'}
        </button>

        {guide?.disclaimer && <p className="text-[11px] text-slate-500 italic">{guide.disclaimer}</p>}
      </div>

      <div className="md:col-span-3 space-y-4">
        {!result && !loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
            <Database size={32} className="text-slate-600" />
            <p className="text-sm">분석 결과가 여기에 표시됩니다</p>
          </div>
        )}
        {loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm text-slate-400">사건을 재구성하는 중...</p>
          </div>
        )}

        {result && (
          <div className="space-y-4">
            <ModeBanner result={result} />
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-400">종합 심각도</span>
                  <SeverityBadge severity={result.overall_severity} />
                </div>
                <button
                  onClick={() => downloadReport(result.id)}
                  className="shrink-0 flex items-center gap-1.5 text-xs bg-cyan-600/20 text-cyan-300 border border-cyan-600/40 rounded-lg px-3 py-1.5 hover:bg-cyan-600/30"
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

            {result.timeline?.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <p className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-1.5"><Clock size={13} /> 재구성된 타임라인</p>
                <div className="space-y-2">
                  {result.timeline.map((t, i) => (
                    <div key={i} className="flex gap-2 text-xs border-l-2 border-cyan-600/40 pl-3 py-0.5">
                      <span className="text-cyan-400 font-mono shrink-0">{t.timestamp}</span>
                      <div>
                        <p className="text-slate-200">{t.event}</p>
                        <p className="text-slate-500 italic">{t.significance}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-3">
              {result.findings?.map((f, i) => (
                <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-[10px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 rounded-full px-2 py-0.5">
                      {f.issue_type_label}
                    </span>
                    {f.mitre_technique && (
                      <span className="text-[10px] font-mono bg-slate-700 text-slate-300 rounded-full px-2 py-0.5">{f.mitre_technique}</span>
                    )}
                  </div>
                  <p className="text-xs font-mono text-slate-400 bg-slate-950/60 rounded-lg px-2 py-1.5 mb-2 overflow-x-auto whitespace-pre">
                    {f.artifact_reference}
                  </p>
                  <p className="text-sm text-slate-300">{f.description}</p>
                  <div className="mt-2 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                    <AlertTriangle size={13} className="text-amber-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-slate-400"><span className="text-amber-300 font-medium">다음 조치: </span>{f.recommendation}</p>
                  </div>
                </div>
              ))}
            </div>

            {result.iocs?.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <p className="text-xs font-semibold text-cyan-400 mb-2 flex items-center gap-1.5"><ListOrdered size={13} /> 추출된 IOC</p>
                <div className="flex flex-wrap gap-1.5">
                  {result.iocs.map((ioc, i) => (
                    <span key={i} className="text-[11px] font-mono bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-300">{ioc}</span>
                  ))}
                </div>
                <a href="/ioc" className="inline-block mt-2 text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2">IoC 분석기에서 평판 확인하기 →</a>
              </div>
            )}
          </div>
        )}

        {history.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
            <div className="flex justify-between items-center mb-3">
              <p className="text-xs font-semibold text-slate-400">최근 분석 ({history.length}건)</p>
              <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400"><Trash2 size={13} /></button>
            </div>
            <div className="space-y-2">
              {history.map((h, i) => (
                <button key={i} onClick={() => setResult(h)} className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors">
                  <SeverityBadge severity={h.overall_severity} />
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

/* ============================== 증거 수집 도구 ============================== */

function ResultBadge({ res }) {
  if (!res) return null
  return (
    <div className={`mt-1 rounded-lg p-2.5 text-xs ${res.ok ? 'bg-green-950/30 border border-green-500/20' : 'bg-red-950/30 border border-red-500/20'}`}>
      {res.ok ? (
        <p className="text-green-300 flex items-center gap-1"><CheckCircle2 size={12} /> {res.count}건 수집됨</p>
      ) : (
        <p className="text-red-300 flex items-center gap-1"><XCircle size={12} /> {res.error}</p>
      )}
      <p className="text-slate-500 mt-1 flex items-center gap-1"><Clock size={11} />{res.collected_at}</p>
      <p className="text-slate-500 font-mono truncate mt-0.5">sha256: {res.sha256}</p>
    </div>
  )
}

function LocalCollectionPanel({ collectedBy, onCollected }) {
  const [items, setItems] = useState([])
  const [results, setResults] = useState({})
  const [collecting, setCollecting] = useState({})

  useEffect(() => {
    axios.get('/api/forensics/collection/items').then(r => setItems(r.data.items))
  }, [])

  const collect = async (itemId) => {
    setCollecting(c => ({ ...c, [itemId]: true }))
    try {
      const res = await axios.post('/api/forensics/collection/collect', { item_id: itemId, collected_by: collectedBy })
      setResults(r => ({ ...r, [itemId]: res.data }))
      onCollected(res.data)
    } catch (err) {
      alert('수집 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setCollecting(c => ({ ...c, [itemId]: false }))
    }
  }

  return (
    <div className="grid md:grid-cols-2 gap-4">
      {items.map(item => (
        <div key={item.id} className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-semibold text-slate-100">{item.label}</p>
            {item.requires_admin && (
              <span className="text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30 rounded-full px-2 py-0.5 shrink-0">관리자 권한 필요할 수 있음</span>
            )}
          </div>
          <p className="text-xs text-slate-400">{item.description}</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[10px] text-slate-500 bg-slate-950/60 rounded px-2 py-1 overflow-x-auto whitespace-nowrap">{item.command}</code>
            <CopyButton text={item.command} />
          </div>
          <button
            onClick={() => collect(item.id)}
            disabled={collecting[item.id]}
            className="flex items-center gap-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 text-white px-3 py-1.5 rounded-lg"
          >
            {collecting[item.id] ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
            {collecting[item.id] ? '수집 중...' : '지금 수집'}
          </button>
          <ResultBadge res={results[item.id]} />
        </div>
      ))}
    </div>
  )
}

function RemoteSshPanel({ collectedBy, onCollected }) {
  const [platforms, setPlatforms] = useState([])
  const [platform, setPlatform] = useState('')
  const [artifactType, setArtifactType] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState(22)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState(null)
  const [collecting, setCollecting] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    axios.get('/api/forensics/collection/remote-options').then(r => {
      setPlatforms(r.data.platforms)
      if (r.data.platforms.length > 0) {
        setPlatform(r.data.platforms[0].platform)
        setArtifactType(r.data.platforms[0].artifact_types[0]?.artifact_type ?? '')
      }
    })
  }, [])

  const currentPlatform = platforms.find(p => p.platform === platform)

  const checkConnection = async () => {
    setChecking(true)
    setCheckResult(null)
    try {
      const res = await axios.post('/api/forensics/collection/check-ssh', { host, port: Number(port), username, password })
      setCheckResult(res.data)
    } catch (err) {
      setCheckResult({ ok: false, error: err.response?.data?.detail ?? err.message })
    } finally {
      setChecking(false)
    }
  }

  const collect = async () => {
    setCollecting(true)
    setResult(null)
    try {
      const res = await axios.post('/api/forensics/collection/collect-remote', {
        platform, artifact_type: artifactType, host, port: Number(port), username, password, collected_by: collectedBy,
      })
      setResult(res.data)
      onCollected(res.data)
    } catch (err) {
      alert('수집 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setCollecting(false)
    }
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
      <p className="text-[11px] text-slate-400">
        paramiko로 SSH 접속해 명령을 실행합니다. 자격증명은 저장되지 않고 이 요청에만 사용됩니다.
        {currentPlatform?.is_network_device && ' 네트워크 장비는 SSH 비인터랙티브 실행 특성상 대표 명령 1개만 자동 실행합니다 — 실패하면 아티팩트 감사기 가이드의 수동 명령을 직접 실행하세요.'}
      </p>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-[11px] text-slate-500 mb-1">플랫폼</p>
          <select
            value={platform}
            onChange={e => { setPlatform(e.target.value); const p = platforms.find(pp => pp.platform === e.target.value); setArtifactType(p?.artifact_types[0]?.artifact_type ?? '') }}
            className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs"
          >
            {platforms.map(p => <option key={p.platform} value={p.platform}>{p.platform_label}</option>)}
          </select>
        </div>
        <div>
          <p className="text-[11px] text-slate-500 mb-1">수집 항목</p>
          <select
            value={artifactType}
            onChange={e => setArtifactType(e.target.value)}
            className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs"
          >
            {currentPlatform?.artifact_types.map(a => <option key={a.artifact_type} value={a.artifact_type}>{a.label}</option>)}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <div className="col-span-2">
          <p className="text-[11px] text-slate-500 mb-1">호스트</p>
          <input value={host} onChange={e => setHost(e.target.value)} placeholder="예: 10.0.1.20" className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs" />
        </div>
        <div>
          <p className="text-[11px] text-slate-500 mb-1">포트</p>
          <input value={port} onChange={e => setPort(e.target.value)} type="number" className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs" />
        </div>
        <div>
          <p className="text-[11px] text-slate-500 mb-1">사용자명</p>
          <input value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs" />
        </div>
      </div>
      <div>
        <p className="text-[11px] text-slate-500 mb-1">비밀번호</p>
        <input value={password} onChange={e => setPassword(e.target.value)} type="password" className="w-full max-w-xs bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs" />
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={checkConnection}
          disabled={checking || !host || !username}
          className="flex items-center gap-1.5 text-xs font-medium bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-slate-200 px-3 py-1.5 rounded-lg"
        >
          {checking ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />} 연결 테스트
        </button>
        <button
          onClick={collect}
          disabled={collecting || !host || !username || !artifactType}
          className="flex items-center gap-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg"
        >
          {collecting ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} 지금 수집
        </button>
      </div>

      {checkResult && (
        <p className={`text-xs flex items-center gap-1 ${checkResult.ok ? 'text-green-300' : 'text-red-300'}`}>
          {checkResult.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />} {checkResult.ok ? checkResult.message : checkResult.error}
        </p>
      )}
      <ResultBadge res={result} />
    </div>
  )
}

function CloudCliPanel({ collectedBy, onCollected }) {
  const [providers, setProviders] = useState([])
  const [provider, setProvider] = useState('')
  const [checking, setChecking] = useState(false)
  const [checkResult, setCheckResult] = useState(null)
  const [collecting, setCollecting] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    axios.get('/api/forensics/collection/cloud-options').then(r => {
      setProviders(r.data.providers)
      if (r.data.providers.length > 0) setProvider(r.data.providers[0].provider)
    })
  }, [])

  const checkConnection = async () => {
    setChecking(true)
    setCheckResult(null)
    try {
      const res = await axios.post('/api/forensics/collection/check-cloud', { provider })
      setCheckResult(res.data)
    } catch (err) {
      setCheckResult({ ok: false, error: err.response?.data?.detail ?? err.message })
    } finally {
      setChecking(false)
    }
  }

  const collect = async () => {
    setCollecting(true)
    setResult(null)
    try {
      const res = await axios.post('/api/forensics/collection/collect-cloud', { provider, collected_by: collectedBy })
      setResult(res.data)
      onCollected(res.data)
    } catch (err) {
      alert('수집 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setCollecting(false)
    }
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
      <p className="text-[11px] text-slate-400">
        원격 접속이 아니라 <b className="text-slate-300">이 백엔드 호스트에 이미 설치·인증된 CLI</b>(aws/az/gcloud)를 그대로 실행합니다 —
        해당 CLI가 이 호스트에 없거나 인증돼 있지 않으면 실패합니다.
      </p>
      <div className="max-w-xs">
        <p className="text-[11px] text-slate-500 mb-1">클라우드 제공자</p>
        <select value={provider} onChange={e => setProvider(e.target.value)} className="w-full bg-slate-900 border border-slate-600 rounded-lg px-2.5 py-1.5 text-xs">
          {providers.map(p => <option key={p.provider} value={p.provider}>{p.platform_label}</option>)}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={checkConnection}
          disabled={checking || !provider}
          className="flex items-center gap-1.5 text-xs font-medium bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-slate-200 px-3 py-1.5 rounded-lg"
        >
          {checking ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />} 연결 테스트
        </button>
        <button
          onClick={collect}
          disabled={collecting || !provider}
          className="flex items-center gap-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg"
        >
          {collecting ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} 지금 수집
        </button>
      </div>
      {checkResult && (
        <p className={`text-xs flex items-center gap-1 ${checkResult.ok ? 'text-green-300' : 'text-red-300'}`}>
          {checkResult.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />} {checkResult.ok ? checkResult.message : checkResult.error}
        </p>
      )}
      <ResultBadge res={result} />
    </div>
  )
}

const COLLECTION_SOURCES = [
  { id: 'local', label: '이 PC (Windows)', icon: HardDrive },
  { id: 'ssh', label: '원격 SSH (Linux/macOS/네트워크 장비)', icon: Terminal },
  { id: 'cloud', label: '클라우드 CLI (AWS/Azure/GCP)', icon: Cloud },
]

function CollectionTab() {
  const [source, setSource] = useState('local')
  const [collectedBy, setCollectedBy] = useState('')
  const [records, setRecords] = useState([])

  useEffect(() => {
    axios.get('/api/forensics/collection/history').then(r => setRecords(r.data.history))
  }, [])

  const onCollected = (record) => setRecords(recs => [record, ...recs])

  const downloadCustody = async () => {
    try {
      await downloadBlob('/api/forensics/collection/custody-report', `chain-of-custody-${Date.now()}.md`)
    } catch {
      alert('아직 수집된 증거가 없습니다.')
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-amber-950/20 border border-amber-500/20 rounded-xl p-4 flex gap-2">
        <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-slate-300">
          이 탭은 AI를 쓰지 않고 실제로 명령을 실행해 증거를 수집합니다. 수집한 데이터는 SHA-256 해시와 함께 기록되어,
          이후 데이터가 변경되지 않았음을 확인할 수 있습니다. 자격증명은 어디에도 저장되지 않고 매 요청에만 사용됩니다.
        </p>
      </div>

      <div className="flex items-center gap-4 flex-wrap">
        <div>
          <p className="text-xs font-semibold text-slate-400 mb-1">수집 대상</p>
          <div className="flex gap-1.5">
            {COLLECTION_SOURCES.map(s => {
              const Icon = s.icon
              return (
                <button
                  key={s.id}
                  onClick={() => setSource(s.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    source === s.id ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  <Icon size={13} />{s.label}
                </button>
              )
            })}
          </div>
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-400 mb-1">수집자 (조사 기록에 남습니다)</p>
          <input
            value={collectedBy}
            onChange={e => setCollectedBy(e.target.value)}
            placeholder="예: 홍길동 (보안팀)"
            className="w-64 bg-slate-800 border border-slate-600 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 placeholder-slate-600"
          />
        </div>
      </div>

      {source === 'local' && <LocalCollectionPanel collectedBy={collectedBy} onCollected={onCollected} />}
      {source === 'ssh' && <RemoteSshPanel collectedBy={collectedBy} onCollected={onCollected} />}
      {source === 'cloud' && <CloudCliPanel collectedBy={collectedBy} onCollected={onCollected} />}

      {records.length > 0 && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
          <div className="flex justify-between items-center mb-3">
            <p className="text-xs font-semibold text-slate-400 flex items-center gap-1.5"><User size={13} /> Chain of Custody 기록 ({records.length}건)</p>
            <button
              onClick={downloadCustody}
              className="flex items-center gap-1.5 text-xs bg-cyan-600/20 text-cyan-300 border border-cyan-600/40 rounded-lg px-3 py-1.5 hover:bg-cyan-600/30"
            >
              <Download size={13} /> 전체 기록 Markdown 다운로드
            </button>
          </div>
          <div className="space-y-1.5 max-h-64 overflow-y-auto">
            {records.map((r, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-slate-400 border-b border-slate-700/50 pb-1.5">
                {r.ok ? <CheckCircle2 size={12} className="text-green-400 shrink-0" /> : <XCircle size={12} className="text-red-400 shrink-0" />}
                <span className="text-slate-300 flex-1 truncate">{r.label}</span>
                <span className="shrink-0">{r.collected_by}</span>
                <span className="shrink-0 text-slate-600">{r.collected_at}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ============================== 메인 페이지 ============================== */

export default function Forensics() {
  const [tab, setTab] = useState('lab')

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="text-cyan-400" size={26} /> 포렌식 실습·분석 센터
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            실제 파일로 연습하는 실습 랩, 조사 아티팩트를 AI로 감사하는 도구, 이 PC의 실제 증거를 수집하는 도구를 한 곳에 모았습니다.
          </p>
        </div>

        <GuidePanel title="포렌식 실습·분석 센터 사용 가이드" steps={PAGE_STEPS} tips={PAGE_TIPS} />

        <div className="flex gap-1 border-b border-slate-700">
          {TABS.map(t => {
            const Icon = t.icon
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                  tab === t.id ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-500 hover:text-slate-300'
                }`}
              >
                <Icon size={15} />{t.label}
              </button>
            )
          })}
        </div>

        {tab === 'lab' && <LabTab />}
        {tab === 'audit' && <AuditTab />}
        {tab === 'collection' && <CollectionTab />}
      </div>
    </div>
  )
}
