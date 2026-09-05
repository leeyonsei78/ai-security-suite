import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Landmark, Building2, Cloud, Download, Trash2, AlertTriangle, BadgeCheck, ExternalLink, ListChecks,
  Server, WifiOff, FlaskConical, ChevronDown, ChevronUp, MapPin, Terminal, Info,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'
import FileUploadButton from '../components/FileUploadButton'
import CopyButton from '../components/CopyButton'

const MODE_BADGE = {
  cloud:   { icon: Cloud,        label: 'Claude Cloud로 분석됨', color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  local:   { icon: Server,       label: '로컬 LLM으로 분석됨',    color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/30' },
  offline: { icon: WifiOff,      label: '오프라인 규칙 기반으로 분석됨(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  mock:    { icon: FlaskConical, label: 'Mock 데모 데이터 (학습용, 실제 분석 아님)', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
}

function DomainCollectionCard({ item }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden bg-slate-900/60">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800/60"
      >
        <span className="text-xs font-medium text-amber-300 flex-1">{item.domain}</span>
        {open ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-slate-800 pt-2">
          <p className="text-[11px] text-slate-300 flex items-start gap-1.5">
            <MapPin size={12} className="text-amber-400 shrink-0 mt-0.5" />
            <span><span className="text-slate-500">어디서:</span> {item.where}</span>
          </p>
          {item.what_to_check && (
            <p className="text-[11px] text-slate-400 flex items-start gap-1.5">
              <Info size={12} className="text-slate-500 shrink-0 mt-0.5" />
              <span><span className="text-slate-500">뭘 확인:</span> {item.what_to_check}</span>
            </p>
          )}
          {item.how && (
            <p className="text-[11px] text-slate-400 flex items-start gap-1.5">
              <Info size={12} className="text-slate-500 shrink-0 mt-0.5" />
              <span><span className="text-slate-500">어떻게:</span> {item.how}</span>
            </p>
          )}
          {item.commands?.length > 0 && (
            <div className="flex items-start gap-1.5">
              <Terminal size={12} className="text-slate-500 shrink-0 mt-1" />
              <pre className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2 overflow-x-auto">
                <code className="text-[10.5px] text-amber-300 font-mono whitespace-pre">{item.commands.join('\n')}</code>
              </pre>
              <CopyButton text={item.commands.join('\n')} />
            </div>
          )}
          {item.cross_link && (
            <p className="text-[10.5px] text-slate-500 italic">{item.cross_link}</p>
          )}
        </div>
      )}
    </div>
  )
}

function DataCollectionGuide({ collection, usageNote }) {
  const [expanded, setExpanded] = useState(false)
  if (!collection?.length) return null
  return (
    <div className="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-2">
      <button onClick={() => setExpanded(e => !e)} className="w-full flex items-center gap-2 text-left">
        <MapPin size={13} className="text-amber-400" />
        <span className="text-xs font-semibold text-amber-300 flex-1">분야별 정보 수집 가이드 — 어디서 뭘 가져오는지</span>
        {expanded ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
      </button>
      {expanded && (
        <div className="space-y-2 pt-1">
          {usageNote && (
            <p className="text-[11px] text-amber-200 bg-amber-950/40 border border-amber-500/30 rounded-lg px-2.5 py-2 flex items-start gap-1.5">
              <Info size={12} className="shrink-0 mt-0.5" />
              <span>{usageNote}</span>
            </p>
          )}
          <div className="space-y-1.5">
            {collection.map(item => <DomainCollectionCard key={item.domain} item={item} />)}
          </div>
        </div>
      )}
    </div>
  )
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

const STEPS = [
  '평가 유형을 선택합니다 — CSP(클라우드 제공자) 자체를 평가할지, 우리 회사가 구성한 클라우드 환경을 점검할지.',
  '해당 유형의 대상 분야 목록을 참고해, 관련 설명(정책·계약서 조항·자가진단 응답) 또는 실제 설정(IAM·네트워크·암호화·로깅 등)을 붙여넣습니다.',
  '[AI로 평가 실행] 버튼을 클릭합니다.',
  '분야별로 분류된 발견 사항과 권장 조치를 확인합니다.',
  '네트워크/IAM 설정 자체를 더 깊이 보려면 방화벽 정책 감사기·IAM 정책 감사기로 이어서 점검하세요.',
]
const TIPS = [
  '이 도구는 금융보안원이 공개한 CSP 안전성평가·클라우드 보안관리 참고서의 분야 구조를 참고한 보조 점검 도구입니다 — 공식 평가·인증을 대체하지 않습니다.',
  '실제 최신 세부 기준과 공식 절차는 금융보안원 홈페이지·레그테크 포털·CSP 안전성평가 통합지원시스템에서 반드시 재확인하세요.',
  'App 16(방화벽 정책 감사기)·App 18(IAM 정책 감사기)이 일반적인 네트워크/권한 감사라면, 이 도구는 "금융권 클라우드 규제"라는 특화된 관점으로 점검합니다.',
]

const TYPE_ICONS = {
  csp_assessment: Building2,
  cloud_env_management: Cloud,
}

export default function FsiCspAudit() {
  const [assessmentType, setAssessmentType] = useState('cloud_env_management')
  const [content, setContent] = useState('')
  const [context, setContext] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)

  useEffect(() => {
    axios.get('/api/fsi-csp-audit/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const meta = guide?.assessment_types?.[assessmentType]

  const analyze = async (contentOverride) => {
    const body = contentOverride ?? content
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/fsi-csp-audit/analyze', { assessment_type: assessmentType, content: body, context })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('평가 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/fsi-csp-audit/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `fsi-csp-audit-${id}.md`
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
            <Landmark className="text-amber-400" size={26} /> 금융보안원 클라우드 CSP 평가
          </h1>
          <p className="text-slate-400 text-sm mt-1">금융보안원의 CSP 안전성평가·클라우드 보안관리 참고서 분야 구조를 기준으로, CSP의 보안 체계 또는 우리 회사가 구성한 클라우드 환경을 AI가 점검합니다.</p>
        </div>

        <GuidePanel title="금융보안원 클라우드 CSP 평가 사용 가이드" steps={STEPS} tips={TIPS} />

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">평가 유형</p>
              <div className="grid grid-cols-1 gap-2">
                {['cloud_env_management', 'csp_assessment'].map(id => {
                  const Icon = TYPE_ICONS[id]
                  const label = guide?.assessment_types?.[id]?.label ?? id
                  return (
                    <button
                      key={id}
                      onClick={() => setAssessmentType(id)}
                      className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-xs font-medium text-left transition-colors ${
                        assessmentType === id ? 'bg-amber-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                      }`}
                    >
                      <Icon size={16} className="shrink-0" />{label}
                    </button>
                  )
                })}
              </div>
            </div>

            {meta && (
              <div className="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-2.5">
                <p className="text-xs text-slate-400">{meta.description}</p>
                <p className="text-[11px] text-amber-300">대상: {meta.who_for}</p>
                <div>
                  <p className="text-[11px] font-semibold text-slate-400 mb-1.5">대상 분야 ({meta.domains.length}개)</p>
                  <div className="flex flex-wrap gap-1.5">
                    {meta.domains.map(d => (
                      <span key={d.name} className="text-[10px] bg-slate-800 border border-slate-700 rounded-full px-2 py-1 text-slate-300">
                        {d.name} <span className="text-slate-500">({d.item_count})</span>
                      </span>
                    ))}
                  </div>
                </div>
                {meta.process_stages?.length > 0 && (
                  <div>
                    <p className="text-[11px] font-semibold text-slate-400 mb-1.5 flex items-center gap-1"><ListChecks size={11} /> 평가 절차</p>
                    <ul className="space-y-1">
                      {meta.process_stages.map((s, i) => (
                        <li key={i} className="text-[10.5px] text-slate-500">{s}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            <DataCollectionGuide
              collection={guide?.data_collection?.[assessmentType]}
              usageNote={assessmentType === 'cloud_env_management' ? guide?.command_usage_note : null}
            />

            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-slate-400">점검 대상 내용 (붙여넣기)</p>
                <FileUploadButton onExtracted={(text) => { setContent(text); analyze(text) }} />
              </div>
              <textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                placeholder={meta?.input_hint ?? '점검할 내용을 입력하세요'}
                rows={10}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-amber-500 placeholder-slate-600"
              />
              <p className="text-[10px] text-slate-600 mt-1">{meta?.input_hint}</p>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">환경 컨텍스트 (선택)</p>
              <input
                value={context}
                onChange={e => setContext(e.target.value)}
                placeholder="예: 카드사 결제 데이터를 처리하는 운영 환경"
                className="w-full bg-slate-800 border border-slate-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-amber-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={() => analyze()}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-amber-600 hover:bg-amber-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '평가 중...' : 'AI로 평가 실행'}
            </button>

            {guide?.disclaimer && (
              <p className="text-[11px] text-slate-500 italic">{guide.disclaimer}</p>
            )}

            {guide?.reference_links?.length > 0 && (
              <div className="flex flex-wrap gap-3">
                {guide.reference_links.map(l => (
                  <a key={l.url} href={l.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 underline underline-offset-2">
                    {l.label} <ExternalLink size={10} />
                  </a>
                ))}
              </div>
            )}
          </div>

          {/* Result Panel */}
          <div className="md:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <Landmark size={32} className="text-slate-600" />
                <p className="text-sm">평가 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 평가 중...</p>
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
                      className="shrink-0 flex items-center gap-1.5 text-xs bg-amber-600/20 text-amber-300 border border-amber-600/40 rounded-lg px-3 py-1.5 hover:bg-amber-600/30"
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
                        <span className="text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30 rounded-full px-2 py-0.5">
                          {f.domain}
                        </span>
                        <span className="text-[10px] font-bold bg-slate-700 text-slate-300 rounded-full px-2 py-0.5">
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
                      <BadgeCheck size={13} /> 관련 규정/기준 참고
                    </p>
                    <ul className="space-y-1">
                      {result.compliance_notes.map((c, i) => (
                        <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                          <span className="text-blue-400 mt-0.5 shrink-0">•</span>
                          <span><b className="text-slate-200">{c.framework}:</b> {c.note}</span>
                        </li>
                      ))}
                    </ul>
                    <p className="text-[10px] text-slate-500 mt-2">참고용이며, 정확한 기준 충족 여부는 전문가 검토 및 금융보안원 공식 자료 확인이 필요합니다.</p>
                  </div>
                )}

                <div className="bg-amber-950/20 border border-amber-500/20 rounded-xl p-4 flex items-center gap-2">
                  <ListChecks size={14} className="text-amber-400 shrink-0" />
                  <p className="text-xs text-slate-300">
                    네트워크/IAM 설정 자체를 더 깊이 보려면 <a href="/firewall-audit" className="text-amber-300 underline hover:text-amber-200">방화벽 정책 감사기</a>· <a href="/iam-audit" className="text-amber-300 underline hover:text-amber-200">IAM 정책 감사기</a>로 이어서 점검하세요.
                  </p>
                </div>
              </div>
            )}

            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 평가 ({history.length}건)</p>
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
