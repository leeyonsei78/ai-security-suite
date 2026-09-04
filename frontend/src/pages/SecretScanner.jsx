import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  ScanSearch, KeySquare, Trash2, Download, AlertTriangle, Upload, FileText, X,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'

const SCAN_STEPS = [
  '스캔할 코드/설정 텍스트를 붙여넣거나, 파일을 업로드합니다.',
  '[스캔 실행] 버튼을 클릭합니다 — Claude AI를 거치지 않고 서버 안에서 정규식·엔트로피로만 즉시 검사합니다.',
  '발견된 항목을 심각도 순으로 확인합니다. 값은 앞뒤 일부만 남기고 마스킹되어 표시됩니다.',
  '실제 시크릿으로 확인되면 해당 서비스에서 즉시 값을 폐기/재발급(rotate)하세요.',
  '이미 git 이력에 커밋됐다면 값 교체만으로는 부족합니다 — 이력에서도 제거를 검토하세요.',
]
const SCAN_TIPS = [
  '이 도구는 Claude AI를 쓰지 않습니다 — 붙여넣은 텍스트가 외부로 전송되지 않고, 매치된 값은 즉시 마스킹되어 원본은 어디에도 저장되지 않습니다.',
  '정규식 기반 탐지라 오탐(placeholder를 진짜로 착각)·누락이 있을 수 있습니다 — gitleaks/trufflehog 등 전용 도구와 함께 쓰는 것을 권장합니다.',
  '"고엔트로피 문자열" 항목은 확신도가 낮은 best-effort 탐지입니다. 실제 시크릿인지 직접 확인하세요.',
]

const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 // 2MB

export default function SecretScanner() {
  const [content, setContent] = useState('')
  const [filename, setFilename] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    axios.get('/api/secret-scan/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      alert(`파일이 너무 큽니다 (${(file.size / 1024 / 1024).toFixed(1)}MB). 최대 2MB까지 지원합니다.`)
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      setContent(String(reader.result ?? ''))
      setFilename(file.name)
    }
    reader.onerror = () => alert('파일을 읽는 중 오류가 발생했습니다. 텍스트 형식의 파일인지 확인해주세요.')
    reader.readAsText(file)
  }

  const clearUploadedFile = () => {
    setFilename('')
    setContent('')
  }

  const scan = async () => {
    if (!content.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/secret-scan/scan', { content, filename })
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
      const res = await axios.get(`/api/secret-scan/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `secret-scan-${id}.md`
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
            <ScanSearch className="text-rose-400" size={26} /> 시크릿 스캐너
          </h1>
          <p className="text-slate-400 text-sm mt-1">코드/설정에 하드코딩된 API 키·비밀번호·토큰을 정규식·엔트로피 기반으로 탐지합니다 (Claude AI 미사용, 항상 실시간 동작).</p>
        </div>

        <GuidePanel title="시크릿 스캐너 사용 가이드" steps={SCAN_STEPS} tips={SCAN_TIPS} />

        {guide?.patterns && (
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-3">
            <p className="text-xs font-semibold text-slate-400 mb-2 flex items-center gap-1.5">
              <KeySquare size={13} /> 탐지 가능한 패턴 ({guide.patterns.length}종)
            </p>
            <div className="flex flex-wrap gap-1.5">
              {guide.patterns.map(p => (
                <span key={p.id} className="text-[10px] bg-slate-900 border border-slate-700 rounded-full px-2 py-0.5 text-slate-400">
                  {p.label}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-slate-400">코드/설정 텍스트 (붙여넣기 또는 파일 업로드)</p>
                <div className="flex items-center gap-2">
                  {filename && (
                    <span className="flex items-center gap-1 text-[11px] text-slate-500">
                      <FileText size={11} />{filename}
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
                  <input ref={fileInputRef} type="file" onChange={handleFileUpload} className="hidden" />
                </div>
              </div>
              <textarea
                value={content}
                onChange={e => { setContent(e.target.value); setFilename('') }}
                placeholder={`AWS_ACCESS_KEY_ID=AKIA...\napi_key = "..."\n-----BEGIN RSA PRIVATE KEY-----`}
                rows={14}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-rose-500 placeholder-slate-600"
              />
              <p className="text-[10px] text-slate-600 mt-1">붙여넣은 내용은 외부로 전송되지 않고 이 서버 안에서만 검사됩니다. 매치된 값은 즉시 마스킹되어 원본은 저장되지 않습니다.</p>
            </div>

            <button
              onClick={scan}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-rose-600 hover:bg-rose-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '스캔 중...' : '스캔 실행'}
            </button>

            {guide?.disclaimer && (
              <p className="text-[11px] text-slate-500 italic">{guide.disclaimer}</p>
            )}
          </div>

          {/* Result Panel */}
          <div className="md:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <ScanSearch size={32} className="text-slate-600" />
                <p className="text-sm">스캔 결과가 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-rose-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">스캔 중...</p>
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
                      className="shrink-0 flex items-center gap-1.5 text-xs bg-rose-600/20 text-rose-300 border border-rose-600/40 rounded-lg px-3 py-1.5 hover:bg-rose-600/30"
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
                        <span className="text-[10px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30 rounded-full px-2 py-0.5">
                          {f.pattern_label}
                        </span>
                        <span className="text-[10px] text-slate-500">line {f.line} · 확신도 {f.confidence}</span>
                      </div>
                      <p className="text-xs font-mono text-slate-400 bg-slate-950/60 rounded-lg px-2 py-1.5 mb-2 overflow-x-auto whitespace-pre">
                        {f.context}
                      </p>
                      <div className="mt-2 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                        <AlertTriangle size={13} className="text-amber-400 shrink-0 mt-0.5" />
                        <p className="text-xs text-slate-400">
                          <span className="text-amber-300 font-medium">권장 조치: </span>{f.recommendation}
                        </p>
                      </div>
                    </div>
                  ))}
                  {result.findings?.length === 0 && (
                    <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500">
                      알려진 패턴의 하드코딩된 시크릿을 발견하지 못했습니다.
                    </div>
                  )}
                </div>
              </div>
            )}

            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 스캔 ({history.length}건)</p>
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
                      <span className="text-xs text-slate-300 truncate flex-1">{h.filename || '(파일명 없음)'} — {h.stats?.total ?? 0}건</span>
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
