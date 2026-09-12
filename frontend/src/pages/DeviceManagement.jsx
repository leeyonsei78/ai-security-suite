import { useState, useEffect, useCallback, useRef } from 'react'
import axios from 'axios'
import {
  Server, Plus, Trash2, Pencil, RefreshCw, Zap, Clock, Wifi, WifiOff, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, Router, Cloud, MonitorCog, Terminal, KeyRound, History,
  FileSpreadsheet, Upload, Download, AlertCircle,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'

const STEPS = [
  '점검할 장비를 등록합니다 — 하나씩 등록하거나, 여러 장비를 CSV/Excel 파일 하나로 한 번에 등록할 수 있습니다.',
  '네트워크 장비(방화벽/라우터/스위치)는 SSH 접속 정보를, 클라우드 계정은 CLI 식별자(프로파일/구독/프로젝트)를 입력합니다.',
  '이 장비를 어떤 관점으로 분석할지(방화벽 정책 감사 / IAM 권한 감사 / 보안 로그 분석) 선택합니다.',
  '[연결 테스트]로 실제로 접속 가능한지 먼저 확인한 뒤 등록합니다.',
  '등록하면 지정한 주기마다 백그라운드에서 자동으로 접속해 정보를 수집하고 분석합니다 — 수동으로 다시 실행할 필요가 없습니다.',
  'CRITICAL 문제가 발견되면 기존 알림 시스템(Slack/이메일/n8n)으로 자동 통보되고, 통합 리스크 대시보드에도 집계됩니다.',
  '지금 바로 확인하고 싶다면 [지금 수집]을 눌러 주기를 기다리지 않고 즉시 실행할 수 있습니다.',
]
const TIPS = [
  '이 기능은 실제로 등록한 장비에 SSH/WinRM/클라우드 CLI로 접속합니다 — 접근 권한이 있는 장비만 등록하세요.',
  '접속 비밀번호는 암호화되어 저장되며, 조회 화면·API 응답 어디에도 다시 노출되지 않습니다. 일괄 업로드에 쓴 파일 내용도 등록에만 사용되고 서버에 저장되지 않습니다.',
  '수집·분석에 쓰이는 엔진은 기존 방화벽/IAM 감사기, 대시보드 로그 분석과 완전히 동일합니다 — 이 화면은 그 실행을 "등록한 장비 기준으로 자동 반복"해주는 역할만 합니다.',
  'Windows 서버는 호스트를 비워두면 이 백엔드가 실행 중인 이 PC 자신을 대상으로 합니다(원격 WinRM 설정 없이 바로 테스트 가능).',
  '일괄 업로드는 행 단위로 처리됩니다 — 일부 행에 오류가 있어도 나머지 정상 행은 그대로 등록되고, 오류가 난 행만 이유와 함께 알려줍니다.',
]

const BULK_TEMPLATE_URL = '/samples/devices/device-bulk-template.csv'
const BULK_COLUMNS = [
  { name: 'name', required: true, desc: '장비 이름' },
  { name: 'device_type', required: true, desc: 'network_device / linux_host / windows_host / aws_account / azure_subscription / gcp_project' },
  { name: 'vendor', required: false, desc: 'network_device일 때만: cisco_ios / fortinet / palo_alto / juniper' },
  { name: 'analyzer', required: true, desc: 'firewall_audit / iam_audit / log_analysis (장비 유형별로 선택 가능한 값이 다름)' },
  { name: 'host', required: false, desc: '호스트/IP 또는 클라우드 식별자(프로파일/구독/프로젝트)' },
  { name: 'port', required: false, desc: 'SSH 포트 (기본 22)' },
  { name: 'username', required: false, desc: 'SSH/WinRM 사용자명' },
  { name: 'password', required: false, desc: 'SSH/WinRM 비밀번호 (수정 시 비워두면 기존 값 유지)' },
  { name: 'context', required: false, desc: '환경 컨텍스트 설명' },
  { name: 'interval_minutes', required: false, desc: '수집 주기(분), 기본 60' },
  { name: 'enabled', required: false, desc: 'TRUE/FALSE, 기본 TRUE' },
]

const DEVICE_ICONS = {
  network_device: Router, linux_host: Terminal, windows_host: MonitorCog,
  aws_account: Cloud, azure_subscription: Cloud, gcp_project: Cloud,
}

const EMPTY_FORM = {
  name: '', device_type: 'windows_host', vendor: '', analyzer: '', host: '', port: '',
  username: '', password: '', context: '', interval_minutes: 60, enabled: true,
}

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString() } catch { return iso }
}

function StatusPill({ status }) {
  if (!status) return <span className="text-[11px] text-slate-500">아직 실행 안 됨</span>
  if (status === 'ok') return <span className="flex items-center gap-1 text-[11px] text-emerald-400"><CheckCircle2 size={12} />정상 수집</span>
  return <span className="flex items-center gap-1 text-[11px] text-red-400"><XCircle size={12} />수집 실패</span>
}

function ResultSummary({ result }) {
  if (!result) return null
  const items = result.findings || result.events || []
  if (items.length === 0) {
    return <p className="text-xs text-slate-400">{result.summary}</p>
  }
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-400">{result.summary}</p>
      {items.slice(0, 5).map((it, i) => (
        <div key={i} className="bg-slate-950/60 border border-slate-700 rounded-lg p-2">
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={it.severity} />
            <span className="text-[11px] text-slate-500">{it.issue_type_label || it.category || ''}</span>
          </div>
          <p className="text-xs text-slate-300">{it.description}</p>
          {(it.recommendation || it.remediation) && (
            <p className="text-[11px] text-amber-300 mt-1"><b>권장 조치:</b> {it.recommendation || it.remediation}</p>
          )}
        </div>
      ))}
    </div>
  )
}

function DeviceHistory({ deviceId }) {
  const [history, setHistory] = useState(null)
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => {
    axios.get(`/api/devices/${deviceId}/history`).then(r => setHistory(r.data.history)).catch(() => setHistory([]))
  }, [deviceId])

  if (history === null) return <p className="text-xs text-slate-500 p-3">기록 불러오는 중...</p>
  if (history.length === 0) return <p className="text-xs text-slate-500 p-3">아직 수집 기록이 없습니다.</p>

  return (
    <div className="space-y-2 p-3">
      {history.map(h => (
        <div key={h.id} className="border border-slate-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setExpandedId(x => x === h.id ? null : h.id)}
            className="w-full flex items-center justify-between gap-2 px-3 py-2 bg-slate-900/60 hover:bg-slate-900 text-left"
          >
            <span className="flex items-center gap-2 text-xs text-slate-300">
              <SeverityBadge severity={h.result?.overall_risk || h.result?.threat_level || 'INFO'} />
              {fmtDate(h.triggered_at)}
            </span>
            {expandedId === h.id ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
          </button>
          {expandedId === h.id && (
            <div className="p-3 bg-slate-950/40">
              <ResultSummary result={h.result} />
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function DeviceCard({ device, onEdit, onDelete, onToggleEnabled, onCollectNow, onRefreshOne }) {
  const [busy, setBusy] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const Icon = DEVICE_ICONS[device.device_type] || Server

  const collectNow = async () => {
    setBusy(true)
    try {
      await onCollectNow(device.id)
      await onRefreshOne()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Icon size={16} className="text-cyan-400 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-slate-100">{device.name}</p>
            <p className="text-[11px] text-slate-500">{device.device_type}{device.vendor ? ` · ${device.vendor}` : ''} · {device.analyzer}</p>
          </div>
        </div>
        <button
          onClick={() => onToggleEnabled(device)}
          className={`shrink-0 text-[11px] px-2 py-1 rounded-lg border ${
            device.enabled ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-slate-700/50 border-slate-600 text-slate-400'
          }`}
        >
          {device.enabled ? '자동 점검 ON' : '자동 점검 OFF'}
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5"><Clock size={11} />주기: {device.interval_minutes}분</div>
        <div className="flex items-center gap-1.5">{device.enabled ? <Wifi size={11} /> : <WifiOff size={11} />}다음 실행: {device.enabled ? fmtDate(device.next_run_at) : '—'}</div>
        <div>최근 실행: {fmtDate(device.last_run_at)}</div>
        <div><StatusPill status={device.last_status} /></div>
      </div>

      {device.last_severity && (
        <div className="flex items-start gap-2 bg-slate-950/50 rounded-lg p-2">
          <SeverityBadge severity={device.last_severity} />
          <p className="text-xs text-slate-400 flex-1">{device.last_summary}</p>
        </div>
      )}

      <div className="flex items-center gap-1.5 flex-wrap">
        <button onClick={collectNow} disabled={busy} className="flex items-center gap-1 text-[11px] bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 text-white rounded-lg px-2.5 py-1.5">
          <Zap size={11} />{busy ? '수집 중...' : '지금 수집'}
        </button>
        <button onClick={() => setHistoryOpen(o => !o)} className="flex items-center gap-1 text-[11px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg px-2.5 py-1.5">
          <History size={11} />기록 {historyOpen ? '숨기기' : '보기'}
        </button>
        <button onClick={() => onEdit(device)} className="flex items-center gap-1 text-[11px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg px-2.5 py-1.5">
          <Pencil size={11} />수정
        </button>
        <button onClick={() => onDelete(device.id)} className="flex items-center gap-1 text-[11px] bg-red-950/40 hover:bg-red-900/50 text-red-300 rounded-lg px-2.5 py-1.5 ml-auto">
          <Trash2 size={11} />삭제
        </button>
      </div>

      {historyOpen && (
        <div className="border border-slate-700 rounded-lg overflow-hidden">
          <DeviceHistory deviceId={device.id} />
        </div>
      )}
    </div>
  )
}

function BulkUploadPanel({ onDone }) {
  const [open, setOpen] = useState(false)
  const [columnsOpen, setColumnsOpen] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const fileInputRef = useRef(null)

  const handleFile = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setUploading(true)
    setResult(null)
    setError('')
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/devices/bulk-upload', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      setResult(res.data)
      onDone()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-750">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <FileSpreadsheet size={15} className="text-emerald-400" />파일로 여러 장비 한 번에 등록 (CSV/Excel)
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-slate-700 pt-4 space-y-3">
          <p className="text-xs text-slate-400">
            아래 형식의 CSV(.csv) 또는 Excel(.xlsx) 파일을 업로드하면 각 행이 개별 등록과 동일한 방식으로 검증되어 한 번에 여러 장비가 등록됩니다.
            한 행에 문제가 있어도 나머지 정상 행은 그대로 등록됩니다.
          </p>

          <div className="flex items-center gap-2 flex-wrap">
            <a
              href={BULK_TEMPLATE_URL} download
              className="inline-flex items-center gap-1.5 text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg px-3 py-2"
            >
              <Download size={12} />예시 파일 다운로드 (device-bulk-template.csv)
            </a>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="inline-flex items-center gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg px-3 py-2"
            >
              <Upload size={12} />{uploading ? '업로드 중...' : '파일 업로드로 등록'}
            </button>
            <input ref={fileInputRef} type="file" accept=".csv,.xlsx,.xls" onChange={handleFile} className="hidden" />
          </div>

          <button onClick={() => setColumnsOpen(o => !o)} className="text-[11px] text-slate-500 hover:text-slate-300 underline underline-offset-2">
            {columnsOpen ? '컬럼 설명 숨기기' : '어떤 컬럼을 채워야 하나요?'}
          </button>
          {columnsOpen && (
            <div className="bg-slate-950/60 border border-slate-700 rounded-lg p-3 overflow-x-auto">
              <table className="text-[11px] text-slate-400 w-full">
                <thead>
                  <tr className="text-left text-slate-500">
                    <th className="pr-3 pb-1">컬럼</th><th className="pr-3 pb-1">필수</th><th className="pb-1">설명</th>
                  </tr>
                </thead>
                <tbody>
                  {BULK_COLUMNS.map(c => (
                    <tr key={c.name} className="border-t border-slate-800">
                      <td className="pr-3 py-1 font-mono text-cyan-300">{c.name}</td>
                      <td className="pr-3 py-1">{c.required ? <span className="text-amber-400">필수</span> : '선택'}</td>
                      <td className="py-1">{c.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {error && (
            <p className="text-xs text-red-400 bg-red-950/30 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>
          )}

          {result && (
            <div className="space-y-2">
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 size={13} />{result.created_count}개 등록됨</span>
                {result.error_count > 0 && (
                  <span className="flex items-center gap-1 text-red-400"><AlertCircle size={13} />{result.error_count}개 오류</span>
                )}
                <span className="text-slate-500">전체 {result.total_rows}행</span>
              </div>
              {result.errors.length > 0 && (
                <div className="space-y-1">
                  {result.errors.map((e, i) => (
                    <p key={i} className="text-[11px] text-red-300 bg-red-950/20 border border-red-500/20 rounded px-2 py-1.5">
                      {e.row}행 ({e.name}): {e.message}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function DeviceManagement() {
  const [meta, setMeta] = useState(null)
  const [devices, setDevices] = useState([])
  const [form, setForm] = useState(EMPTY_FORM)
  const [editingId, setEditingId] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [formOpen, setFormOpen] = useState(true)
  const [error, setError] = useState('')

  const loadDevices = useCallback(() => {
    axios.get('/api/devices').then(r => setDevices(r.data.devices)).catch(() => {})
  }, [])

  useEffect(() => {
    axios.get('/api/devices/meta').then(r => setMeta(r.data)).catch(() => {})
    loadDevices()
    const interval = setInterval(loadDevices, 15000) // 스케줄러가 백그라운드에서 갱신하는 상태를 주기적으로 반영
    return () => clearInterval(interval)
  }, [loadDevices])

  const currentTypeMeta = meta?.device_types?.find(t => t.id === form.device_type)
  const allowedAnalyzers = currentTypeMeta?.analyzers || []

  useEffect(() => {
    if (allowedAnalyzers.length && !allowedAnalyzers.includes(form.analyzer)) {
      setForm(f => ({ ...f, analyzer: allowedAnalyzers[0] }))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.device_type, meta])

  const needsCredentials = ['network_device', 'linux_host'].includes(form.device_type) ||
    (form.device_type === 'windows_host' && form.host.trim() && !['localhost', '127.0.0.1'].includes(form.host.trim()))
  const isCloud = ['aws_account', 'azure_subscription', 'gcp_project'].includes(form.device_type)
  const isNetworkDevice = form.device_type === 'network_device'

  const resetForm = () => {
    setForm(EMPTY_FORM)
    setEditingId(null)
    setTestResult(null)
    setError('')
  }

  const startEdit = (device) => {
    setForm({
      name: device.name, device_type: device.device_type, vendor: device.vendor || '',
      analyzer: device.analyzer, host: device.host || '', port: device.port || '',
      username: device.username || '', password: '', context: device.context || '',
      interval_minutes: device.interval_minutes, enabled: device.enabled,
    })
    setEditingId(device.id)
    setTestResult(null)
    setError('')
    setFormOpen(true)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const buildPayload = () => ({
    ...form,
    port: form.port ? Number(form.port) : null,
    interval_minutes: Number(form.interval_minutes),
    vendor: form.device_type === 'network_device' ? form.vendor : null,
  })

  const testConnection = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await axios.post('/api/devices/test-connection', buildPayload())
      setTestResult(res.data)
    } catch (err) {
      setTestResult({ ok: false, error: err.response?.data?.detail || err.message })
    } finally {
      setTesting(false)
    }
  }

  const save = async () => {
    setError('')
    setSaving(true)
    try {
      if (editingId) {
        await axios.put(`/api/devices/${editingId}`, buildPayload())
      } else {
        await axios.post('/api/devices', buildPayload())
      }
      resetForm()
      loadDevices()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setSaving(false)
    }
  }

  const deleteDevice = async (id) => {
    if (!confirm('이 장비를 삭제하시겠습니까? 등록된 접속 정보와 자동 점검 설정이 함께 삭제됩니다.')) return
    await axios.delete(`/api/devices/${id}`)
    loadDevices()
  }

  const toggleEnabled = async (device) => {
    await axios.put(`/api/devices/${device.id}`, {
      name: device.name, device_type: device.device_type, vendor: device.vendor, analyzer: device.analyzer,
      host: device.host, port: device.port, username: device.username, context: device.context,
      interval_minutes: device.interval_minutes, enabled: !device.enabled,
    })
    loadDevices()
  }

  const collectNow = async (id) => {
    try {
      await axios.post(`/api/devices/${id}/collect-now`)
    } catch (err) {
      alert('수집 실패: ' + (err.response?.data?.detail || err.message))
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-5xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Server className="text-cyan-400" size={26} /> 장비 관리 &amp; 자동 점검
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            방화벽·스위치·서버·클라우드 계정을 등록하면 설정한 주기마다 자동으로 접속해 정보를 수집·분석하고,
            문제가 발견되면 알림을 보냅니다 — SIEM 장비가 API로 대상 장비를 폴링하는 것과 같은 방식입니다.
          </p>
        </div>

        <GuidePanel title="장비 등록 & 자동 점검 사용 가이드" steps={STEPS} tips={TIPS} />

        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
          <button onClick={() => setFormOpen(o => !o)} className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-750">
            <span className="flex items-center gap-2 text-sm font-semibold text-slate-200">
              <Plus size={15} className="text-cyan-400" />{editingId ? `장비 수정 (#${editingId})` : '새 장비 등록'}
            </span>
            {formOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>

          {formOpen && (
            <div className="px-4 pb-4 border-t border-slate-700 pt-4 space-y-4">
              <div className="grid md:grid-cols-2 gap-3">
                <div>
                  <p className="text-xs font-semibold text-slate-400 mb-1.5">장비 이름</p>
                  <input
                    value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="예: 본사 방화벽, 운영계 AWS 계정"
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <p className="text-xs font-semibold text-slate-400 mb-1.5">장비 유형</p>
                  <select
                    value={form.device_type}
                    onChange={e => setForm(f => ({ ...f, device_type: e.target.value, vendor: '' }))}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  >
                    {meta?.device_types?.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                </div>
              </div>

              {isNetworkDevice && (
                <div>
                  <p className="text-xs font-semibold text-slate-400 mb-1.5">벤더</p>
                  <select
                    value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">선택하세요</option>
                    {meta?.vendors?.map(v => <option key={v.id} value={v.id}>{v.label}</option>)}
                  </select>
                </div>
              )}

              <div>
                <p className="text-xs font-semibold text-slate-400 mb-1.5">분석 방식</p>
                <div className="flex gap-2 flex-wrap">
                  {meta?.analyzers?.filter(a => allowedAnalyzers.includes(a.id)).map(a => (
                    <button
                      key={a.id}
                      onClick={() => setForm(f => ({ ...f, analyzer: a.id }))}
                      className={`text-xs px-3 py-1.5 rounded-lg ${form.analyzer === a.id ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
                    >
                      {a.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-3">
                <div>
                  <p className="text-xs font-semibold text-slate-400 mb-1.5">
                    {isCloud ? '식별자' : '호스트/IP'}
                  </p>
                  <input
                    value={form.host} onChange={e => setForm(f => ({ ...f, host: e.target.value }))}
                    placeholder={currentTypeMeta?.host_hint}
                    className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">{currentTypeMeta?.host_hint}</p>
                </div>
                {!isCloud && (
                  <div>
                    <p className="text-xs font-semibold text-slate-400 mb-1.5">포트 (선택, 기본 22)</p>
                    <input
                      value={form.port} onChange={e => setForm(f => ({ ...f, port: e.target.value }))}
                      placeholder="22" type="number"
                      className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                )}
              </div>

              {(needsCredentials || isNetworkDevice) && (
                <div className="grid md:grid-cols-2 gap-3 bg-slate-950/40 border border-slate-700 rounded-lg p-3">
                  <div>
                    <p className="text-xs font-semibold text-slate-400 mb-1.5 flex items-center gap-1"><KeyRound size={11} />사용자명</p>
                    <input
                      value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                      className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-400 mb-1.5">비밀번호{editingId ? ' (변경 시에만 입력)' : ''}</p>
                    <input
                      value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                      type="password"
                      className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              )}

              {isCloud && (
                <p className="text-[11px] text-slate-500 bg-slate-950/40 border border-slate-700 rounded-lg p-2.5">
                  클라우드 계정은 이 백엔드 호스트에 이미 설치·인증된 CLI(aws/az/gcloud)를 그대로 사용합니다 — 이 화면에 별도 자격증명을 입력하지 않습니다.
                </p>
              )}

              <div>
                <p className="text-xs font-semibold text-slate-400 mb-1.5">환경 컨텍스트 (선택)</p>
                <input
                  value={form.context} onChange={e => setForm(f => ({ ...f, context: e.target.value }))}
                  placeholder="예: 결제 정보를 다루는 프로덕션 웹 서버"
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-400 mb-1.5">수집 주기</p>
                <div className="flex gap-2 flex-wrap items-center">
                  {meta?.interval_presets?.map(p => (
                    <button
                      key={p.minutes}
                      onClick={() => setForm(f => ({ ...f, interval_minutes: p.minutes }))}
                      className={`text-xs px-3 py-1.5 rounded-lg ${Number(form.interval_minutes) === p.minutes ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
                    >
                      {p.label}
                    </button>
                  ))}
                  <input
                    value={form.interval_minutes}
                    onChange={e => setForm(f => ({ ...f, interval_minutes: e.target.value }))}
                    type="number" min={5} max={10080}
                    className="w-24 bg-slate-900 border border-slate-600 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
                  />
                  <span className="text-[11px] text-slate-500">분 (직접 입력 가능, 5~10080)</span>
                </div>
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
                등록 즉시 자동 점검 활성화
              </label>

              {testResult && (
                <div className={`flex items-start gap-2 rounded-lg p-2.5 text-xs ${testResult.ok ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border border-red-500/30 text-red-300'}`}>
                  {testResult.ok ? <CheckCircle2 size={13} className="shrink-0 mt-0.5" /> : <XCircle size={13} className="shrink-0 mt-0.5" />}
                  <span>{testResult.message || testResult.error}</span>
                </div>
              )}
              {error && <p className="text-xs text-red-400 bg-red-950/30 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>}

              <div className="flex items-center gap-2">
                <button
                  onClick={testConnection} disabled={testing || !form.name.trim()}
                  className="flex items-center gap-1.5 text-xs bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-slate-200 rounded-lg px-3 py-2"
                >
                  <RefreshCw size={12} className={testing ? 'animate-spin' : ''} />{testing ? '테스트 중...' : '연결 테스트'}
                </button>
                <button
                  onClick={save} disabled={saving || !form.name.trim() || (isNetworkDevice && !form.vendor)}
                  className="flex-1 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold"
                >
                  {saving ? '저장 중...' : editingId ? '수정 저장' : '장비 등록'}
                </button>
                {editingId && (
                  <button onClick={resetForm} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-2">취소</button>
                )}
              </div>
            </div>
          )}
        </div>

        <BulkUploadPanel onDone={loadDevices} />

        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-semibold text-slate-300">등록된 장비 ({devices.length})</p>
            <button onClick={loadDevices} className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200">
              <RefreshCw size={11} />새로고침
            </button>
          </div>
          {devices.length === 0 ? (
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-8 text-center text-slate-500 text-sm">
              등록된 장비가 없습니다. 위에서 장비를 등록해보세요.
            </div>
          ) : (
            <div className="grid md:grid-cols-2 gap-4">
              {devices.map(d => (
                <DeviceCard
                  key={d.id} device={d} onEdit={startEdit} onDelete={deleteDevice}
                  onToggleEnabled={toggleEnabled} onCollectNow={collectNow} onRefreshOne={loadDevices}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
