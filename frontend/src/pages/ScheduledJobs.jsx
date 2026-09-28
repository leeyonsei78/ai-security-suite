import { useState, useEffect } from 'react'
import axios from 'axios'
import { Clock, Globe, Database, Trash2, Play, Plus, AlertTriangle, Cloud, ShieldAlert } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const JOB_STEPS = [
  '점검 유형을 선택합니다 — 웹 스캐너/CVE 감시는 대상만 입력하면 되고, CloudWatch Logs/GuardDuty는 App 17(CloudTrail 연동)에서 등록한 AWS 연결이 먼저 있어야 합니다.',
  '대상(URL·키워드·로그 그룹명 등)과 점검 주기(시간 단위)를 입력하고 [등록]을 클릭합니다.',
  '등록된 작업은 백엔드가 켜져 있는 동안 자동으로 주기마다 실행됩니다 — n8n 같은 별도 도구 설치가 필요 없습니다.',
  '직전 실행과 비교해 새로 생긴 CRITICAL 이슈/고위험 CVE·GuardDuty 탐지가 있을 때만 알림(🔔)이 발송됩니다.',
  '[지금 실행]으로 주기를 기다리지 않고 즉시 한 번 테스트할 수 있습니다.',
]
const JOB_TIPS = [
  '실행 결과는 각각 웹 스캐너(App 6)·CVE 조회(App 15)·대시보드(App 1) 히스토리에도 그대로 쌓입니다.',
  '백엔드 프로세스가 켜져 있어야 스케줄이 동작합니다(재시작하면 자동으로 다시 등록됨).',
  '같은 문제가 계속 나와도 매번 알림을 보내지 않고, "새로 생긴" 항목이 있을 때만 알림을 보냅니다.',
  'GuardDuty는 AWS가 이미 심각도를 계산해주므로 Claude 재분석 없이 그 결과를 그대로 사용합니다(원가 절약).',
]

const JOB_TYPE_CONFIG = {
  webscan: { icon: Globe, label: '웹 스캐너 정기 점검', placeholder: 'https://example.com', requiresConnection: false, targetRequired: true },
  cve_watch: { icon: Database, label: 'CVE 키워드 감시', placeholder: 'log4j', requiresConnection: false, targetRequired: true },
  cloudwatch_logs: { icon: Cloud, label: 'AWS CloudWatch Logs 감시', placeholder: '/aws/lambda/my-function', requiresConnection: true, targetRequired: true },
  guardduty_findings: { icon: ShieldAlert, label: 'AWS GuardDuty 탐지 감시', placeholder: '(비워두면 자동 탐지)', requiresConnection: true, targetRequired: false },
}

function JobCard({ job, onDelete, onRunNow, running }) {
  const cfg = JOB_TYPE_CONFIG[job.job_type] ?? JOB_TYPE_CONFIG.webscan
  const Icon = cfg.icon

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Icon size={16} className="text-cyan-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-xs text-slate-400">{cfg.label} · {job.interval_hours}시간마다</p>
            <p className="text-sm font-mono text-slate-200 truncate">{job.target || '(자동 탐지)'}</p>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onRunNow(job.id)}
            disabled={running === job.id}
            className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-cyan-400 disabled:opacity-50"
            title="지금 실행"
          >
            <Play size={14} className={running === job.id ? 'animate-pulse' : ''} />
          </button>
          <button
            onClick={() => onDelete(job.id)}
            className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-red-400"
            title="삭제"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {job.last_error && (
        <p className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle size={12} /> {job.last_error}</p>
      )}
      {job.last_summary && !job.last_error && (
        <p className="text-xs text-slate-300">{job.last_summary}</p>
      )}
      <p className="text-xs text-slate-500">
        {job.last_run_at ? `마지막 실행: ${new Date(job.last_run_at).toLocaleString('ko-KR')}` : '아직 실행되지 않음'}
      </p>
    </div>
  )
}

export default function ScheduledJobs() {
  const [jobs, setJobs] = useState([])
  const [connections, setConnections] = useState([])
  const [jobType, setJobType] = useState('webscan')
  const [target, setTarget] = useState('')
  const [connectionId, setConnectionId] = useState('')
  const [intervalHours, setIntervalHours] = useState(24)
  const [creating, setCreating] = useState(false)
  const [running, setRunning] = useState(null)
  const [error, setError] = useState('')

  const fetchJobs = () => {
    axios.get('/api/scheduled-jobs').then(r => setJobs(r.data.jobs)).catch(() => {})
  }
  const fetchConnections = () => {
    axios.get('/api/cloudtrail/connections').then(r => setConnections(r.data.connections)).catch(() => {})
  }

  useEffect(() => { fetchJobs(); fetchConnections() }, [])

  const cfg = JOB_TYPE_CONFIG[jobType]

  const createJob = async () => {
    if (cfg.targetRequired && !target.trim()) return
    if (cfg.requiresConnection && !connectionId) return
    setCreating(true)
    setError('')
    try {
      await axios.post('/api/scheduled-jobs', {
        job_type: jobType, target, interval_hours: Number(intervalHours),
        connection_id: cfg.requiresConnection ? Number(connectionId) : null,
      })
      setTarget('')
      fetchJobs()
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setCreating(false)
    }
  }

  const deleteJob = async (id) => {
    await axios.delete(`/api/scheduled-jobs/${id}`)
    fetchJobs()
  }

  const runNow = async (id) => {
    setRunning(id)
    try {
      await axios.post(`/api/scheduled-jobs/${id}/run-now`)
      fetchJobs()
    } finally {
      setRunning(null)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Clock className="text-cyan-400" size={26} /> 정기 점검 스케줄러
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            n8n 같은 외부 자동화 도구 없이, 이 앱 자체 내장 스케줄러로 웹 스캔·CVE 감시를 주기적으로 자동 실행합니다.
          </p>
        </div>

        <GuidePanel title="정기 점검 스케줄러 사용 가이드" steps={JOB_STEPS} tips={JOB_TIPS} />

        {/* Create form */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
          <p className="text-sm font-semibold text-slate-300">새 정기 점검 등록</p>
          <div className="grid sm:grid-cols-[auto_1fr_auto] gap-3">
            <select
              value={jobType}
              onChange={e => { setJobType(e.target.value); setTarget(''); setConnectionId('') }}
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm"
            >
              <option value="webscan">웹 스캐너 정기 점검</option>
              <option value="cve_watch">CVE 키워드 감시</option>
              <option value="cloudwatch_logs">AWS CloudWatch Logs 감시</option>
              <option value="guardduty_findings">AWS GuardDuty 탐지 감시</option>
            </select>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder={cfg.placeholder}
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
            <div className="flex items-center gap-1.5 shrink-0">
              <input
                type="number"
                min={1}
                max={720}
                value={intervalHours}
                onChange={e => setIntervalHours(e.target.value)}
                className="w-16 bg-slate-900 border border-slate-600 rounded-lg px-2 py-2 text-sm"
              />
              <span className="text-xs text-slate-400">시간마다</span>
            </div>
          </div>

          {cfg.requiresConnection && (
            <div>
              <select
                value={connectionId}
                onChange={e => setConnectionId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm"
              >
                <option value="">AWS 연결 선택 (App 17에서 먼저 등록 필요)</option>
                {connections.map(c => (
                  <option key={c.id} value={c.id}>{c.role_arn}</option>
                ))}
              </select>
              {connections.length === 0 && (
                <p className="text-xs text-amber-400 mt-1">
                  등록된 AWS 연결이 없습니다 — <a href="/cloudtrail" className="underline">CloudTrail 연동(App 17)</a>에서 먼저 등록하세요.
                </p>
              )}
            </div>
          )}

          {error && <p className="text-xs text-red-400 break-all">{error}</p>}
          <button
            onClick={createJob}
            disabled={creating || (cfg.targetRequired && !target.trim()) || (cfg.requiresConnection && !connectionId)}
            className="flex items-center gap-1.5 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold"
          >
            <Plus size={14} /> {creating ? '등록 중...' : '등록'}
          </button>
        </div>

        {/* Job list */}
        <div className="space-y-3">
          <p className="text-sm font-semibold text-slate-300">등록된 정기 점검 ({jobs.length}개)</p>
          {jobs.length === 0 && (
            <p className="text-sm text-slate-500 text-center py-8">등록된 정기 점검이 없습니다.</p>
          )}
          {jobs.map(job => (
            <JobCard key={job.id} job={job} onDelete={deleteJob} onRunNow={runNow} running={running} />
          ))}
        </div>
      </div>
    </div>
  )
}
