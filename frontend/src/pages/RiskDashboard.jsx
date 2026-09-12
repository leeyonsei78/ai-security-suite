import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { Gauge, RefreshCw, Compass, ChevronDown, ChevronUp } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'

const GUIDE_TIPS = [
  '이 페이지는 새로운 분석을 수행하지 않습니다 — 각 앱이 이미 남긴 히스토리·알림 기록만 모아서 보여줍니다.',
  '앱마다 결과 스키마가 달라 심각도별 세부 집계 대신 "실행 건수"와 "CRITICAL 알림 건수"라는 공통 지표만 씁니다.',
  '알림을 펼쳤을 때 나오는 대상/권장 조치는 원본 분석 결과에서 최대한 찾아 보여주는 best-effort입니다 — 앱마다 항목별 권장 조치 필드가 다르거나 없을 수 있어, 정확한 내용은 항상 해당 앱 페이지에서 다시 확인하세요.',
  '펼친 알림 상단에 🎓 교육용(Mock 데모, 실제로 존재하지 않는 시나리오)인지 🔧 실전(실제 데이터를 분석한 결과)인지 표시됩니다 — 교육용 항목의 조치/명령은 실제 시스템에 적용하지 마세요.',
  '같은 앱·같은 요약·같은 대상의 알림이 반복되면 "×N"으로 한 항목에 묶어 보여줍니다 — 실제로 서로 다른 문제가 N개라는 뜻이 아니라, 같은 문제를 N번 재분석·재감지했다는 뜻입니다.',
  '알림을 펼친 뒤 [✅ 처리 완료로 표시]를 누르면 "미해결 CRITICAL" 집계에서 빠집니다 — 실제로 조치했는지는 이 앱이 검증하지 않으므로, 조치 없이 누르면 안 됩니다. 잘못 눌렀다면 [↩ 다시 열기]로 되돌릴 수 있습니다.',
]

// 알림이 가리키는 원본 분석 결과(entry)는 앱마다 스키마가 제각각이라(App16 findings,
// App1 events, App4 IoC 결과 등) 공통 필드 후보를 우선순위대로 찾아보는 best-effort 방식.
// 정확한 스키마 파싱이 아니므로 못 찾으면 정직하게 "정보 없음"으로 표시한다.
const TARGET_FIELDS = [
  'affected_resource', 'affected', 'resource', 'target_host', 'source_ip',
  'ioc', 'artifact_reference', 'rule_reference', 'target', 'host', 'domain', 'context', 'name',
]
const ACTION_FIELDS = ['remediation', 'recommendation']

function findActionableNode(root, wantSeverity) {
  const wanted = String(wantSeverity || '').toUpperCase()
  let fallback = null

  function visit(node, depth) {
    if (depth > 6 || node == null || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node) {
        const hit = visit(item, depth + 1)
        if (hit) return hit
      }
      return null
    }
    if (node.remediation || node.recommendation) {
      const sev = String(node.severity || node.verdict || '').toUpperCase()
      if (sev === wanted) return node
      if (!fallback) fallback = node
    }
    for (const key of Object.keys(node)) {
      const hit = visit(node[key], depth + 1)
      if (hit) return hit
    }
    return null
  }

  return visit(root, 0) || fallback
}

function extractField(node, fields) {
  if (!node) return null
  for (const f of fields) {
    if (node[f]) return String(node[f])
  }
  return null
}

// "대상"이 JSON 문자열(예: 방화벽 규칙 원문)이면 한 줄 raw JSON보다 key: value 나열이
// 훨씬 읽기 쉽다 — 앱마다 필드 의미를 알 수 없으니 값 자체를 가공하지 않고 나열만 한다.
function formatTarget(raw) {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) return raw
  try {
    const parsed = JSON.parse(trimmed)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const pairs = Object.entries(parsed)
        .filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && v.length === 0))
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.map(x => (typeof x === 'object' ? JSON.stringify(x) : x)).join(', ') : v}`)
      if (pairs.length) return pairs.join(' · ')
    }
  } catch {
    // JSON 파싱 실패 시 원문 그대로 표시
  }
  return raw
}

// 같은 앱·심각도·요약·대상의 알림이 반복되면(같은 문제를 여러 번 재분석/재감지) 한
// 항목으로 묶는다 — "101건"이 서로 다른 101개 문제처럼 보이는 문제에 대한 대응.
// 입력은 이미 최신순으로 정렬돼 있다고 가정 — 각 그룹의 대표값은 가장 최근 occurrence.
function groupAlerts(alerts) {
  const map = new Map()
  const order = []
  for (const a of alerts) {
    const key = `${a.app}|${a.severity}|${a.summary}|${a.target ?? ''}`
    if (!map.has(key)) {
      map.set(key, { ...a, count: 1, occurrences: [a] })
      order.push(key)
    } else {
      const g = map.get(key)
      g.count += 1
      g.occurrences.push(a)
    }
  }
  return order.map(k => map.get(k))
}

const MODE_EXPLANATION = {
  mock: {
    label: '🎓 교육용 (Mock 데모)',
    className: 'bg-amber-500/10 border border-amber-500/30 text-amber-300',
    text: '이 결과는 실제로 존재하지 않는 고정된 학습용 시나리오입니다. 아래 "대상"은 실제 시스템이 아니며, 여기 나온 명령/조치를 실제 시스템에 그대로 적용하지 마세요 — 진짜 대응이 필요하면 해당 앱에서 실제 데이터를 분석하세요.',
  },
  offline: {
    label: '🔧 실전 (오프라인 규칙 기반)',
    className: 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300',
    text: '실제로 제출/수집된 데이터를 규칙 기반으로 분석한 결과입니다. 아래 대응 방법을 실제로 적용하세요.',
  },
  cloud: {
    label: '🔧 실전 (외부 AI API 분석)',
    className: 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300',
    text: '실제로 제출/수집된 데이터를 AI가 분석한 결과입니다. 아래 대응 방법을 실제로 적용하세요.',
  },
  local: {
    label: '🔧 실전 (로컬 LLM 분석)',
    className: 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300',
    text: '실제로 제출/수집된 데이터를 AI가 분석한 결과입니다. 아래 대응 방법을 실제로 적용하세요.',
  },
  claude_cli: {
    label: '🔧 실전 (Claude Code CLI 분석)',
    className: 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300',
    text: '이 PC의 Claude Code 구독을 통해 실제로 제출/수집된 데이터를 분석한 결과입니다. 아래 대응 방법을 실제로 적용하세요.',
  },
}

const APP_ROUTES = {
  dashboard: '/', phishing: '/phishing', vuln: '/vuln', ioc: '/ioc', webscan: '/webscan',
  injection: '/injection', model_audit: '/model-audit', firewall_audit: '/firewall-audit',
  infra_scan_dependency: '/infra-scan', infra_scan_network: '/infra-scan', iam_audit: '/iam-audit',
  secret_scan: '/secret-scan', container_audit: '/container-audit', dns_security: '/dns-security',
  attack_monitor: '/attack-monitor', attack_monitor_aws: '/attack-monitor',
  fsi_csp_audit: '/fsi-csp-audit', forensics_artifact_audit: '/forensics',
  kese_kit_audit: '/kese-kit', device_monitor: '/devices',
}

const BAR_COLORS = ['#f87171', '#fb923c', '#fbbf24', '#a3e635', '#38bdf8']

function AlertRow({ alert, navigate, onChanged }) {
  const [isOpen, setIsOpen] = useState(false)
  const [detail, setDetail] = useState(null) // {loading, entry, error}
  const [busy, setBusy] = useState(false)

  const hasSnapshot = Object.prototype.hasOwnProperty.call(alert, 'mode')
  const occurrences = alert.occurrences || [alert]
  const count = alert.count || 1
  const resolved = occurrences.every(o => o.resolved)
  const unresolvedCount = occurrences.filter(o => !o.resolved).length

  const toggle = () => {
    setIsOpen(o => !o)
    // 신규 알림은 발생 시점에 저장해둔 스냅샷을 그대로 쓰고(원본이 삭제돼도 유지),
    // 스냅샷이 없는 구버전 알림만 원본을 그때그때 조회해 best-effort로 찾는다.
    if (hasSnapshot || detail) return
    setDetail({ loading: true })
    axios.get('/api/dashboard/alert-entry', { params: { app: alert.app, entry_id: alert.entry_id } })
      .then(r => setDetail({ loading: false, entry: r.data }))
      .catch(err => setDetail({ loading: false, error: err.response?.data?.detail || '원본 분석 결과를 불러오지 못했습니다.' }))
  }

  const handleResolveToggle = async () => {
    setBusy(true)
    const action = resolved ? 'reopen' : 'resolve'
    const targets = resolved ? occurrences : occurrences.filter(o => !o.resolved)
    try {
      await Promise.all(targets.map(o => axios.post(`/api/dashboard/alerts/${o.id}/${action}`)))
      onChanged?.()
    } finally {
      setBusy(false)
    }
  }

  const entry = detail?.entry
  const node = entry ? findActionableNode(entry, alert.severity) : null
  const target = hasSnapshot ? alert.target : ((entry?.target_label || extractField(node, TARGET_FIELDS)) ?? null)
  const method = hasSnapshot ? alert.recommendation : extractField(node, ACTION_FIELDS)
  const mode = hasSnapshot ? alert.mode : (entry?.mode ?? null)
  const findingDescription = hasSnapshot ? alert.finding_description : extractField(node, ['description'])
  const modeInfo = mode ? MODE_EXPLANATION[mode] : null
  const dataLoaded = hasSnapshot || !!entry

  return (
    <div className={`rounded-lg overflow-hidden ${resolved ? 'bg-slate-900/30' : 'bg-slate-900/60'}`}>
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 p-2.5 text-left hover:bg-slate-800/60 transition-colors"
      >
        <SeverityBadge severity={alert.severity} />
        <div className="flex-1 min-w-0">
          <p className="text-xs text-slate-400 flex items-center gap-1.5">
            {alert.app_label}
            {count > 1 && <span className="text-slate-500">×{count}{unresolvedCount !== count ? ` (미해결 ${unresolvedCount})` : ''}</span>}
            {resolved && <span className="text-emerald-400">✅ 처리완료</span>}
          </p>
          <p className={`text-sm truncate ${resolved ? 'text-slate-500' : 'text-slate-200'}`}>{alert.summary}</p>
        </div>
        <span className="text-[10px] text-slate-500 shrink-0">{new Date(alert.created_at).toLocaleString('ko-KR')}</span>
        {isOpen ? <ChevronUp size={14} className="text-slate-500 shrink-0" /> : <ChevronDown size={14} className="text-slate-500 shrink-0" />}
      </button>

      {isOpen && (
        <div className="px-3 pb-3 pt-2 border-t border-slate-700/60 space-y-2 text-xs">
          {!hasSnapshot && detail?.loading && <p className="text-slate-500">불러오는 중...</p>}
          {!hasSnapshot && detail?.error && (
            <p className="text-amber-400">{detail.error} — {alert.app_label} 페이지에서 직접 확인하세요.</p>
          )}
          {!hasSnapshot && !detail?.loading && !detail?.error && !entry && (
            <p className="text-slate-500">
              이 알림은 이 기능이 추가되기 전에 쌓인 오래된 알림이라 대상/방법 정보를 확인할 수 없습니다 —
              {alert.app_label} 페이지에서 직접 확인하세요.
            </p>
          )}

          {dataLoaded && (
            <>
              {modeInfo ? (
                <p className={`rounded px-2 py-1.5 ${modeInfo.className}`}>
                  <span className="font-semibold">{modeInfo.label}</span> — {modeInfo.text}
                  {alert.app === 'attack_monitor_aws' && mode !== 'mock' && (
                    <> (이 프로젝트의 로컬 테스트 샌드박스(LocalStack)에서 발생한 변경이며, 프로덕션 AWS 계정이 아닙니다.)</>
                  )}
                </p>
              ) : (
                <p className="text-slate-500">
                  이 결과가 교육용(Mock)인지 실전 분석인지 확인할 수 있는 정보가 없습니다.
                </p>
              )}

              {count > 1 && (
                <p className="text-slate-500">
                  같은 문제가 총 {count}번 발생했습니다(가장 최근 발생 기준으로 표시 중) — 아래 [처리 완료로 표시]는 {count}건 모두에 적용됩니다.
                </p>
              )}

              <div>
                <span className="text-slate-500 font-semibold">🎓 무엇이 문제인가요: </span>
                <span className="text-slate-200">{findingDescription || alert.summary}</span>
              </div>
              <div>
                <span className="text-slate-500 font-semibold">📍 대상: </span>
                <span className="text-slate-200 break-all">
                  {formatTarget(target) || `이 결과에서 대상 정보를 찾지 못했습니다 — ${alert.app_label} 페이지에서 확인하세요.`}
                </span>
              </div>
              <div>
                <span className="text-slate-500 font-semibold">🔧 지금 해야 할 일: </span>
                <span className="text-slate-200">
                  {method || `이 앱은 항목별 권장 조치 문구를 별도로 제공하지 않습니다 — ${alert.app_label} 페이지에서 이 항목을 열어 확인하세요.`}
                </span>
              </div>
              <div>
                <span className="text-slate-500 font-semibold">✅ 처리 후 확인: </span>
                <span className="text-slate-200">
                  {mode === 'mock'
                    ? `이 항목은 교육용 데모라 실제로 조치·재확인할 대상이 없습니다 — ${alert.app_label}에서 실제 데이터를 분석해 연습해보세요.`
                    : <>
                        조치를 적용한 뒤 {alert.app_label}에서 {target ? `"${formatTarget(target)}" 대상으로 ` : ''}
                        같은 내용을 다시 분석/감사해 더 이상 CRITICAL로 나오지 않는지 확인하세요.
                        확인됐다면 아래 [처리 완료로 표시]를 눌러 "미해결 CRITICAL" 집계에서 제외하세요.
                      </>}
                </span>
              </div>
            </>
          )}
          <div className="flex items-center gap-4 pt-0.5">
            <button
              onClick={handleResolveToggle}
              disabled={busy}
              className={resolved ? 'text-slate-400 hover:text-slate-300' : 'text-emerald-400 hover:text-emerald-300 font-semibold'}
            >
              {busy ? '처리 중...' : resolved ? '↩ 다시 열기' : `✅ 처리 완료로 표시${count > 1 ? ` (${count}건 모두)` : ''}`}
            </button>
            <button
              onClick={() => navigate(APP_ROUTES[alert.app] ?? '/')}
              className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
            >
              → {alert.app_label}에서 확인하기
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function RiskDashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [expandedApp, setExpandedApp] = useState(null)
  const [appAlerts, setAppAlerts] = useState({}) // app -> {loading, alerts, error}
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    axios.get('/api/dashboard/overview').then(r => setData(r.data)).finally(() => setLoading(false))
  }

  const fetchAppAlerts = (app) => {
    setAppAlerts(prev => ({ ...prev, [app]: { ...(prev[app] || {}), loading: true } }))
    axios.get('/api/dashboard/alerts', { params: { app } })
      .then(r => setAppAlerts(prev => ({ ...prev, [app]: { loading: false, alerts: r.data.alerts } })))
      .catch(() => setAppAlerts(prev => ({ ...prev, [app]: { loading: false, error: '알림 목록을 불러오지 못했습니다.' } })))
  }

  useEffect(() => { load() }, [])

  // 알림 처리(완료/재오픈) 후에는 개요(집계·정렬)와, 지금 펼쳐진 앱의 목록이 있다면 그것도
  // 함께 새로고침해 두 화면의 처리 상태가 어긋나지 않게 한다.
  const handleAlertChanged = () => {
    load()
    if (expandedApp) fetchAppAlerts(expandedApp)
  }

  const toggleAppRow = (appRow) => {
    if (appRow.critical_alerts === 0) {
      navigate(APP_ROUTES[appRow.app] ?? '/')
      return
    }
    if (expandedApp === appRow.app) {
      setExpandedApp(null)
      return
    }
    setExpandedApp(appRow.app)
    if (appAlerts[appRow.app]) return
    fetchAppAlerts(appRow.app)
  }

  const appCount = data?.apps?.length ?? null
  const appCountLabel = appCount != null ? `${appCount}개` : '여러'

  const chartData = (data?.apps ?? [])
    .filter(a => a.unresolved_critical_alerts > 0)
    .slice(0, 8)
    .map(a => ({ name: a.app_label, value: a.unresolved_critical_alerts }))

  const groupedRecent = data ? groupAlerts(data.recent_alerts) : []

  const guideSteps = [
    `탐지형 앱 ${appCountLabel}의 실행 건수와 CRITICAL 알림 건수를 한 화면에서 확인합니다.`,
    'CRITICAL이 있는 앱을 클릭하면 그 앱의 CRITICAL 알림 전체 목록이 그 자리에서 펼쳐집니다(개수 제한 없음).',
    '펼쳐진 알림을 다시 클릭하면 대상·권장 조치·처리 후 확인 방법이 나옵니다(원본 분석 결과에서 찾은 내용, best-effort).',
    '조치를 마쳤으면 [✅ 처리 완료로 표시]를 눌러 "미해결 CRITICAL" 집계에서 빼세요 — 잘못 눌렀으면 [↩ 다시 열기]로 되돌릴 수 있습니다.',
    '하단 "최근 알림"은 앱을 가리지 않고 시간순으로 가장 최근 CRITICAL 15건만 모아 보여줍니다.',
    '[새로고침]으로 최신 상태를 다시 집계합니다.',
  ]

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        <div className="flex items-start justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Gauge className="text-indigo-400" size={26} /> 통합 리스크 대시보드
            </h1>
            <p className="text-slate-400 text-sm mt-1">탐지형 앱 {appCountLabel}의 실행 현황과 CRITICAL 알림을 한 화면에서 확인합니다.</p>
          </div>
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg px-3 py-2 shrink-0"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> 새로고침
          </button>
        </div>

        <div className="bg-indigo-950/30 border border-indigo-500/20 rounded-xl p-4 flex gap-3">
          <Compass className="text-indigo-400 shrink-0 mt-0.5" size={18} />
          <div className="text-sm text-slate-300 space-y-1.5">
            <p className="font-semibold text-indigo-300">이 화면의 용도 — "다음에 어느 앱부터 봐야 하는지" 찾는 출발점</p>
            <p>
              이 프로젝트에는 탐지 결과를 내는 앱이 {appCountLabel}(방화벽·IAM·컨테이너 감사기, 취약점 스캐너, IoC 분석기 등) 있습니다.
              매번 하나씩 열어 확인하는 대신, 어느 앱에 <b>아직 처리 안 된 CRITICAL</b>이 몰려 있는지 한 화면에서 비교해
              우선적으로 확인할 앱을 찾기 위한 페이지입니다.
            </p>
            <p>
              이 화면 자체는 아무것도 새로 분석하지 않습니다 — 각 앱이 이미 실행될 때마다 남긴 기록을 그대로 모아 세기만 합니다.
              "앱별 현황"에서 CRITICAL이 있는 앱을 클릭하면 그 앱의 전체 알림 목록이 바로 아래 펼쳐지고, 알림을 다시 클릭하면
              대상·조치·처리 후 확인 방법까지 볼 수 있습니다. 조치를 마친 알림은 [✅ 처리 완료로 표시]를 눌러 "미해결" 집계에서
              뺄 수 있습니다(단, 실제로 조치했는지는 검증하지 않습니다). 하단 "최근 알림"은 앱을 가리지 않고 시간순으로 최신
              15건만 훑어보는 용도입니다.
            </p>
          </div>
        </div>

        <GuidePanel title="통합 리스크 대시보드 사용 가이드" steps={guideSteps} tips={GUIDE_TIPS} />

        {!data && loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-32 flex items-center justify-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {data && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="탐지형 앱" value={data.apps.length} color="border-slate-600" />
              <StatCard label="전체 실행 건수" value={data.total_runs} color="border-blue-500" />
              <StatCard
                label="미해결 CRITICAL"
                value={data.total_unresolved_critical_alerts}
                color="border-red-600"
                hint="아직 [처리 완료]로 표시하지 않은 건수입니다 — 실제로 지금 대응해야 할 건수는 이 숫자입니다."
              />
              <StatCard
                label="누적 CRITICAL 알림"
                value={data.total_critical_alerts}
                color="border-slate-600"
                hint="지금까지 발생한 전체 건수(처리 완료 포함)입니다. 같은 문제를 여러 번 재분석하면 그때마다 늘어나므로, 우선순위는 '미해결'을 기준으로 판단하세요."
              />
            </div>

            {chartData.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <p className="text-xs font-semibold text-slate-400 mb-3">앱별 미해결 CRITICAL 건수 (상위 8개)</p>
                <ResponsiveContainer width="100%" height={Math.max(120, chartData.length * 40)}>
                  <BarChart data={chartData} layout="vertical" margin={{ left: 24, right: 16 }}>
                    <XAxis type="number" allowDecimals={false} stroke="#64748b" fontSize={11} />
                    <YAxis type="category" dataKey="name" width={180} stroke="#94a3b8" fontSize={11} />
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {chartData.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
              <p className="text-xs font-semibold text-slate-400 px-4 pt-4">앱별 현황</p>
              <p className="text-[11px] text-slate-500 px-4 pb-2">CRITICAL이 있는 앱을 클릭하면 전체 목록이 펼쳐집니다. 알림이 없는 앱을 클릭하면 그 앱 페이지로 이동합니다.</p>
              <div className="divide-y divide-slate-700/60">
                {data.apps.map(a => {
                  const isAppOpen = expandedApp === a.app
                  const appDetail = appAlerts[a.app]
                  const groupedAppAlerts = appDetail?.alerts ? groupAlerts(appDetail.alerts) : []
                  return (
                    <div key={a.app}>
                      <button
                        onClick={() => toggleAppRow(a)}
                        className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-slate-700/40 transition-colors text-left"
                      >
                        <span className="text-sm text-slate-200 flex items-center gap-1.5">
                          {a.app_label}
                          {a.critical_alerts > 0 && (
                            isAppOpen ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />
                          )}
                        </span>
                        <div className="flex items-center gap-4 shrink-0">
                          <span className="text-xs text-slate-500">실행 {a.total_runs}건</span>
                          {a.critical_alerts === 0 ? (
                            <span className="text-xs text-slate-600">알림 없음</span>
                          ) : a.unresolved_critical_alerts === 0 ? (
                            <span className="text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-full px-2 py-0.5">
                              ✅ 모두 처리됨 ({a.critical_alerts}건)
                            </span>
                          ) : a.unresolved_critical_alerts === a.critical_alerts ? (
                            <span className="text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 rounded-full px-2 py-0.5">
                              CRITICAL {a.critical_alerts}
                            </span>
                          ) : (
                            <span className="text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 rounded-full px-2 py-0.5">
                              미해결 {a.unresolved_critical_alerts} / 누적 {a.critical_alerts}
                            </span>
                          )}
                        </div>
                      </button>

                      {isAppOpen && (
                        <div className="px-4 pb-4 pt-1 space-y-2 bg-slate-900/30">
                          <div className="flex items-center justify-between">
                            <p className="text-[11px] text-slate-500">
                              {a.app_label} — 미해결 {a.unresolved_critical_alerts}건 / 누적 {a.critical_alerts}건
                              {groupedAppAlerts.length > 0 && ` (중복 제거 시 ${groupedAppAlerts.length}개 항목)`}
                            </p>
                            <button
                              onClick={() => navigate(APP_ROUTES[a.app] ?? '/')}
                              className="text-[11px] text-indigo-400 hover:text-indigo-300 underline underline-offset-2 shrink-0"
                            >
                              → {a.app_label} 페이지 열기
                            </button>
                          </div>
                          {appDetail?.loading && <p className="text-xs text-slate-500">불러오는 중...</p>}
                          {appDetail?.error && <p className="text-xs text-amber-400">{appDetail.error}</p>}
                          {groupedAppAlerts.map(al => (
                            <AlertRow key={al.id} alert={al} navigate={navigate} onChanged={handleAlertChanged} />
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <p className="text-xs font-semibold text-slate-400 mb-3">
                최근 알림 ({groupedRecent.length}개 항목, 원본 {data.recent_alerts.length}건)
              </p>
              {data.recent_alerts.length === 0 && (
                <p className="text-sm text-slate-500 text-center py-6">아직 CRITICAL 알림이 없습니다.</p>
              )}
              <div className="space-y-2">
                {groupedRecent.map(a => (
                  <AlertRow key={a.id} alert={a} navigate={navigate} onChanged={handleAlertChanged} />
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
