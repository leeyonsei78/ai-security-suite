import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { Gauge, RefreshCw } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import GuidePanel from '../components/GuidePanel'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'

const GUIDE_STEPS = [
  '탐지형 앱 14개의 실행 건수와 CRITICAL 알림 건수를 한 화면에서 확인합니다.',
  'CRITICAL 알림이 있는 앱을 클릭하면 해당 앱 페이지로 바로 이동합니다.',
  '하단 최근 알림 목록에서 어느 앱에서 무엇이 발견됐는지 시간순으로 확인합니다.',
  '[새로고침]으로 최신 상태를 다시 집계합니다.',
]
const GUIDE_TIPS = [
  '이 페이지는 새로운 분석을 수행하지 않습니다 — 각 앱이 이미 남긴 히스토리·알림 기록만 모아서 보여줍니다.',
  '앱마다 결과 스키마가 달라 심각도별 세부 집계 대신 "실행 건수"와 "CRITICAL 알림 건수"라는 공통 지표만 씁니다.',
  '더 자세한 내용은 각 앱 페이지의 "최근 분석/감사" 목록에서 확인하세요.',
]

const APP_ROUTES = {
  dashboard: '/', phishing: '/phishing', vuln: '/vuln', ioc: '/ioc', webscan: '/webscan',
  injection: '/injection', model_audit: '/model-audit', firewall_audit: '/firewall-audit',
  infra_scan_dependency: '/infra-scan', infra_scan_network: '/infra-scan', iam_audit: '/iam-audit',
  secret_scan: '/secret-scan', container_audit: '/container-audit', dns_security: '/dns-security',
}

const BAR_COLORS = ['#f87171', '#fb923c', '#fbbf24', '#a3e635', '#38bdf8']

export default function RiskDashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    axios.get('/api/dashboard/overview').then(r => setData(r.data)).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const chartData = (data?.apps ?? [])
    .filter(a => a.critical_alerts > 0)
    .slice(0, 8)
    .map(a => ({ name: a.app_label, value: a.critical_alerts }))

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        <div className="flex items-start justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Gauge className="text-indigo-400" size={26} /> 통합 리스크 대시보드
            </h1>
            <p className="text-slate-400 text-sm mt-1">탐지형 앱 14개의 실행 현황과 CRITICAL 알림을 한 화면에서 확인합니다.</p>
          </div>
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg px-3 py-2 shrink-0"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> 새로고침
          </button>
        </div>

        <GuidePanel title="통합 리스크 대시보드 사용 가이드" steps={GUIDE_STEPS} tips={GUIDE_TIPS} />

        {!data && loading && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-32 flex items-center justify-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {data && (
          <>
            <div className="grid grid-cols-3 gap-4">
              <StatCard label="탐지형 앱" value={data.apps.length} color="border-slate-600" />
              <StatCard label="전체 실행 건수" value={data.total_runs} color="border-blue-500" />
              <StatCard label="누적 CRITICAL 알림" value={data.total_critical_alerts} color="border-red-600" />
            </div>

            {chartData.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <p className="text-xs font-semibold text-slate-400 mb-3">앱별 CRITICAL 알림 건수 (상위 8개)</p>
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
              <p className="text-xs font-semibold text-slate-400 px-4 pt-4 pb-2">앱별 현황</p>
              <div className="divide-y divide-slate-700/60">
                {data.apps.map(a => (
                  <button
                    key={a.app}
                    onClick={() => navigate(APP_ROUTES[a.app] ?? '/')}
                    className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-slate-700/40 transition-colors text-left"
                  >
                    <span className="text-sm text-slate-200">{a.app_label}</span>
                    <div className="flex items-center gap-4 shrink-0">
                      <span className="text-xs text-slate-500">실행 {a.total_runs}건</span>
                      {a.critical_alerts > 0 ? (
                        <span className="text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 rounded-full px-2 py-0.5">
                          CRITICAL {a.critical_alerts}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-600">알림 없음</span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <p className="text-xs font-semibold text-slate-400 mb-3">최근 알림 ({data.recent_alerts.length}건)</p>
              {data.recent_alerts.length === 0 && (
                <p className="text-sm text-slate-500 text-center py-6">아직 CRITICAL 알림이 없습니다.</p>
              )}
              <div className="space-y-2">
                {data.recent_alerts.map(a => (
                  <div key={a.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-slate-900/60">
                    <SeverityBadge severity={a.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-400">{a.app_label}</p>
                      <p className="text-sm text-slate-200 truncate">{a.summary}</p>
                    </div>
                    <span className="text-[10px] text-slate-500 shrink-0">{new Date(a.created_at).toLocaleString('ko-KR')}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
