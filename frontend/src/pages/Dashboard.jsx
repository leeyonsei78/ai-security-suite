import { useState, useEffect } from 'react'
import axios from 'axios'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { Shield, AlertTriangle, Upload, Trash2, RefreshCw } from 'lucide-react'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import GuidePanel from '../components/GuidePanel'

const DASHBOARD_STEPS = [
  '상단 탭에서 "분석" 탭을 선택합니다.',
  '로그 파일(.log, .txt)을 드래그하거나 [파일 업로드] 버튼으로 업로드하거나, 텍스트 박스에 로그를 직접 붙여넣습니다.',
  '[분석 시작] 버튼을 클릭하면 AI가 로그를 읽고 위협을 분류합니다.',
  '"개요" 탭에서 위협 분포 파이차트와 심각도별 통계를 확인합니다.',
  '"이벤트" 탭에서 탐지된 이벤트 목록(소스 IP, 심각도, 대응 방안)을 확인합니다.',
  '"상세" 탭에서 선택한 분석 건의 전체 결과를 조회합니다.',
]
const DASHBOARD_TIPS = [
  'API 키 없이도 Mock 모드로 샘플 위협 8종이 자동 생성됩니다.',
  '우측 상단 새로고침(↺) 버튼으로 최신 결과를 다시 불러옵니다.',
  '휴지통(🗑) 버튼으로 전체 분석 내역을 초기화할 수 있습니다.',
  '심각도: Critical(즉시조치) → High → Medium → Low → Info 순으로 위험합니다.',
]

const PIE_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

export default function Dashboard() {
  const [analyses, setAnalyses] = useState([])
  const [loading, setLoading] = useState(false)
  const [textInput, setTextInput] = useState('')
  const [activeTab, setActiveTab] = useState('overview')
  const [isMock, setIsMock] = useState(null)
  const [selectedAnalysis, setSelectedAnalysis] = useState(null)

  const fetchThreats = async () => {
    const res = await axios.get('/api/threats')
    setAnalyses(res.data.analyses)
  }

  const fetchMode = async () => {
    try {
      const res = await axios.get('/api/mode')
      setIsMock(res.data.mock)
    } catch {
      setIsMock(true)
    }
  }

  useEffect(() => {
    fetchMode()
    fetchThreats()
  }, [])

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/analyze/upload', form)
      setSelectedAnalysis(res.data)
      setActiveTab('detail')
      await fetchThreats()
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
      e.target.value = ''
    }
  }

  const handleTextAnalyze = async () => {
    if (!textInput.trim()) return
    setLoading(true)
    try {
      const res = await axios.post('/api/analyze/text', { content: textInput })
      setSelectedAnalysis(res.data)
      setActiveTab('detail')
      await fetchThreats()
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const handleClear = async () => {
    if (!confirm('모든 분석 결과를 삭제할까요?')) return
    await axios.delete('/api/threats')
    setAnalyses([])
    setSelectedAnalysis(null)
  }

  // Aggregate stats across all analyses
  const totalStats = analyses.reduce(
    (acc, a) => {
      const s = a.statistics ?? {}
      acc.critical += s.critical ?? 0
      acc.high += s.high ?? 0
      acc.medium += s.medium ?? 0
      acc.low += s.low ?? 0
      acc.info += s.info ?? 0
      acc.total += s.total_events ?? 0
      return acc
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  )

  const pieData = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .map((k) => ({ name: k, value: totalStats[k.toLowerCase()] }))
    .filter((d) => d.value > 0)

  const allEvents = analyses.flatMap((a) => a.events ?? [])

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* Sub-header */}
      <header className="border-b border-slate-700 px-6 py-3 flex items-center gap-3">
        <div>
          <h1 className="text-base font-semibold">보안 로그 분석 대시보드</h1>
          <p className="text-xs text-slate-400">로그를 업로드하거나 붙여넣기하면 Claude AI가 위협을 분류합니다.</p>
        </div>
        <div className="ml-auto flex gap-2">
          <button onClick={fetchThreats} className="p-2 rounded-lg hover:bg-slate-700 text-slate-400">
            <RefreshCw size={18} />
          </button>
          <button onClick={handleClear} className="p-2 rounded-lg hover:bg-slate-700 text-red-400">
            <Trash2 size={18} />
          </button>
        </div>
      </header>

      <div className="p-6 space-y-6">
        {/* Guide */}
        <GuidePanel title="보안 로그 분석 대시보드 사용 가이드" steps={DASHBOARD_STEPS} tips={DASHBOARD_TIPS} />

        {/* Stat Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard label="전체 이벤트" value={totalStats.total} color="border-slate-600" />
          <StatCard label="Critical" value={totalStats.critical} color="border-red-600" />
          <StatCard label="High" value={totalStats.high} color="border-orange-500" />
          <StatCard label="Medium" value={totalStats.medium} color="border-yellow-500" />
          <StatCard label="Low" value={totalStats.low} color="border-blue-500" />
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-slate-700">
          {['overview', 'events', 'analyze', 'detail'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${
                activeTab === tab
                  ? 'border-b-2 border-blue-400 text-blue-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab === 'overview' ? '개요' : tab === 'events' ? '이벤트' : tab === 'analyze' ? '분석' : '결과'}
            </button>
          ))}
        </div>

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <h2 className="text-sm font-semibold text-slate-400 mb-4">위협 분포</h2>
              {pieData.length > 0 ? (
                <div style={{ width: '100%', height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={PIE_COLORS[entry.name]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-slate-500 text-center py-16">분석 결과 없음</p>
              )}
            </div>
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <h2 className="text-sm font-semibold text-slate-400 mb-4">최근 분석 ({analyses.length}건)</h2>
              <div className="space-y-2 max-h-52 overflow-y-auto">
                {analyses.length === 0 && <p className="text-slate-500 text-sm">없음</p>}
                {analyses.map((a) => (
                  <button
                    key={a.id}
                    onClick={() => { setSelectedAnalysis(a); setActiveTab('detail') }}
                    className="w-full text-left p-2 rounded-lg hover:bg-slate-700 flex justify-between items-center"
                  >
                    <span className="text-sm truncate">{a.filename}</span>
                    <SeverityBadge severity={a.threat_level} />
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Events Tab */}
        {activeTab === 'events' && (
          <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-700">
                <tr>
                  <th className="text-left px-4 py-3 text-slate-300">심각도</th>
                  <th className="text-left px-4 py-3 text-slate-300">분류</th>
                  <th className="text-left px-4 py-3 text-slate-300">설명</th>
                  <th className="text-left px-4 py-3 text-slate-300">소스 IP</th>
                  <th className="text-left px-4 py-3 text-slate-300">대응 방안</th>
                </tr>
              </thead>
              <tbody>
                {allEvents.length === 0 && (
                  <tr><td colSpan={5} className="text-center py-8 text-slate-500">이벤트 없음</td></tr>
                )}
                {allEvents.map((ev, i) => (
                  <tr key={i} className="border-t border-slate-700 hover:bg-slate-750">
                    <td className="px-4 py-3"><SeverityBadge severity={ev.severity} /></td>
                    <td className="px-4 py-3 text-slate-300">{ev.category}</td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{ev.description}</td>
                    <td className="px-4 py-3 font-mono text-slate-400">{ev.source_ip ?? '-'}</td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{ev.remediation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Analyze Tab */}
        {activeTab === 'analyze' && (
          <div className="grid md:grid-cols-2 gap-6">
            {/* File Upload */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <h2 className="font-semibold mb-4 flex items-center gap-2"><Upload size={18} /> 로그 파일 업로드</h2>
              <label className="block border-2 border-dashed border-slate-600 rounded-xl p-8 text-center cursor-pointer hover:border-blue-500 transition-colors">
                <input type="file" accept=".log,.txt,.csv,.json" className="hidden" onChange={handleFileUpload} />
                <p className="text-slate-400">.log / .txt / .csv / .json</p>
                <p className="text-xs text-slate-500 mt-1">클릭하여 파일 선택</p>
              </label>
            </div>

            {/* Text Input */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <h2 className="font-semibold mb-4 flex items-center gap-2"><AlertTriangle size={18} /> 텍스트 직접 입력</h2>
              <textarea
                value={textInput}
                onChange={(e) => setTextInput(e.target.value)}
                placeholder="로그 내용을 여기에 붙여넣기..."
                className="w-full h-36 bg-slate-900 border border-slate-600 rounded-lg p-3 text-sm font-mono resize-none focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleTextAnalyze}
                disabled={loading || !textInput.trim()}
                className="mt-3 w-full py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg font-medium transition-colors"
              >
                {loading ? '분석 중...' : 'Claude AI로 분석'}
              </button>
            </div>
          </div>
        )}

        {/* Detail Tab */}
        {activeTab === 'detail' && (
          <div className="space-y-4">
            {!selectedAnalysis ? (
              <p className="text-slate-500 text-center py-12">분석 결과를 선택하거나 로그를 분석하세요.</p>
            ) : (
              <>
                <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
                  <div className="flex justify-between items-start">
                    <div>
                      <h2 className="font-semibold">{selectedAnalysis.filename}</h2>
                      <p className="text-sm text-slate-400 mt-1">{selectedAnalysis.summary}</p>
                    </div>
                    <SeverityBadge severity={selectedAnalysis.threat_level} />
                  </div>
                </div>
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-slate-700">
                      <tr>
                        <th className="text-left px-4 py-3 text-slate-300">심각도</th>
                        <th className="text-left px-4 py-3 text-slate-300">분류</th>
                        <th className="text-left px-4 py-3 text-slate-300">설명</th>
                        <th className="text-left px-4 py-3 text-slate-300">소스 IP</th>
                        <th className="text-left px-4 py-3 text-slate-300">대응 방안</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedAnalysis.events ?? []).map((ev, i) => (
                        <tr key={i} className="border-t border-slate-700 hover:bg-slate-750">
                          <td className="px-4 py-3"><SeverityBadge severity={ev.severity} /></td>
                          <td className="px-4 py-3 text-slate-300">{ev.category}</td>
                          <td className="px-4 py-3 text-slate-400 max-w-xs">{ev.description}</td>
                          <td className="px-4 py-3 font-mono text-slate-400">{ev.source_ip ?? '-'}</td>
                          <td className="px-4 py-3 text-slate-400 max-w-xs">{ev.remediation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
