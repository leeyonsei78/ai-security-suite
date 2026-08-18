import { useState } from 'react'
import axios from 'axios'
import { Search, Trash2, Copy, CheckCircle, XCircle, AlertTriangle, HelpCircle, Globe, Hash, Mail, Wifi } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const VERDICT_CONFIG = {
  MALICIOUS:  { color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30',    icon: XCircle,       label: '악성' },
  SUSPICIOUS: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', icon: AlertTriangle, label: '의심' },
  CLEAN:      { color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30',  icon: CheckCircle,   label: '정상' },
  UNKNOWN:    { color: 'text-slate-400',  bg: 'bg-slate-700/50 border-slate-600',     icon: HelpCircle,    label: '불명' },
}

const TYPE_CONFIG = {
  ip:      { icon: Wifi,   label: 'IP',     color: 'text-blue-400'   },
  domain:  { icon: Globe,  label: '도메인',  color: 'text-purple-400' },
  hash:    { icon: Hash,   label: '해시',   color: 'text-orange-400' },
  email:   { icon: Mail,   label: '이메일', color: 'text-pink-400'   },
  unknown: { icon: Search, label: '?',      color: 'text-slate-500'  },
}

const CONF_COLOR = (c) => c >= 80 ? 'text-red-400' : c >= 50 ? 'text-yellow-400' : 'text-slate-400'

const IOC_STEPS = [
  '텍스트 박스에 분석할 IoC를 한 줄에 하나씩 입력합니다. (IP, 도메인, 해시, 이메일 혼합 가능)',
  '[AI로 IoC 분석] 버튼을 클릭합니다.',
  '결과 테이블에서 각 IoC의 판정(악성·의심·정상), 신뢰도, 카테고리를 확인합니다.',
  '행을 클릭하면 상세 설명과 권장 조치를 볼 수 있습니다.',
  '우측 상단 통계 카드로 전체 위협 현황을 한눈에 파악합니다.',
]
const IOC_TIPS = [
  'IP 주소: 192.168.1.1 형식',
  '도메인/URL: example.com 또는 https://example.com 형식',
  '파일 해시: MD5(32자리), SHA1(40자리), SHA256(64자리) 16진수',
  '이메일 주소: user@domain.com 형식',
  '한 번에 최대 50개까지 일괄 분석 가능합니다.',
]

const SAMPLE_IOCS = `185.220.101.45
paypa1-secure.verify-now.com
44d88612fea8a8f36de82e1278abb02f
admin@secure-bank-alert.net
8.8.8.8
https://malware-download.ru/payload.exe
d41d8cd98f00b204e9800998ecf8427e
noreply@github.com`

function StatBadge({ label, count, color }) {
  return (
    <div className={`flex flex-col items-center px-4 py-2 rounded-lg bg-slate-800 border ${color}`}>
      <span className="text-xl font-bold">{count}</span>
      <span className="text-xs text-slate-400">{label}</span>
    </div>
  )
}

function IoCRow({ item, onClick, selected }) {
  const vcfg = VERDICT_CONFIG[item.verdict] ?? VERDICT_CONFIG.UNKNOWN
  const tcfg = TYPE_CONFIG[item.ioc_type] ?? TYPE_CONFIG.unknown
  const Icon = vcfg.icon
  const TypeIcon = tcfg.icon

  return (
    <div
      onClick={onClick}
      className={`cursor-pointer border rounded-xl p-3 transition-all ${vcfg.bg} ${selected ? 'ring-2 ring-blue-500' : 'hover:brightness-110'}`}
    >
      <div className="flex items-center gap-3">
        <Icon size={16} className={`${vcfg.color} shrink-0`} />
        <TypeIcon size={13} className={`${tcfg.color} shrink-0`} />
        <span className="font-mono text-xs text-slate-200 flex-1 truncate">{item.ioc}</span>
        <span className="text-xs text-slate-400 hidden sm:block">{item.category}</span>
        <span className={`text-xs font-bold ${CONF_COLOR(item.confidence)} shrink-0`}>{item.confidence}%</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${vcfg.color} bg-black/20 shrink-0`}>{vcfg.label}</span>
      </div>
    </div>
  )
}

function IoCDetail({ item }) {
  const vcfg = VERDICT_CONFIG[item.verdict] ?? VERDICT_CONFIG.UNKNOWN
  const tcfg = TYPE_CONFIG[item.ioc_type] ?? TYPE_CONFIG.unknown
  const VIcon = vcfg.icon

  return (
    <div className={`border rounded-xl p-5 space-y-3 ${vcfg.bg}`}>
      <div className="flex items-start gap-3">
        <VIcon size={22} className={`${vcfg.color} mt-0.5 shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-bold ${vcfg.color}`}>{vcfg.label}</span>
            <span className="text-xs text-slate-400">신뢰도 {item.confidence}%</span>
            <span className={`text-xs px-1.5 py-0.5 rounded bg-black/20 ${tcfg.color}`}>{tcfg.label}</span>
          </div>
          <p className="font-mono text-xs text-slate-300 mt-1 break-all">{item.ioc}</p>
        </div>
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-400 mb-1">카테고리</p>
        <p className="text-sm text-slate-200">{item.category}</p>
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-400 mb-1">분석 결과</p>
        <p className="text-sm text-slate-300 leading-relaxed">{item.description}</p>
      </div>

      {item.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {item.tags.map((t, i) => (
            <span key={i} className="text-xs px-2 py-0.5 bg-slate-700 rounded-full text-slate-300">{t}</span>
          ))}
        </div>
      )}

      <div className="bg-slate-800/60 rounded-lg p-3">
        <p className="text-xs font-semibold text-blue-400 mb-1">권장 조치</p>
        <p className="text-xs text-slate-300 leading-relaxed">{item.recommendation}</p>
      </div>
    </div>
  )
}

export default function IoCAnalyzer() {
  const [content, setContent]     = useState('')
  const [loading, setLoading]     = useState(false)
  const [results, setResults]     = useState([])
  const [selected, setSelected]   = useState(null)
  const [copied, setCopied]       = useState(false)

  const analyze = async () => {
    if (!content.trim()) return
    setLoading(true)
    setResults([])
    setSelected(null)
    try {
      const res = await axios.post('/api/ioc/analyze', { content })
      setResults(res.data.results)
      if (res.data.results.length > 0) setSelected(0)
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const loadSample = () => {
    setContent(SAMPLE_IOCS)
    setResults([])
    setSelected(null)
  }

  const copyResult = () => {
    if (!results.length) return
    const text = results.map(r =>
      `[${r.verdict}] ${r.ioc} (${r.ioc_type}) - ${r.category} - 신뢰도 ${r.confidence}%\n  ${r.description}`
    ).join('\n\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const counts = results.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Search className="text-cyan-400" size={26} /> IoC 분석기
          </h1>
          <p className="text-slate-400 text-sm mt-1">IP, 도메인, 파일 해시, 이메일을 입력하면 AI가 알려진 악성 지표인지 판별합니다.</p>
        </div>

        <GuidePanel title="IoC 분석기 사용 가이드" steps={IOC_STEPS} tips={IOC_TIPS} />

        <div className="grid lg:grid-cols-5 gap-6">
          {/* Input */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex justify-between items-center">
              <p className="text-sm font-medium text-slate-300">IoC 목록 입력 <span className="text-slate-500 font-normal">(한 줄에 하나)</span></p>
              <button onClick={loadSample} className="text-xs text-cyan-400 hover:text-cyan-300">예시 불러오기</button>
            </div>

            <textarea
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={"185.220.101.45\npaypa1-secure.verify-now.com\n44d88612fea8a8f36de82e1278abb02f\nadmin@phish.net"}
              rows={14}
              className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-xs font-mono resize-none focus:outline-none focus:border-cyan-500 placeholder-slate-600"
            />

            <button
              onClick={analyze}
              disabled={loading || !content.trim()}
              className="w-full py-3 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Search size={16} />
              {loading ? '분석 중...' : 'AI로 IoC 분석'}
            </button>

            {/* Stats */}
            {results.length > 0 && (
              <div className="grid grid-cols-4 gap-2">
                <StatBadge label="악성" count={counts.MALICIOUS ?? 0} color="border-red-500/40" />
                <StatBadge label="의심" count={counts.SUSPICIOUS ?? 0} color="border-yellow-500/40" />
                <StatBadge label="정상" count={counts.CLEAN ?? 0} color="border-green-500/40" />
                <StatBadge label="불명" count={counts.UNKNOWN ?? 0} color="border-slate-600" />
              </div>
            )}
          </div>

          {/* Results */}
          <div className="lg:col-span-3 space-y-3">
            {!results.length && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <Search size={40} className="text-slate-600" />
                <p className="text-sm text-slate-500">IoC를 입력하고 분석 버튼을 클릭하세요</p>
                <p className="text-xs text-slate-600">IP · 도메인 · 파일 해시 · 이메일을 혼합해서 입력 가능</p>
              </div>
            )}

            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center flex flex-col items-center gap-3">
                <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 위협 지표를 분석 중...</p>
              </div>
            )}

            {results.length > 0 && (
              <>
                <div className="flex justify-between items-center">
                  <p className="text-sm font-semibold text-slate-300">분석 결과 ({results.length}개)</p>
                  <button
                    onClick={copyResult}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs font-medium transition-colors"
                  >
                    <Copy size={12} /> {copied ? '복사됨!' : '결과 복사'}
                  </button>
                </div>

                {/* IoC list */}
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {results.map((item, i) => (
                    <IoCRow key={i} item={item} selected={selected === i} onClick={() => setSelected(i)} />
                  ))}
                </div>

                {/* Detail */}
                {selected !== null && results[selected] && (
                  <IoCDetail item={results[selected]} />
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
