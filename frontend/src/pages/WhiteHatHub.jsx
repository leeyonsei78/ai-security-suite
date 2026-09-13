import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'
import {
  ShieldHalf, AlertTriangle, ArrowRight, CheckCircle2, Circle, Swords, Cpu,
  ShieldCheck, Fingerprint, Search, Layers, Package,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const HUB_STEPS = [
  '이 페이지는 새로운 실습을 담고 있지 않습니다 — 이미 흩어져 있는 실습 모듈(Web CTF 아레나, 모의 해킹 랩, Pwn/Reverse 실습실, AD/Kerberos 공격 실습, 포렌식 실습 랩)을 하나의 학습 경로로 정리한 허브입니다.',
  '아래 "추천 학습 경로"를 순서대로 따라가거나, 관심 있는 모듈로 바로 이동해도 됩니다.',
  '각 모듈 카드의 [바로가기]를 누르면 해당 실습 페이지로 이동합니다.',
  '모듈을 완료했다면 카드의 체크박스를 눌러 개인 진행 상황을 표시할 수 있습니다 (이 브라우저에만 저장되며, 서버로 전송되지 않습니다).',
]
const HUB_TIPS = [
  '정보보안팀이 "공격 기법을 알아야 방어할 수 있다"는 목적으로 만든 화이트해커(방어적 보안) 연습 공간입니다 — 모든 대상은 로컬에서만 동작하는 가상의 시스템입니다.',
  '난이도가 궁금하면 각 카드의 난이도 범위를, 설치 요구사항이 궁금하면 "필요 환경"을 먼저 확인하세요.',
  '실전 감각이 목적이라면 타이머·공유 스코어보드가 있는 Web CTF 아레나부터, 팀 스터디가 목적이라면 모의 해킹 랩의 체이닝 시나리오부터 시작하는 것을 추천합니다.',
]

const MODULE_ICONS = {
  web_arena: Swords,
  pentest_lab: ShieldCheck,
  pwn_lab: Cpu,
  ad_attack_lab: Fingerprint,
  forensics_lab: Search,
}

const PROGRESS_KEY = 'whitehat-hub-progress'

function loadProgress() {
  try {
    return JSON.parse(localStorage.getItem(PROGRESS_KEY) || '{}')
  } catch {
    return {}
  }
}

function saveProgress(progress) {
  try {
    localStorage.setItem(PROGRESS_KEY, JSON.stringify(progress))
  } catch { /* ignore */ }
}

function ModuleCard({ module, done, onToggleDone }) {
  const Icon = MODULE_ICONS[module.id] || Package
  return (
    <div className={`bg-slate-800 border rounded-xl p-5 space-y-3 transition-colors ${done ? 'border-green-600/50' : 'border-slate-700'}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon size={20} className="text-violet-400 shrink-0" />
          <div>
            <p className="text-base font-bold text-slate-100">{module.title}</p>
            <span className="text-[11px] font-semibold text-violet-300 bg-violet-500/10 border border-violet-500/30 rounded-full px-2 py-0.5">{module.category}</span>
          </div>
        </div>
        <button onClick={onToggleDone} className="shrink-0 text-slate-400 hover:text-green-400" title="완료로 표시 (이 브라우저에만 저장됨)">
          {done ? <CheckCircle2 size={20} className="text-green-400" /> : <Circle size={20} />}
        </button>
      </div>
      <p className="text-sm text-slate-300">{module.description}</p>
      <div className="flex flex-wrap gap-3 text-[11px] text-slate-500">
        <span>난이도: <span className="text-slate-300">{module.difficulty_range}</span></span>
        <span>챌린지 수: <span className="text-slate-300">{module.challenge_count}개</span></span>
      </div>
      <p className="text-[11px] text-slate-500">필요 환경: <span className="text-slate-400">{module.requires}</span></p>
      <Link
        to={module.route}
        className="inline-flex items-center gap-1.5 text-xs font-semibold text-violet-300 hover:text-violet-200 bg-violet-600/10 border border-violet-600/30 rounded-lg px-3 py-1.5"
      >
        바로가기 <ArrowRight size={13} />
      </Link>
    </div>
  )
}

export default function WhiteHatHub() {
  const [catalog, setCatalog] = useState(null)
  const [progress, setProgress] = useState(loadProgress)

  useEffect(() => {
    axios.get('/api/whitehat-hub/catalog').then(r => setCatalog(r.data)).catch(() => {})
  }, [])

  const toggleDone = (moduleId) => {
    setProgress(prev => {
      const next = { ...prev, [moduleId]: !prev[moduleId] }
      saveProgress(next)
      return next
    })
  }

  const modules = catalog?.modules || []
  const byId = Object.fromEntries(modules.map(m => [m.id, m]))
  const doneCount = modules.filter(m => progress[m.id]).length

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-5xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldHalf className="text-violet-400" size={26} /> 화이트해커 연습 허브
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            정보보안팀이 방어 역량을 기르기 위해 공격 기법을 직접 실습하는 공간 — 웹 해킹, 모의해킹 체이닝, 시스템 해킹,
            AD/Kerberos 공격, 포렌식 실습을 하나의 학습 경로로 모았습니다.
            {catalog && <> 총 <span className="text-slate-200 font-semibold">{catalog.total_challenge_count}개</span> 챌린지, {doneCount}/{modules.length} 모듈 완료 표시됨.</>}
          </p>
        </div>

        <GuidePanel title="화이트해커 연습 허브 사용 가이드" steps={HUB_STEPS} tips={HUB_TIPS} />

        {catalog?.safety_notice && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex gap-2.5">
            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-200">{catalog.safety_notice}</p>
          </div>
        )}

        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
          <p className="text-sm font-semibold flex items-center gap-1.5"><Layers size={15} className="text-violet-400" /> 추천 학습 경로</p>
          <div className="space-y-3">
            {(catalog?.learning_path || []).map(step => (
              <div key={step.order} className="flex gap-3 items-start">
                <div className="shrink-0 w-7 h-7 rounded-full bg-violet-600/20 border border-violet-500/40 text-violet-300 text-xs font-bold flex items-center justify-center">
                  {step.order}
                </div>
                <div className="flex-1 space-y-1">
                  <p className="text-sm font-semibold text-slate-100">{step.title}</p>
                  <p className="text-xs text-slate-400">{step.why}</p>
                  <div className="flex gap-1.5 flex-wrap pt-0.5">
                    {step.modules.map(mid => byId[mid] && (
                      <Link
                        key={mid}
                        to={byId[mid].route}
                        className="text-[11px] text-violet-300 hover:text-violet-200 bg-violet-600/10 border border-violet-600/30 rounded-full px-2.5 py-1"
                      >
                        {byId[mid].title} →
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p className="text-sm font-semibold mb-3">전체 실습 모듈</p>
          <div className="grid sm:grid-cols-2 gap-4">
            {modules.map(m => (
              <ModuleCard key={m.id} module={m} done={!!progress[m.id]} onToggleDone={() => toggleDone(m.id)} />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
