import { useState } from 'react'
import { GraduationCap, Trophy, Fingerprint, Crosshair, ArrowLeft, CheckCircle2, Circle, Square, SquareCheck, Lightbulb, Target, ListChecks, Compass, BookMarked, Wrench, Route, ChevronDown, ChevronUp } from 'lucide-react'

export const AUDIENCE_CONFIG = {
  beginner: { label: '처음 해보는 사람', icon: GraduationCap, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30' },
  ctf: { label: '해킹 대회 준비', icon: Trophy, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  privacy: { label: '개인정보 유출 대응', icon: Fingerprint, color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30' },
  pentest: { label: '모의 해킹 실전', icon: Crosshair, color: 'text-violet-400', bg: 'bg-violet-500/10 border-violet-500/30' },
}

const TYPE_LABEL = { portscan: '포트 스캔', config: '설정 파일', code: '코드 스니펫', memory: '메모리 덤프' }

export function ScenarioPicker({ scenarios, onSelect, ctfGuide }) {
  const groups = [
    { key: 'beginner', items: scenarios.filter(s => s.audience === 'beginner') },
    { key: 'ctf', items: scenarios.filter(s => s.audience === 'ctf') },
    { key: 'pentest', items: scenarios.filter(s => s.audience === 'pentest') },
    { key: 'privacy', items: scenarios.filter(s => s.audience === 'privacy') },
  ]

  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">시나리오를 선택하면 상황 설명과 샘플 데이터가 자동으로 준비됩니다. 먼저 스스로 생각해본 뒤 AI 분석 결과와 비교해보세요.</p>
      {groups.map(g => {
        const cfg = AUDIENCE_CONFIG[g.key]
        if (g.items.length === 0) return null
        return (
          <div key={g.key}>
            <div className={`flex items-center gap-2 mb-2 text-sm font-semibold ${cfg.color}`}>
              <cfg.icon size={16} /> {cfg.label}
            </div>
            {g.key === 'ctf' && <div className="mb-3"><CtfPrepGuide guide={ctfGuide} /></div>}
            <div className="grid sm:grid-cols-3 gap-3">
              {g.items.map(s => (
                <button
                  key={s.id}
                  onClick={() => onSelect(s)}
                  className={`text-left border rounded-xl p-4 hover:bg-white/5 transition-colors ${cfg.bg}`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-black/20">{s.level}</span>
                    <span className="text-xs text-slate-400">{TYPE_LABEL[s.input_type]}</span>
                  </div>
                  <p className="text-sm font-semibold text-slate-100 leading-snug">{s.title}</p>
                </button>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function CtfPrepGuide({ guide }) {
  const [open, setOpen] = useState(false)
  if (!guide) return null

  return (
    <div className="bg-amber-950/30 border border-amber-500/20 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-amber-900/20 transition-colors text-left"
      >
        <Compass size={15} className="text-amber-400 shrink-0" />
        <span className="text-sm font-medium text-amber-300">{guide.title}</span>
        <span className="ml-auto text-xs text-amber-500">{open ? '접기' : '무엇부터 배워야 할지 보기'}</span>
        {open ? <ChevronUp size={14} className="text-amber-500" /> : <ChevronDown size={14} className="text-amber-500" />}
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-amber-500/20 pt-3 space-y-4">
          <p className="text-xs text-slate-300 leading-relaxed">{guide.intro}</p>

          <div>
            <p className="text-xs font-semibold text-amber-400 mb-1.5 flex items-center gap-1"><BookMarked size={12} /> 먼저 다질 기초</p>
            <ul className="space-y-1">
              {guide.foundations.map((f, i) => (
                <li key={i} className="flex gap-1.5 text-xs text-slate-300"><span className="text-amber-500 shrink-0">•</span>{f}</li>
              ))}
            </ul>
          </div>

          <div>
            <p className="text-xs font-semibold text-amber-400 mb-2">분야별 핵심 개념</p>
            <div className="grid sm:grid-cols-2 gap-2">
              {guide.categories.map((c, i) => (
                <div key={i} className="bg-black/20 rounded-lg p-2.5">
                  <p className="text-xs font-bold text-slate-200 mb-0.5">{c.name}</p>
                  <p className="text-[11px] text-slate-400 mb-1.5">{c.desc}</p>
                  <ul className="space-y-0.5">
                    {c.learn.map((l, j) => (
                      <li key={j} className="text-[11px] text-slate-300 flex gap-1"><span className="text-amber-500 shrink-0">-</span>{l}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-xs font-semibold text-amber-400 mb-1.5 flex items-center gap-1"><Wrench size={12} /> 꼭 다뤄봐야 할 도구</p>
            <div className="flex flex-wrap gap-1.5">
              {guide.tools.map((t, i) => (
                <span key={i} className="text-[11px] bg-black/20 border border-amber-500/20 rounded-full px-2 py-1 text-slate-300">
                  <span className="font-semibold text-amber-300">{t.name}</span> · {t.use}
                </span>
              ))}
            </div>
          </div>

          <div>
            <p className="text-xs font-semibold text-amber-400 mb-1.5 flex items-center gap-1"><Route size={12} /> 추천 학습 순서</p>
            <ol className="space-y-1">
              {guide.learning_order.map((s, i) => (
                <li key={i} className="flex gap-2 text-xs text-slate-300">
                  <span className="shrink-0 w-4 h-4 rounded-full bg-amber-600/40 text-amber-200 flex items-center justify-center font-bold text-[9px]">{i + 1}</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
          </div>

          <div>
            <p className="text-xs font-semibold text-amber-400 mb-1.5">연습할 수 있는 곳</p>
            <ul className="space-y-1">
              {guide.practice_platforms.map((p, i) => (
                <li key={i} className="flex gap-1.5 text-xs text-slate-400"><span className="text-amber-500 shrink-0">•</span>{p}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

export function ScenarioInfoCard({ scenario, onBack }) {
  const cfg = AUDIENCE_CONFIG[scenario.audience]
  return (
    <div className="space-y-3">
      <button onClick={onBack} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
        <ArrowLeft size={13} /> 다른 시나리오 선택
      </button>

      <div className={`border rounded-xl p-4 space-y-4 ${cfg.bg}`}>
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <cfg.icon size={16} className={cfg.color} />
            <span className={`text-xs font-bold ${cfg.color}`}>{cfg.label} · {scenario.level}</span>
          </div>
          <p className="text-base font-bold text-slate-100">{scenario.title}</p>
        </div>

        <div>
          <p className="text-xs font-semibold text-slate-400 mb-1">상황</p>
          <p className="text-xs text-slate-300 leading-relaxed">{scenario.situation}</p>
        </div>

        <div>
          <p className="text-xs font-semibold text-slate-400 mb-1 flex items-center gap-1"><Target size={12} /> 학습 목표</p>
          <p className="text-xs text-slate-300 leading-relaxed">{scenario.objective}</p>
        </div>

        <div>
          <p className="text-xs font-semibold text-slate-400 mb-2">따라하기 단계</p>
          <ol className="space-y-1.5">
            {scenario.steps.map((step, i) => (
              <li key={i} className="flex gap-2 text-xs text-slate-300">
                <span className="shrink-0 w-5 h-5 rounded-full bg-black/30 flex items-center justify-center font-bold text-[10px]">{i + 1}</span>
                <span className="pt-0.5">{step}</span>
              </li>
            ))}
          </ol>
        </div>

        {scenario.response_plan?.length > 0 && (
          <ResponsePlanChecklist plan={scenario.response_plan} />
        )}

        {scenario.tips?.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-amber-400 mb-1.5 flex items-center gap-1"><Lightbulb size={12} /> 실전 팁</p>
            <ul className="space-y-1">
              {scenario.tips.map((t, i) => (
                <li key={i} className="flex gap-1.5 text-xs text-slate-400">
                  <span className="text-amber-500 shrink-0">•</span>{t}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

function ResponsePlanChecklist({ plan }) {
  const [checked, setChecked] = useState({})
  const total = plan.reduce((n, p) => n + p.items.length, 0)
  const done = Object.values(checked).filter(Boolean).length
  const toggle = (key) => setChecked(c => ({ ...c, [key]: !c[key] }))

  return (
    <div>
      <p className="text-xs font-semibold text-rose-300 mb-2 flex items-center justify-between">
        <span>사고 대응 절차 (처음부터 종료까지)</span>
        <span className="text-slate-400 font-normal">{done}/{total} 완료</span>
      </p>
      <div className="space-y-3">
        {plan.map((phase, pi) => (
          <div key={pi}>
            <p className="text-[11px] font-bold text-slate-200 mb-1">{phase.phase}</p>
            <ul className="space-y-1">
              {phase.items.map((item, ii) => {
                const key = `${pi}-${ii}`
                const isChecked = !!checked[key]
                return (
                  <li key={key}>
                    <button
                      onClick={() => toggle(key)}
                      className="w-full flex items-start gap-2 text-left text-xs hover:text-slate-100 transition-colors"
                    >
                      {isChecked
                        ? <SquareCheck size={14} className="text-green-400 shrink-0 mt-0.5" />
                        : <Square size={14} className="text-slate-500 shrink-0 mt-0.5" />}
                      <span className={isChecked ? 'text-slate-500 line-through' : 'text-slate-300'}>{item}</span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}

export function ScenarioChecklist({ scenario, result }) {
  const resultText = result ? JSON.stringify(result).toLowerCase() : ''
  const findings = scenario.expected_findings.map(f => ({
    ...f,
    matched: result ? resultText.includes(f.keyword.toLowerCase()) : false,
  }))
  const matchedCount = findings.filter(f => f.matched).length

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
      <p className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-1.5">
        <ListChecks size={14} />
        확인 포인트 {result && <span className="text-slate-500">({matchedCount}/{findings.length} 확인됨)</span>}
      </p>
      <ul className="space-y-2.5">
        {findings.map((f, i) => (
          <li key={i} className="flex gap-2 text-xs">
            {f.matched
              ? <CheckCircle2 size={14} className="text-green-400 shrink-0 mt-0.5" />
              : <Circle size={14} className="text-slate-600 shrink-0 mt-0.5" />}
            <div>
              <span className={f.matched ? 'text-slate-200 font-medium' : 'text-slate-400'}>{f.label}</span>
              <p className="text-slate-500 mt-0.5">{f.explain}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
