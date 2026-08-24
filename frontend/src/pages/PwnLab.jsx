import { useState, useEffect } from 'react'
import axios from 'axios'
import { Cpu, Binary, Puzzle, ScanSearch, Download, ChevronDown, ChevronUp, KeyRound, CheckCircle2, XCircle, EyeOff, Eye, Square, SquareCheck, Container, TerminalSquare, Wrench } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const LAB_STEPS = [
  'Pwn/Reverse 챌린지는 0단계(실습 환경 준비)를 먼저 끝내세요 — Docker 또는 WSL 중 하나로 리눅스 gdb 환경을 만들어야 합니다. Misc 챌린지는 별도 환경 없이 바로 풀 수 있습니다.',
  '각 챌린지 카드에서 [다운로드]로 파일을 받습니다 (Pwn/Reverse는 컴파일 전 .c 소스, Misc는 그대로 분석할 파일).',
  'Pwn/Reverse는 "빌드 방법"의 gcc 명령으로 컴파일 후 "분석 단계"를 따라 gdb/Ghidra로 분석합니다. Misc는 "풀이 단계"를 따라 바로 분석합니다.',
  '막히면 힌트를 하나씩 열어보세요.',
  'flag를 찾으면 하단 입력창에 제출해 정답인지 바로 확인할 수 있습니다.',
  '스스로 못 풀었다면 [모범 답안 보기]로 전체 풀이를 확인하세요 — 그래도 직접 따라 해보는 것이 실력에 남습니다.',
]
const LAB_TIPS = [
  'ret2win은 스택 카나리와 PIE를 꺼서 빌드합니다 — 오프셋 계산에만 집중할 수 있도록 난이도를 낮춘 것입니다.',
  'crackme는 소스가 주어지지만, 실전처럼 컴파일된 바이너리만 보고 Ghidra로 분석하는 연습을 해보세요.',
  'Misc의 제로폭 문자 챌린지는 파일을 반드시 [다운로드] 버튼으로 받으세요 — 화면에서 직접 복사하면 숨겨진 문자가 누락될 수 있습니다.',
  '이 실습은 여러분 자신의 로컬 환경(Docker 컨테이너 등)에서 직접 컴파일·실행하는 것을 전제로 합니다.',
]

const CATEGORY_CONFIG = {
  pwn: { label: 'Pwn', icon: Binary, color: 'text-violet-400', bg: 'bg-violet-500/10 border-violet-500/30' },
  reverse: { label: 'Reverse', icon: Puzzle, color: 'text-cyan-400', bg: 'bg-cyan-500/10 border-cyan-500/30' },
  misc: { label: 'Misc/OSINT', icon: ScanSearch, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' },
}

const isCompiledCategory = (category) => category === 'pwn' || category === 'reverse'

function downloadText(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function SetupPath({ path, accent, icon: Icon }) {
  return (
    <div className="bg-black/20 rounded-lg p-3 space-y-3">
      <p className={`text-sm font-bold flex items-center gap-1.5 ${accent}`}><Icon size={14} /> {path.title}</p>
      <ol className="space-y-1.5">
        {path.steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-xs text-slate-300">
            <span className={`shrink-0 w-4 h-4 rounded-full bg-white/10 flex items-center justify-center font-bold text-[9px] ${accent}`}>{i + 1}</span>
            <span className="whitespace-pre-line font-mono leading-relaxed">{s}</span>
          </li>
        ))}
      </ol>
      {path.troubleshooting?.length > 0 && (
        <div className="pt-2 border-t border-white/10">
          <p className="text-xs font-semibold text-amber-400 mb-1 flex items-center gap-1"><Wrench size={11} /> 문제가 생겼다면</p>
          <ul className="space-y-1">
            {path.troubleshooting.map((t, i) => (
              <li key={i} className="text-[11px] text-slate-400 flex gap-1.5"><span className="text-amber-500 shrink-0">•</span>{t}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function LabSetupPanel({ setup }) {
  const [open, setOpen] = useState(true)
  const [checked, setChecked] = useState({})
  const [tab, setTab] = useState('docker')
  if (!setup) return null

  const toggle = (i) => setChecked(c => ({ ...c, [i]: !c[i] }))
  const doneCount = Object.values(checked).filter(Boolean).length

  return (
    <div className="bg-slate-800 border-2 border-cyan-500/40 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-slate-700/50 transition-colors text-left"
      >
        <Cpu size={15} className="text-cyan-400 shrink-0" />
        <span className="text-sm font-semibold text-slate-100">{setup.title}</span>
        <span className="ml-auto text-xs text-slate-500">{open ? '접기' : '펼치기'}</span>
        {open ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
      </button>
      {open && (
        <div className="px-4 pb-4 border-t border-slate-700 pt-3 space-y-4">
          <p className="text-xs text-slate-300 leading-relaxed">{setup.intro}</p>

          {/* Checklist */}
          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-xs font-semibold text-slate-300 mb-2">준비 체크리스트 ({doneCount}/{setup.prereq_checklist.length})</p>
            <ul className="space-y-1.5">
              {setup.prereq_checklist.map((item, i) => (
                <li key={i}>
                  <button onClick={() => toggle(i)} className="w-full flex items-start gap-2 text-left text-xs hover:text-slate-100 transition-colors">
                    {checked[i]
                      ? <SquareCheck size={14} className="text-green-400 shrink-0 mt-0.5" />
                      : <Square size={14} className="text-slate-500 shrink-0 mt-0.5" />}
                    <span className={checked[i] ? 'text-slate-500 line-through' : 'text-slate-300'}>{item}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Which to choose */}
          <div className="bg-cyan-500/10 border border-cyan-500/25 rounded-lg p-3">
            <p className="text-xs font-semibold text-cyan-300 mb-1">어떤 방법을 선택할까요?</p>
            <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">{setup.which_to_choose}</p>
          </div>

          {/* Path tabs */}
          <div className="flex gap-2">
            <button
              onClick={() => setTab('docker')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${tab === 'docker' ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
            >
              <Container size={13} /> 방법 A: Docker
            </button>
            <button
              onClick={() => setTab('wsl')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${tab === 'wsl' ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
            >
              <TerminalSquare size={13} /> 방법 B: WSL
            </button>
          </div>

          {tab === 'docker' && (
            <div className="space-y-3">
              <SetupPath path={setup.docker_path} accent="text-cyan-300" icon={Container} />
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-xs font-semibold text-slate-400">Dockerfile</p>
                  <button
                    onClick={() => downloadText('Dockerfile', setup.dockerfile)}
                    className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                  >
                    <Download size={12} /> 다운로드
                  </button>
                </div>
                <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono">{setup.dockerfile}</pre>
              </div>
            </div>
          )}

          {tab === 'wsl' && (
            <SetupPath path={setup.wsl_path} accent="text-violet-300" icon={TerminalSquare} />
          )}

          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-xs font-semibold text-slate-400 mb-1">Ghidra (GUI 도구는 Windows에 직접 설치)</p>
            <p className="text-xs text-slate-300 leading-relaxed">{setup.ghidra_note}</p>
          </div>
        </div>
      )}
    </div>
  )
}

function ChallengeCard({ challenge }) {
  const [sourceOpen, setSourceOpen] = useState(false)
  const [hintCount, setHintCount] = useState(0)
  const [solutionOpen, setSolutionOpen] = useState(false)
  const [flagInput, setFlagInput] = useState('')
  const [flagResult, setFlagResult] = useState(null) // null | true | false
  const [checking, setChecking] = useState(false)

  const cfg = CATEGORY_CONFIG[challenge.category]

  const checkFlag = async () => {
    if (!flagInput.trim()) return
    setChecking(true)
    setFlagResult(null)
    try {
      const res = await axios.post('/api/pwn-lab/verify', { challenge_id: challenge.id, flag: flagInput.trim() })
      setFlagResult(res.data.correct)
    } catch {
      setFlagResult(false)
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className={`border rounded-xl p-5 space-y-4 ${cfg.bg}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <cfg.icon size={18} className={cfg.color} />
        <span className={`text-xs font-bold ${cfg.color}`}>{cfg.label}</span>
        <span className="text-xs bg-black/20 px-1.5 py-0.5 rounded">{challenge.difficulty}</span>
        <span className="text-xs text-slate-400">주요 도구: {challenge.tool_focus}</span>
      </div>

      <p className="text-base font-bold text-slate-100">{challenge.title}</p>
      <p className="text-xs text-slate-300 leading-relaxed">{challenge.situation}</p>
      <p className="text-xs text-slate-400 leading-relaxed"><span className="font-semibold text-slate-300">목표: </span>{challenge.objective}</p>

      {/* Source */}
      <div>
        <button
          onClick={() => setSourceOpen(o => !o)}
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-slate-100 mb-1.5"
        >
          {sourceOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />} {isCompiledCategory(challenge.category) ? '소스 코드' : '제공 파일'} ({challenge.source_filename})
        </button>
        {sourceOpen && (
          <div className="space-y-1.5">
            <div className="flex justify-end">
              <button
                onClick={() => downloadText(challenge.source_filename, challenge.source_code)}
                className="flex items-center gap-1 text-xs text-slate-300 hover:text-white bg-black/20 px-2 py-1 rounded"
              >
                <Download size={12} /> {isCompiledCategory(challenge.category) ? '소스' : '파일'} 다운로드
              </button>
            </div>
            <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono max-h-72">{challenge.source_code}</pre>
          </div>
        )}
      </div>

      {/* Build steps */}
      <div>
        <p className="text-xs font-semibold text-slate-300 mb-1.5">{isCompiledCategory(challenge.category) ? '빌드 방법' : '준비 단계'}</p>
        <ol className="space-y-1">
          {challenge.build_steps.map((s, i) => (
            <li key={i} className="flex gap-2 text-xs text-slate-300">
              <span className="shrink-0 w-4 h-4 rounded-full bg-black/30 flex items-center justify-center font-bold text-[9px]">{i + 1}</span>
              <span className="font-mono">{s}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Analysis steps */}
      <div>
        <p className="text-xs font-semibold text-slate-300 mb-1.5">{isCompiledCategory(challenge.category) ? `분석 단계 (${challenge.tool_focus})` : '풀이 단계'}</p>
        <ol className="space-y-1">
          {challenge.analysis_steps.map((s, i) => (
            <li key={i} className="flex gap-2 text-xs text-slate-300">
              <span className="shrink-0 w-4 h-4 rounded-full bg-black/30 flex items-center justify-center font-bold text-[9px]">{i + 1}</span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
      </div>

      {/* Exploit template (pwn only) */}
      {challenge.exploit_template && (
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <p className="text-xs font-semibold text-slate-300">익스플로잇 템플릿 (pwntools)</p>
            <button
              onClick={() => downloadText('exploit.py', challenge.exploit_template)}
              className="flex items-center gap-1 text-xs text-slate-300 hover:text-white bg-black/20 px-2 py-1 rounded"
            >
              <Download size={12} /> 다운로드
            </button>
          </div>
          <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono">{challenge.exploit_template}</pre>
        </div>
      )}

      {/* Hints */}
      <div>
        <p className="text-xs font-semibold text-slate-300 mb-1.5">힌트 ({hintCount}/{challenge.hints.length})</p>
        <ul className="space-y-1.5 mb-2">
          {challenge.hints.slice(0, hintCount).map((h, i) => (
            <li key={i} className="text-xs text-slate-300 bg-black/20 rounded-lg p-2">💡 {h}</li>
          ))}
        </ul>
        {hintCount < challenge.hints.length && (
          <button
            onClick={() => setHintCount(c => c + 1)}
            className="text-xs text-amber-400 hover:text-amber-300"
          >
            힌트 {hintCount + 1} 보기 →
          </button>
        )}
      </div>

      {/* Solution */}
      <div>
        <button
          onClick={() => setSolutionOpen(o => !o)}
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-slate-100"
        >
          {solutionOpen ? <Eye size={13} /> : <EyeOff size={13} />} 모범 답안 {solutionOpen ? '숨기기' : '보기'}
        </button>
        {solutionOpen && (
          <pre className="mt-1.5 bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">{challenge.solution}</pre>
        )}
      </div>

      {/* Flag submission */}
      <div className="bg-slate-900/60 rounded-lg p-3 space-y-2">
        <p className="text-xs font-semibold text-slate-300 flex items-center gap-1"><KeyRound size={12} /> flag 제출</p>
        <div className="flex gap-2">
          <input
            value={flagInput}
            onChange={e => { setFlagInput(e.target.value); setFlagResult(null) }}
            placeholder="예: PWN{...} 또는 RE{...}"
            className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={checkFlag}
            disabled={checking || !flagInput.trim()}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-xs font-semibold"
          >
            확인
          </button>
        </div>
        {flagResult === true && (
          <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 size={13} /> 정답입니다! 축하합니다.</p>
        )}
        {flagResult === false && (
          <p className="text-xs text-red-400 flex items-center gap-1"><XCircle size={13} /> 아직 아닙니다 — 힌트를 더 확인해보세요.</p>
        )}
      </div>
    </div>
  )
}

export default function PwnLab() {
  const [challenges, setChallenges] = useState([])
  const [labSetup, setLabSetup] = useState(null)

  useEffect(() => {
    axios.get('/api/pwn-lab/challenges').then(res => {
      setChallenges(res.data.challenges)
      setLabSetup(res.data.lab_setup)
    })
  }, [])

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Cpu className="text-cyan-400" size={26} /> Pwn / Reverse / Misc 실습실
          </h1>
          <p className="text-slate-400 text-sm mt-1">Pwn·Reverse는 실제로 컴파일해서 gdb·Ghidra로 직접 분석하고, Misc/OSINT는 인코딩·스테가노그래피·단서 조합을 직접 풀어보는 실습 챌린지입니다. 취약점 스캐너의 텍스트 분석만으로는 다룰 수 없는 영역을 여기서 손으로 연습하세요.</p>
        </div>

        <GuidePanel title="Pwn/Reverse/Misc 실습실 사용 가이드" steps={LAB_STEPS} tips={LAB_TIPS} />

        <LabSetupPanel setup={labSetup} />

        <div className="space-y-5">
          {challenges.map(c => (
            <ChallengeCard key={c.id} challenge={c} />
          ))}
        </div>
      </div>
    </div>
  )
}
