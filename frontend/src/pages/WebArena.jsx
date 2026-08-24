import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  Swords, Timer, Play, Pause, RotateCcw, Trophy, Database, LockOpen, CodeXml,
  ChevronDown, ChevronUp, CheckCircle2, XCircle, KeyRound, AlertTriangle,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const ARENA_STEPS = [
  '이 아레나는 실제로 동작하는 취약한 서버(로컬 백엔드, 연습용 데이터)를 대상으로 진짜 HTTP 요청을 보내 공격하는 곳입니다.',
  '원하면 [타이머]로 시간을 설정하고 시작해 실전처럼 시간 압박 속에서 풀어보세요.',
  '각 챌린지 카드에서 직접 값을 입력하고 요청을 보내 응답을 확인하세요 — 정답 payload를 찾으면 응답에 flag가 바로 나타납니다.',
  '찾은 flag를 아래 제출란에 입력하면 오른쪽 스코어보드에 반영됩니다.',
  '3개를 모두 풀면 총 소요 시간이 요약됩니다 — 팀이 있다면 서로 시간을 비교해보는 것도 좋은 연습입니다.',
]
const ARENA_TIPS = [
  '막히면 힌트를 하나씩 열어보세요.',
  '요청/응답은 실제 네트워크 요청입니다 — 브라우저 개발자도구의 Network 탭으로도 확인해보면 실전 감각을 더 기를 수 있습니다.',
  '여기 있는 취약점(SQLi, IDOR, XSS)은 실무에서도 가장 흔하게 발견되는 유형입니다.',
]

const DURATIONS = [15, 30, 60]

function useTimer() {
  const [totalSeconds, setTotalSeconds] = useState(30 * 60)
  const [remaining, setRemaining] = useState(30 * 60)
  const [running, setRunning] = useState(false)
  const intervalRef = useRef(null)

  useEffect(() => {
    if (running) {
      intervalRef.current = setInterval(() => {
        setRemaining(r => {
          if (r <= 1) {
            clearInterval(intervalRef.current)
            setRunning(false)
            return 0
          }
          return r - 1
        })
      }, 1000)
    }
    return () => clearInterval(intervalRef.current)
  }, [running])

  const setDuration = (min) => {
    setRunning(false)
    setTotalSeconds(min * 60)
    setRemaining(min * 60)
  }
  const reset = () => {
    setRunning(false)
    setRemaining(totalSeconds)
  }

  return { remaining, running, setRunning, setDuration, reset, totalSeconds }
}

function formatTime(sec) {
  const m = Math.floor(sec / 60).toString().padStart(2, '0')
  const s = Math.floor(sec % 60).toString().padStart(2, '0')
  return `${m}:${s}`
}

function TimerCard() {
  const { remaining, running, setRunning, setDuration, reset, totalSeconds } = useTimer()
  const low = remaining <= 60 && remaining > 0
  const done = remaining === 0

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
      <p className="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><Timer size={14} /> 실전 타이머</p>
      <div className={`text-4xl font-mono font-bold text-center py-2 ${done ? 'text-red-400' : low ? 'text-amber-400' : 'text-slate-100'}`}>
        {formatTime(remaining)}
      </div>
      <div className="flex gap-1.5 justify-center">
        {DURATIONS.map(d => (
          <button
            key={d}
            onClick={() => setDuration(d)}
            className={`text-xs px-2.5 py-1 rounded-lg ${totalSeconds === d * 60 ? 'bg-cyan-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
          >
            {d}분
          </button>
        ))}
      </div>
      <div className="flex gap-2 justify-center">
        <button onClick={() => setRunning(r => !r)} className="flex items-center gap-1 text-xs px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 rounded-lg font-semibold">
          {running ? <Pause size={13} /> : <Play size={13} />} {running ? '일시정지' : '시작'}
        </button>
        <button onClick={reset} className="flex items-center gap-1 text-xs px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg">
          <RotateCcw size={13} /> 리셋
        </button>
      </div>
    </div>
  )
}

function Scoreboard({ solved, totalCount }) {
  const solvedList = Object.values(solved).filter(Boolean)
  const done = solvedList.length === totalCount
  let totalElapsed = null
  if (done) {
    const times = solvedList.map(s => s.at)
    totalElapsed = ((Math.max(...times) - Math.min(...times)) / 1000).toFixed(1)
  }

  const rows = [
    { id: 'sqli', label: 'SQL Injection', icon: Database },
    { id: 'idor', label: 'IDOR', icon: LockOpen },
    { id: 'xss', label: 'Reflected XSS', icon: CodeXml },
  ]

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
      <p className="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><Trophy size={14} /> 스코어보드 ({solvedList.length}/{totalCount})</p>
      <div className="space-y-1.5">
        {rows.map(({ id, label, icon: Icon }) => {
          const s = solved[id]
          return (
            <div key={id} className="flex items-center gap-2 text-xs">
              {s ? <CheckCircle2 size={14} className="text-green-400 shrink-0" /> : <Icon size={14} className="text-slate-500 shrink-0" />}
              <span className={s ? 'text-slate-200' : 'text-slate-400'}>{label}</span>
              {s && <span className="ml-auto text-slate-500">{new Date(s.at).toLocaleTimeString()}</span>}
            </div>
          )
        })}
      </div>
      {done && (
        <div className="pt-2 border-t border-slate-700 text-xs text-emerald-400 font-semibold">
          🎉 전부 완료! 총 소요 시간: {totalElapsed}초
        </div>
      )}
    </div>
  )
}

function FlagSubmit({ challengeId, onSolved, alreadySolved }) {
  const [flag, setFlag] = useState('')
  const [result, setResult] = useState(null)
  const [checking, setChecking] = useState(false)

  const check = async () => {
    if (!flag.trim()) return
    setChecking(true)
    setResult(null)
    try {
      const res = await axios.post('/api/web-arena/verify', { challenge_id: challengeId, flag: flag.trim() })
      setResult(res.data.correct)
      if (res.data.correct) onSolved(challengeId)
    } catch {
      setResult(false)
    } finally {
      setChecking(false)
    }
  }

  if (alreadySolved) {
    return (
      <div className="text-xs text-green-400 flex items-center gap-1.5 bg-green-500/10 border border-green-500/25 rounded-lg p-2">
        <CheckCircle2 size={14} /> 이미 풀었습니다!
      </div>
    )
  }

  return (
    <div className="bg-slate-900/60 rounded-lg p-3 space-y-2">
      <p className="text-xs font-semibold text-slate-300 flex items-center gap-1"><KeyRound size={12} /> flag 제출</p>
      <div className="flex gap-2">
        <input
          value={flag}
          onChange={e => { setFlag(e.target.value); setResult(null) }}
          placeholder="예: WEB{...}"
          className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500"
        />
        <button
          onClick={check}
          disabled={checking || !flag.trim()}
          className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-xs font-semibold"
        >
          확인
        </button>
      </div>
      {result === true && <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 size={13} /> 정답입니다!</p>}
      {result === false && <p className="text-xs text-red-400 flex items-center gap-1"><XCircle size={13} /> 아직 아닙니다.</p>}
    </div>
  )
}

function HintList({ hints }) {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p className="text-xs font-semibold text-slate-300 mb-1.5">힌트 ({count}/{hints.length})</p>
      <ul className="space-y-1.5 mb-2">
        {hints.slice(0, count).map((h, i) => (
          <li key={i} className="text-xs text-slate-300 bg-black/20 rounded-lg p-2">💡 {h}</li>
        ))}
      </ul>
      {count < hints.length && (
        <button onClick={() => setCount(c => c + 1)} className="text-xs text-amber-400 hover:text-amber-300">
          힌트 {count + 1} 보기 →
        </button>
      )}
    </div>
  )
}

function SqliChallenge({ meta, solved, onSolved }) {
  const [username, setUsername] = useState("admin'--")
  const [password, setPassword] = useState('anything')
  const [resp, setResp] = useState(null)

  const submit = async () => {
    try {
      const res = await axios.post('/api/web-arena/sqli/login', { username, password })
      setResp(res.data)
    } catch (err) {
      setResp(err.response?.data ?? { error: String(err) })
    }
  }

  return (
    <div className="bg-violet-500/10 border border-violet-500/30 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2">
        <Database size={18} className="text-violet-400" />
        <span className="text-xs font-bold text-violet-400">{meta.difficulty}</span>
      </div>
      <p className="text-base font-bold text-slate-100">{meta.title}</p>
      <p className="text-xs text-slate-300">{meta.situation}</p>
      <p className="text-[11px] font-mono text-slate-500">{meta.endpoint}</p>

      <div className="grid sm:grid-cols-2 gap-2">
        <div>
          <label className="text-[11px] text-slate-400">username</label>
          <input value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-violet-500" />
        </div>
        <div>
          <label className="text-[11px] text-slate-400">password</label>
          <input value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-violet-500" />
        </div>
      </div>
      <button onClick={submit} className="w-full py-2 bg-violet-600 hover:bg-violet-700 rounded-lg text-xs font-semibold">로그인 시도</button>

      {resp && (
        <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">{JSON.stringify(resp, null, 2)}</pre>
      )}

      <HintList hints={meta.hints} />
      <FlagSubmit challengeId="sqli" onSolved={onSolved} alreadySolved={!!solved} />
    </div>
  )
}

function IdorChallenge({ meta, solved, onSolved }) {
  const [username, setUsername] = useState('guest')
  const [token, setToken] = useState('')
  const [orderId, setOrderId] = useState('1001')
  const [order, setOrder] = useState(null)
  const [loginResp, setLoginResp] = useState(null)

  const login = async () => {
    const res = await axios.post('/api/web-arena/idor/login', { username })
    setLoginResp(res.data)
    setToken(res.data.token)
  }

  const getOrder = async () => {
    try {
      const res = await axios.get(`/api/web-arena/idor/orders/${orderId}`, { headers: { Authorization: `Bearer ${token}` } })
      setOrder(res.data)
    } catch (err) {
      setOrder(err.response?.data ?? { error: String(err) })
    }
  }

  return (
    <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2">
        <LockOpen size={18} className="text-cyan-400" />
        <span className="text-xs font-bold text-cyan-400">{meta.difficulty}</span>
      </div>
      <p className="text-base font-bold text-slate-100">{meta.title}</p>
      <p className="text-xs text-slate-300">{meta.situation}</p>
      <p className="text-[11px] font-mono text-slate-500">{meta.endpoint}</p>

      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="text-[11px] text-slate-400">username</label>
          <input value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500" />
        </div>
        <button onClick={login} className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-800 rounded-lg text-xs font-semibold shrink-0">로그인</button>
      </div>
      {loginResp && <p className="text-[11px] font-mono text-slate-400 break-all">token: {loginResp.token}</p>}

      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="text-[11px] text-slate-400">order_id</label>
          <input value={orderId} onChange={e => setOrderId(e.target.value)} className="w-full bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-cyan-500" />
        </div>
        <button onClick={getOrder} disabled={!token} className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-xs font-semibold shrink-0">주문 조회</button>
      </div>

      {order && (
        <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">{JSON.stringify(order, null, 2)}</pre>
      )}

      <HintList hints={meta.hints} />
      <FlagSubmit challengeId="idor" onSolved={onSolved} alreadySolved={!!solved} />
    </div>
  )
}

function XssChallenge({ meta, solved, onSolved }) {
  const [q, setQ] = useState('<script>alert(1)</script>')
  const [html, setHtml] = useState('')

  const search = async () => {
    const res = await axios.get('/api/web-arena/xss/search', { params: { q } })
    setHtml(res.data)
  }

  return (
    <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2">
        <CodeXml size={18} className="text-amber-400" />
        <span className="text-xs font-bold text-amber-400">{meta.difficulty}</span>
      </div>
      <p className="text-base font-bold text-slate-100">{meta.title}</p>
      <p className="text-xs text-slate-300">{meta.situation}</p>
      <p className="text-[11px] font-mono text-slate-500">{meta.endpoint}</p>

      <div className="flex gap-2">
        <input value={q} onChange={e => setQ(e.target.value)} className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-amber-500" />
        <button onClick={search} className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 rounded-lg text-xs font-semibold shrink-0">검색</button>
      </div>

      {html && (
        <div>
          <p className="text-[11px] text-slate-500 mb-1 flex items-center gap-1">
            <AlertTriangle size={11} /> 안전을 위해 실제 렌더링 대신 응답 HTML 소스만 보여줍니다 (실제 브라우저라면 스크립트가 실행됩니다).
          </p>
          <pre className="bg-black/40 rounded-lg p-3 text-[11px] text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">{html}</pre>
        </div>
      )}

      <HintList hints={meta.hints} />
      <FlagSubmit challengeId="xss" onSolved={onSolved} alreadySolved={!!solved} />
    </div>
  )
}

export default function WebArena() {
  const [challenges, setChallenges] = useState([])
  const [solved, setSolved] = useState({})

  useEffect(() => {
    axios.get('/api/web-arena/challenges').then(res => setChallenges(res.data.challenges))
  }, [])

  const markSolved = (id) => {
    setSolved(s => (s[id] ? s : { ...s, [id]: { at: Date.now() } }))
  }

  const byId = Object.fromEntries(challenges.map(c => [c.id, c]))

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Swords className="text-rose-400" size={26} /> Web CTF 아레나
          </h1>
          <p className="text-slate-400 text-sm mt-1">실제로 살아있는 취약한 로컬 서버를 상대로 진짜 HTTP 요청을 보내 공격하는 실전 연습장입니다.</p>
        </div>

        <div className="bg-red-500/10 border border-red-500/25 rounded-lg p-3 text-xs text-red-300">
          이 서버는 로컬 개발 환경에서만 실행되는 연습용 취약 서비스입니다. 데이터는 메모리에만 있고 서버를 재시작하면 초기화됩니다. 이런 코드를 실제 서비스에 절대 배포하지 마세요.
        </div>

        <GuidePanel title="Web CTF 아레나 사용 가이드" steps={ARENA_STEPS} tips={ARENA_TIPS} />

        <div className="grid lg:grid-cols-4 gap-6">
          <div className="lg:col-span-3 space-y-5">
            {byId.sqli && <SqliChallenge meta={byId.sqli} solved={solved.sqli} onSolved={markSolved} />}
            {byId.idor && <IdorChallenge meta={byId.idor} solved={solved.idor} onSolved={markSolved} />}
            {byId.xss && <XssChallenge meta={byId.xss} solved={solved.xss} onSolved={markSolved} />}
          </div>
          <div className="space-y-4">
            <TimerCard />
            <Scoreboard solved={solved} totalCount={challenges.length || 3} />
          </div>
        </div>
      </div>
    </div>
  )
}
