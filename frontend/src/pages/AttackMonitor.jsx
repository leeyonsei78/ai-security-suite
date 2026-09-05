import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  Radar, Radio, Play, Square, Send, RefreshCw, ExternalLink,
  ShieldAlert, ShieldCheck, Wifi, Bug, Lock, Cloud, Server, WifiOff, FlaskConical,
  ChevronDown, ChevronUp, CheckCircle2, XCircle, Loader2, MonitorCog,
} from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'
import GuidePanel from '../components/GuidePanel'
import StatCard from '../components/StatCard'
import CopyButton from '../components/CopyButton'

const MODE_BADGE = {
  cloud:   { icon: Cloud,        label: 'Claude Cloud', color: 'text-green-400' },
  local:   { icon: Server,       label: '로컬 LLM',      color: 'text-blue-400' },
  offline: { icon: WifiOff,      label: '오프라인 규칙 기반', color: 'text-amber-400' },
  mock:    { icon: FlaskConical, label: 'Mock 데모',      color: 'text-slate-400' },
}

const STEPS = [
  '["노출 현황 점검" 패널의 [지금 점검] 버튼을 눌러 이 PC의 현재 상태(방화벽 로깅/RDP/최근 로그온 실패/전체 인터페이스에 열린 포트/Defender)를 확인합니다.',
  '"실제 시스템 모니터링" 탭에서 [모니터링 시작]을 누르면 20초마다 실제 Windows 보안 신호(로그온 실패·Defender 탐지·신규 포트)를 조회해 AI가 분석합니다.',
  '"AWS 활동 모니터링" 탭은 test-range의 무료 LocalStack 샌드박스를 대상으로, IAM 정책/보안그룹 등에 위험한 변경(와일드카드 권한, 0.0.0.0/0 전체공개)이 생기면 15초마다 탐지합니다.',
  '"시뮬레이션" 탭은 실제 시스템 대신 합성 공격 로그로 데모를 보여줍니다 — 이벤트를 직접 주입해 AI 분류를 시험해볼 수 있습니다.',
  'CRITICAL/HIGH로 판정된 이벤트 카드에는 "대응 제안" 박스가 함께 표시됩니다 — 제안된 명령은 자동 실행되지 않으니 확인 후 직접 실행하세요.',
  '실제 시스템 모드에서 CRITICAL 판정이 나오면 알림 시스템(🔔)에도 자동으로 기록/전송됩니다. 시뮬레이션(데모) 결과는 알림을 트리거하지 않습니다.',
]
const TIPS = [
  '방화벽 연결 로깅은 관리자 권한이 있어야 켤 수 있습니다 — 꺼져 있으면 노출 현황 점검 결과에 켜는 명령이 함께 안내됩니다.',
  'Mock 모드에서는 실제 신호 내용과 무관하게 샘플 위협이 무작위로 표시될 수 있습니다 — "수집된 원본 신호"를 펼쳐 실제로 무엇이 관찰됐는지 함께 확인하세요.',
  '이 앱은 Windows 전용입니다 (PowerShell로 이벤트 로그·방화벽·Defender·리스닝 포트를 조회).',
  '대응 제안의 명령어는 참고용입니다 — 절대 자동 실행되지 않으며, 반드시 대상을 직접 확인한 뒤 관리자 권한 PowerShell에서 수동으로 실행하세요.',
]

function ResponseBox({ response }) {
  if (!response) return null
  return (
    <div className="mt-2 bg-slate-900/60 border border-slate-700 rounded-lg p-3 space-y-2">
      <div className="flex items-center gap-2">
        <ShieldCheck size={13} className="text-emerald-400 shrink-0" />
        <span className="text-xs font-semibold text-emerald-400">대응 제안: {response.action_label}</span>
        <a href={response.related_link} className="ml-auto flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 shrink-0">
          {response.related_label} <ExternalLink size={10} />
        </a>
      </div>
      <p className="text-xs text-slate-400">{response.rationale}</p>
      {response.suggested_command && (
        <div className="flex items-start gap-2 bg-black/40 rounded p-2">
          <code className="text-[11px] text-amber-300 font-mono flex-1 break-all">{response.suggested_command}</code>
          <CopyButton text={response.suggested_command} />
        </div>
      )}
      <p className="text-[10px] text-slate-500">{response.note}</p>
    </div>
  )
}

function EventCard({ ev }) {
  return (
    <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
      <div className="flex items-center gap-2 mb-2">
        <SeverityBadge severity={ev.threat_level} />
        <span className="text-xs text-slate-500">{ev.events?.length ?? 0}개 이벤트</span>
        {ev.mode && (() => {
          const cfg = MODE_BADGE[ev.mode] ?? MODE_BADGE.offline
          const Icon = cfg.icon
          return (
            <span className={`flex items-center gap-1 text-[10px] font-semibold ${cfg.color}`}>
              <Icon size={11} /> {cfg.label}
            </span>
          )
        })()}
        {ev.target_host && (
          <span className="flex items-center gap-1 text-[10px] font-semibold text-cyan-400">
            <Server size={10} /> {ev.target_host}
          </span>
        )}
        <span className="ml-auto text-xs text-slate-500">{new Date().toLocaleTimeString('ko-KR')}</span>
      </div>
      <p className="text-sm text-slate-300">{ev.summary}</p>
      {ev.fallback_reason && <p className="text-xs text-amber-400 mt-1">{ev.fallback_reason}</p>}
      {ev.engine_note && <p className="text-[10px] text-slate-500 mt-1 italic">{ev.engine_note}</p>}
      {ev.events?.length > 0 && (
        <div className="mt-3 space-y-3">
          {ev.events.map((e, j) => (
            <div key={j} className="border-t border-slate-700/60 pt-2 first:border-0 first:pt-0">
              <div className="flex flex-wrap items-start gap-2 text-xs">
                <SeverityBadge severity={e.severity} />
                <span className="text-slate-300 font-medium">{e.category}</span>
                {e.source_ip && <span className="font-mono text-slate-500">{e.source_ip}</span>}
              </div>
              <p className="text-xs text-slate-400 mt-1">{e.description}</p>
              <p className="text-[11px] text-slate-500 mt-1">AI 권장 조치: {e.remediation}</p>
              {(e.severity === 'CRITICAL' || e.severity === 'HIGH') && <ResponseBox response={e.response} />}
            </div>
          ))}
        </div>
      )}
      <details className="mt-3">
        <summary className="text-[11px] text-slate-500 cursor-pointer hover:text-slate-300">수집된 원본 신호 보기</summary>
        <pre className="mt-1 text-[10px] text-slate-500 bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap">{ev.raw_log}</pre>
      </details>
    </div>
  )
}

function LiveFeed({ mode, isMock, target }) {
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState([])
  const [injectText, setInjectText] = useState('')
  const wsRef = useRef(null)
  const intervalRef = useRef(mode === 'real' ? 20 : mode === 'aws' ? 15 : 8)

  const start = () => {
    if (wsRef.current) return
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/attack-monitor/ws?mode=${mode}`)
    ws.onopen = () => setConnected(true)
    ws.onclose = () => { setConnected(false); wsRef.current = null }
    ws.onerror = () => setConnected(false)
    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data)
      if (data.type === 'connected') {
        intervalRef.current = data.interval_seconds
        if (mode === 'real') ws.send(JSON.stringify({ type: 'set_target', target: target || null }))
        return
      }
      if (data.type !== 'event') return
      setEvents(prev => [data, ...prev].slice(0, 20))
    }
    wsRef.current = ws
  }

  const stop = () => {
    wsRef.current?.close()
    wsRef.current = null
    setConnected(false)
  }

  const sendInjectedLine = () => {
    if (!injectText.trim() || wsRef.current?.readyState !== WebSocket.OPEN) return
    wsRef.current.send(JSON.stringify({ type: 'inject', line: injectText.trim() }))
    setInjectText('')
  }

  useEffect(() => () => { wsRef.current?.close() }, [])

  return (
    <div className="space-y-4">
      <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Radio size={18} className={connected ? 'text-red-400' : 'text-slate-500'} />
          <span className="text-sm font-medium">
            {connected ? `모니터링 중 — ${intervalRef.current}초마다 자동 분석` : '모니터링 중지됨'}
          </span>
          {connected && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
        </div>
        <button
          onClick={connected ? stop : start}
          className={`ml-auto flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            connected ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
          }`}
        >
          {connected ? <><Square size={14} /> 모니터링 중지</> : <><Play size={14} /> 모니터링 시작</>}
        </button>
      </div>

      {(mode === 'real' || mode === 'aws') && isMock && (
        <p className="text-xs text-amber-400 bg-amber-950/30 border border-amber-500/20 rounded-lg px-3 py-2">
          Mock 모드입니다 — 실제 수집된 신호와 무관하게 샘플 위협이 무작위로 표시될 수 있습니다. 각 카드의 "수집된 원본 신호 보기"로 실제 관찰된 내용을 함께 확인하세요.
        </p>
      )}

      {mode === 'aws' && (
        <p className="text-xs text-cyan-300 bg-cyan-950/20 border border-cyan-500/20 rounded-lg px-3 py-2">
          이 탭은 실제 AWS CloudTrail이 아니라, test-range의 무료 LocalStack 샌드박스 컨테이너
          자체의 요청 로그를 신호원으로 씁니다 — IAM 정책/보안그룹 등을 실제로 바꿔보면(예:
          지난번에 안내한 <code className="font-mono">authorize-security-group-ingress</code> 명령)
          다음 주기에 여기 반영됩니다.
        </p>
      )}

      {mode === 'simulate' && (
        <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
          <p className="text-xs font-semibold text-slate-400 mb-2">이벤트 주입 (다음 분석 주기에 포함됨, 데모 전용)</p>
          <div className="flex gap-2">
            <input
              value={injectText}
              onChange={e => setInjectText(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && sendInjectedLine()}
              placeholder='예: sshd: Failed password for root from 1.2.3.4 port 22 ssh2'
              disabled={!connected}
              className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 disabled:opacity-50"
            />
            <button
              onClick={sendInjectedLine}
              disabled={!connected || !injectText.trim()}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-40 rounded-lg text-sm"
            >
              <Send size={14} /> 전송
            </button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {events.length === 0 && (
          <p className="text-slate-500 text-center py-12">
            {connected ? '첫 분석 주기를 기다리는 중...' : '[모니터링 시작]을 누르면 실시간 피드가 여기 표시됩니다.'}
          </p>
        )}
        {events.map((ev, i) => <EventCard key={i} ev={ev} />)}
      </div>
    </div>
  )
}

function TargetSelector({ target, setTarget }) {
  const [scope, setScope] = useState(target ? 'remote' : 'local')
  const [host, setHost] = useState(target?.host ?? '')
  const [authMode, setAuthMode] = useState('current') // 'current' | 'credentials'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [guideOpen, setGuideOpen] = useState(false)

  const buildTarget = () => {
    if (scope === 'local' || !host.trim()) return null
    if (authMode === 'credentials' && username.trim() && password) {
      return { host: host.trim(), username: username.trim(), password }
    }
    return { host: host.trim() }
  }

  useEffect(() => {
    setTarget(buildTarget())
    setTestResult(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, host, authMode, username, password])

  const testConnection = async () => {
    const t = buildTarget()
    if (!t) { alert('대상 호스트명 또는 IP를 입력하세요.'); return }
    setTesting(true)
    setTestResult(null)
    try {
      const res = await axios.post('/api/attack-monitor/check-remote', { target: t })
      setTestResult(res.data)
    } catch (err) {
      setTestResult({ ok: false, message: err.response?.data?.detail ?? err.message })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 space-y-3">
      <div className="flex items-center gap-2">
        <MonitorCog size={15} className="text-blue-400" />
        <h3 className="text-sm font-semibold">모니터링 대상</h3>
      </div>

      <div className="flex gap-2">
        <button
          onClick={() => setScope('local')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${scope === 'local' ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
        >
          이 PC (로컬)
        </button>
        <button
          onClick={() => setScope('remote')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${scope === 'remote' ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
        >
          원격 PC 지정
        </button>
      </div>

      {scope === 'remote' && (
        <div className="space-y-3 pt-3 border-t border-slate-700">
          <div>
            <p className="text-xs text-slate-400 mb-1">대상 호스트명 또는 IP</p>
            <input
              value={host}
              onChange={e => setHost(e.target.value)}
              placeholder="예: 192.168.0.50 또는 SERVER01"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 placeholder-slate-600"
            />
          </div>

          <div className="flex flex-wrap gap-4 text-xs text-slate-300">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="radio" checked={authMode === 'current'} onChange={() => setAuthMode('current')} />
              현재 로그인 계정 사용 (통합 인증, 같은 도메인일 때 권장)
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="radio" checked={authMode === 'credentials'} onChange={() => setAuthMode('credentials')} />
              사용자 이름/비밀번호 직접 입력
            </label>
          </div>

          {authMode === 'credentials' && (
            <div className="grid grid-cols-2 gap-2">
              <input
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="사용자 이름 (예: DOMAIN\user 또는 .\user)"
                className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 placeholder-slate-600"
              />
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="비밀번호"
                autoComplete="new-password"
                className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 placeholder-slate-600"
              />
            </div>
          )}

          <p className="text-[10.5px] text-amber-400">
            입력한 자격증명은 서버에 저장되지 않으며, 이 화면에서 요청할 때만 사용된 뒤 즉시 버려집니다.
          </p>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={testConnection}
              disabled={testing || !host.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-lg text-xs font-medium"
            >
              {testing ? <Loader2 size={12} className="animate-spin" /> : <Wifi size={12} />}
              {testing ? '연결 확인 중...' : '연결 테스트'}
            </button>
            {testResult && (
              <span className={`flex items-center gap-1 text-xs font-semibold ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                {testResult.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                {testResult.ok ? '연결 성공' : '연결 실패'}
              </span>
            )}
          </div>
          {testResult && (
            <p className={`text-xs rounded-lg p-2 ${testResult.ok ? 'text-emerald-300 bg-emerald-950/30 border border-emerald-500/30' : 'text-red-300 bg-red-950/30 border border-red-500/30'}`}>
              {testResult.message}
            </p>
          )}

          <button onClick={() => setGuideOpen(o => !o)} className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300">
            {guideOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            사전 준비 — 대상 PC에서 원격 관리를 켜는 법
          </button>
          {guideOpen && (
            <div className="bg-slate-900/60 rounded-lg p-3 space-y-3 text-xs text-slate-400">
              <div>
                <p className="mb-1">1. <b className="text-slate-300">대상 PC</b>에서 관리자 권한 PowerShell을 열고 실행:</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-slate-950 rounded p-2 font-mono text-amber-300 text-[11px]">Enable-PSRemoting -Force</code>
                  <CopyButton text="Enable-PSRemoting -Force" />
                </div>
              </div>
              <div>
                <p className="mb-1">2. 같은 도메인이 아닌 워크그룹 환경이라면, <b className="text-slate-300">이 PC(백엔드 실행 PC)</b>에서도 관리자 권한으로 대상을 신뢰 목록에 추가:</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-slate-950 rounded p-2 font-mono text-amber-300 text-[11px] break-all">Set-Item WSMan:\localhost\Client\TrustedHosts -Value '{host || "대상IP"}' -Force</code>
                  <CopyButton text={`Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '${host || '대상IP'}' -Force`} />
                </div>
              </div>
              <p>3. 두 PC가 같은 네트워크에서 서로 접근 가능해야 하고, 대상 PC 방화벽에서 WinRM(TCP 5985) 인바운드가 허용돼 있어야 합니다(Enable-PSRemoting이 보통 자동으로 규칙을 추가합니다).</p>
              <p>4. 위 입력창에 대상 호스트명/IP를 넣고 인증 방식(현재 로그인 계정 또는 사용자 이름/비밀번호)을 선택한 뒤 <b className="text-slate-300">[연결 테스트]</b>를 눌러 "연결 성공"이 뜨는지 확인하세요. 실패하면 메시지가 WinRM 미설정인지 인증 오류인지 구분해서 알려줍니다.</p>
              <p>5. 연결에 성공하면 바로 아래 <b className="text-slate-300">"노출 현황 점검"</b> 패널이 자동으로 이 원격 PC를 점검하고, <b className="text-slate-300">"실제 시스템 모니터링"</b> 탭에서 [모니터링 시작]을 누르면 이 PC 대신 원격 PC의 로그온 실패·Defender 탐지·신규 포트를 20초마다 분석합니다.</p>
              <p className="text-slate-500 italic">테스트용 두 번째 PC 없이 이 기능을 만들어 실제 원격 대상으로는 검증하지 못했습니다 — 진행 중 막히면 연결 테스트의 에러 메시지를 확인해주세요.</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function AwsConnectionCheck() {
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState(null)

  const test = async () => {
    setTesting(true)
    setResult(null)
    try {
      const res = await axios.post('/api/attack-monitor/check-aws')
      setResult(res.data)
    } catch (err) {
      setResult({ ok: false, message: err.response?.data?.detail ?? err.message })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 space-y-2">
      <div className="flex items-center gap-2">
        <Cloud size={15} className="text-cyan-400" />
        <h3 className="text-sm font-semibold">AWS 샌드박스 연결 확인</h3>
        <button
          onClick={test}
          disabled={testing}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-lg text-xs font-medium"
        >
          {testing ? <Loader2 size={12} className="animate-spin" /> : <Wifi size={12} />}
          {testing ? '확인 중...' : '연결 테스트'}
        </button>
      </div>
      <p className="text-xs text-slate-500">
        test-range의 <code className="font-mono">test-range-localstack</code> 컨테이너를 대상으로
        합니다 — 설정 없이 바로 동작하며, 컨테이너가 꺼져 있으면 아래에서 확인할 수 있습니다.
      </p>
      {result && (
        <p className={`text-xs rounded-lg p-2 flex items-start gap-1.5 ${result.ok ? 'text-emerald-300 bg-emerald-950/30 border border-emerald-500/30' : 'text-red-300 bg-red-950/30 border border-red-500/30'}`}>
          {result.ok ? <CheckCircle2 size={13} className="shrink-0 mt-0.5" /> : <XCircle size={13} className="shrink-0 mt-0.5" />}
          {result.message}
        </p>
      )}
    </div>
  )
}

function ExposurePanel({ target }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  const check = async () => {
    setLoading(true)
    try {
      const res = target
        ? await axios.post('/api/attack-monitor/exposure', { target })
        : await axios.get('/api/attack-monitor/exposure')
      setData(res.data)
    } catch (err) {
      alert('점검 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { check() }, [target])

  const levelColor = { CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-blue-400', INFO: 'text-slate-400' }

  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <div className="flex items-center gap-2 mb-4">
        <Wifi size={16} className="text-blue-400" />
        <h2 className="font-semibold text-sm">노출 현황 점검 — {target ? `${target.host}(원격)` : '이 PC'}의 실제 현재 상태</h2>
        <button
          onClick={check}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs disabled:opacity-50"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> {loading ? '점검 중...' : '지금 점검'}
        </button>
      </div>

      {!data ? (
        <p className="text-slate-500 text-sm">점검 중...</p>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard
              label="방화벽 로깅"
              value={data.firewall_logging_enabled ? 'ON' : 'OFF'}
              color={data.firewall_logging_enabled ? 'border-emerald-600' : 'border-amber-500'}
              hint={
                data.firewall_logging_enabled
                  ? '방화벽이 허용·차단한 연결 기록을 남기는 기능입니다. 켜져 있어 정상 — 나중에 공격 흔적을 추적할 수 있습니다.'
                  : '방화벽이 허용·차단한 연결 기록을 남기는 기능입니다. 꺼져 있어 주의 — 침해사고가 나도 흔적을 확인하기 어렵습니다.'
              }
            />
            <StatCard
              label="RDP"
              value={data.rdp_enabled ? '활성화' : '비활성화'}
              color={data.rdp_enabled ? 'border-orange-500' : 'border-emerald-600'}
              hint={
                data.rdp_enabled
                  ? '외부에서 이 PC를 원격으로 조작할 수 있게 하는 기능입니다. 켜져 있어 주의 — 무차별 대입(비밀번호 추측) 공격의 흔한 표적입니다. 쓰지 않는다면 끄세요.'
                  : '외부에서 이 PC를 원격으로 조작할 수 있게 하는 기능입니다. 꺼져 있어 정상 — 흔한 공격 경로 하나가 차단된 상태입니다.'
              }
            />
            <StatCard
              label="24h 로그온 실패"
              value={data.failed_logon_24h}
              color={data.failed_logon_24h > 0 ? 'border-orange-500' : 'border-emerald-600'}
              hint={
                data.failed_logon_24h > 0
                  ? '최근 24시간 동안 로그인에 실패한 횟수입니다. 숫자가 있어 주의 — 특히 짧은 시간에 여러 번이면 비밀번호를 추측하는 공격(무차별 대입)일 수 있습니다.'
                  : '최근 24시간 동안 로그인에 실패한 횟수입니다. 0건으로 정상 — 의심스러운 로그인 시도가 관측되지 않았습니다.'
              }
            />
            <StatCard
              label="전체 인터페이스 노출 포트"
              value={data.exposed_listeners?.length ?? 0}
              color="border-slate-600"
              hint="0.0.0.0 등 모든 네트워크 인터페이스에 열려 있어 외부(같은 네트워크의 다른 기기 등)에서 접근 가능한 포트 개수입니다. 숫자가 많다고 무조건 위험한 건 아니며 — 방화벽이 실제로 막고 있는지, 각 포트가 정말 필요한 서비스인지가 더 중요합니다."
            />
          </div>

          <div className="space-y-1.5">
            {data.notes?.map((n, i) => (
              <div key={i} className="text-xs bg-slate-900/60 rounded-lg p-2.5">
                <span className={`font-bold mr-1.5 ${levelColor[n.level] ?? 'text-slate-400'}`}>[{n.level}]</span>
                <span className="text-slate-300">{n.text}</span>
                {n.command && (
                  <div className="flex items-start gap-2 bg-black/40 rounded mt-1.5 p-2">
                    <code className="text-[11px] text-amber-300 font-mono flex-1 break-all">{n.command}</code>
                    <CopyButton text={n.command} />
                  </div>
                )}
              </div>
            ))}
          </div>

          <details>
            <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-300">
              0.0.0.0 / ::(모든 인터페이스)에 열려 있는 포트 {data.exposed_listeners?.length ?? 0}개 전체 보기
            </summary>
            <div className="mt-2 max-h-48 overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="text-slate-500"><tr><th className="text-left py-1">주소</th><th className="text-left py-1">포트</th><th className="text-left py-1">프로세스</th></tr></thead>
                <tbody>
                  {data.exposed_listeners?.map((l, i) => (
                    <tr key={i} className="border-t border-slate-700/50">
                      <td className="py-1 font-mono text-slate-400">{l.address}</td>
                      <td className="py-1 font-mono text-slate-400">{l.port}</td>
                      <td className="py-1 text-slate-400">{l.process}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>

          <p className="text-[10px] text-slate-500">마지막 점검: {new Date(data.checked_at).toLocaleString('ko-KR')} · 방화벽 인바운드 규칙이 실제로 이 포트들을 막고 있는지는 <a href="/firewall-audit" className="text-blue-400 hover:underline">방화벽 정책 감사기</a>로 별도 확인하세요.</p>
        </div>
      )}
    </div>
  )
}

export default function AttackMonitor() {
  const [activeTab, setActiveTab] = useState('real')
  const [isMock, setIsMock] = useState(true)
  const [target, setTarget] = useState(null)

  useEffect(() => {
    axios.get('/api/mode').then(r => setIsMock(r.data.effective_mode === 'mock')).catch(() => setIsMock(true))
  }, [])

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      <header className="border-b border-slate-700 px-6 py-3">
        <div className="flex items-center gap-2">
          <Radar size={20} className="text-blue-400" />
          <h1 className="text-base font-semibold">실시간 공격 모니터링 & 대응 센터</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">이 PC의 실제 보안 신호를 지속적으로 확인하고, 탐지 시 구체적인 대응 방법을 제안합니다.</p>
      </header>

      <div className="p-6 space-y-6">
        <GuidePanel title="실시간 공격 모니터링 & 대응 센터 사용 가이드" steps={STEPS} tips={TIPS} />

        <TargetSelector target={target} setTarget={setTarget} />

        <ExposurePanel target={target} />

        <div className="flex gap-2 border-b border-slate-700">
          {[
            { key: 'real', label: '실제 시스템 모니터링', icon: ShieldAlert },
            { key: 'aws', label: 'AWS 활동 모니터링', icon: Cloud },
            { key: 'simulate', label: '시뮬레이션 (데모)', icon: Bug },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-4 py-2 text-sm font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === key ? 'border-b-2 border-blue-400 text-blue-400' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon size={14} /> {label}
            </button>
          ))}
        </div>

        {activeTab === 'real' && (
          <div>
            <p className="text-xs text-slate-500 mb-3 flex items-center gap-1.5"><Lock size={11} /> 이 탭에서 CRITICAL 판정이 나오면 알림 시스템(🔔)에 실제로 기록/전송됩니다.</p>
            <LiveFeed mode="real" isMock={isMock} target={target} />
          </div>
        )}
        {activeTab === 'aws' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-500 flex items-center gap-1.5"><Lock size={11} /> 이 탭에서 CRITICAL 판정이 나오면 알림 시스템(🔔)에도 실제로 기록/전송됩니다(샌드박스 안의 진짜 활동이라 시뮬레이션과 다르게 취급).</p>
            <AwsConnectionCheck />
            <LiveFeed mode="aws" isMock={isMock} />
          </div>
        )}
        {activeTab === 'simulate' && (
          <div>
            <p className="text-xs text-slate-500 mb-3">데모용 합성 로그입니다 — 실제 시스템 신호가 아니며, 알림을 트리거하지 않습니다.</p>
            <LiveFeed mode="simulate" isMock={isMock} />
          </div>
        )}
      </div>
    </div>
  )
}
