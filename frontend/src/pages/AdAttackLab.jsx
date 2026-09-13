import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  Fingerprint, Radar, KeyRound, ShieldAlert, AlertTriangle, Download,
  CheckCircle2, XCircle, Send, Wrench, Check, Unlock, Database,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const LAB_STEPS = [
  '맨 위 RoE(참여 규칙) 고지를 읽습니다 — 이 랩은 로컬 시뮬레이션이며, 실제 도메인에는 승인 없이 절대 사용하면 안 됩니다.',
  '1단계에서 도메인 계정을 정찰합니다 — 먼저 query=all로 전체를 훑은 뒤 spn/preauth로 좁혀보세요.',
  '2단계에서 SPN이 있는 계정의 TGS 티켓을 요청하고, 워드리스트로 오프라인 크랙을 시도합니다.',
  '3단계(추가 실습)는 AS-REP Roasting을 연습합니다 — 최종 flag에는 필요 없지만 또 다른 AD 공격 기법입니다.',
  '4단계에서 크랙한 자격증명으로 DCSync를 시도해 도메인 전체 해시를 덤프하고 flag를 획득합니다.',
  '찾은 flag를 맨 아래 제출란에 입력해 정답을 확인합니다.',
]
const LAB_TIPS = [
  '이 랩은 실제 Kerberos 프로토콜(암호화 통신)을 구현하지 않습니다 — 대신 "취약한 속성을 가진 계정을 찾아 실제로 악용해야 진행되는" 판정 로직을 실제로 구현했습니다.',
  '실제 환경에서는 Impacket의 GetUserSPNs.py/secretsdump.py, hashcat 같은 도구로 이 과정을 수행합니다 — 각 단계 힌트에 실제 도구명을 함께 적어두었습니다.',
  '막히면 힌트를 하나씩 열어보세요.',
  '전체 과정을 자동화하는 Python 익스플로잇 템플릿을 다운로드할 수 있습니다.',
  '서비스 계정 비밀번호에 회사명+계절+연도 패턴을 쓰는 것은 실무에서도 매우 흔한 실수입니다 — 이 랩의 워드리스트도 그런 패턴으로 구성되어 있습니다.',
]

function StageCard({ stage, solved, children }) {
  const [hintCount, setHintCount] = useState(0)
  if (!stage) return null

  return (
    <div className={`bg-slate-800 border rounded-xl p-5 space-y-3 transition-colors ${solved ? 'border-green-600/50' : stage.optional ? 'border-amber-600/40' : 'border-slate-700'}`}>
      <div className="flex items-center gap-2">
        <h3 className="font-semibold">{stage.title}</h3>
        {stage.optional && (
          <span className="text-xs font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded-full px-2 py-0.5">추가 실습 (선택)</span>
        )}
        {solved && (
          <span className="ml-auto flex items-center gap-1 text-xs font-bold text-green-400 bg-green-500/10 border border-green-500/30 rounded-full px-2 py-0.5">
            <Check size={12} /> 성공
          </span>
        )}
      </div>
      {stage.meaning && <p className="text-xs text-slate-400"><span className="font-semibold text-slate-300">의미: </span>{stage.meaning}</p>}
      <p className="text-sm text-slate-300">{stage.situation}</p>
      <p className="text-xs text-slate-500 font-mono bg-slate-900/60 rounded p-2">{stage.endpoint}</p>

      {children}

      <div>
        <p className="text-xs font-semibold text-slate-400 mb-1.5">힌트 ({hintCount}/{stage.hints.length})</p>
        <ul className="space-y-1.5 mb-2">
          {stage.hints.slice(0, hintCount).map((h, i) => (
            <li key={i} className="text-xs text-slate-300 bg-black/20 rounded-lg p-2">💡 {h}</li>
          ))}
        </ul>
        {hintCount < stage.hints.length && (
          <button onClick={() => setHintCount(c => c + 1)} className="text-xs text-amber-400 hover:text-amber-300">
            힌트 {hintCount + 1} 보기 →
          </button>
        )}
      </div>

      {solved && stage.remediation && <RemediationBox remediation={stage.remediation} />}
    </div>
  )
}

function RemediationBox({ remediation }) {
  return (
    <div className="bg-green-500/5 border border-green-500/30 rounded-lg p-3 space-y-2">
      <p className="text-xs font-semibold text-green-400 flex items-center gap-1.5">
        <Wrench size={13} /> 이 취약점 해결 방법
      </p>
      <p className="text-xs text-slate-300">{remediation.summary}</p>
      {remediation.fixes?.length > 0 && (
        <ul className="space-y-1">
          {remediation.fixes.map((f, i) => (
            <li key={i} className="text-xs text-slate-300 flex gap-1.5">
              <span className="text-green-400 mt-0.5 shrink-0">•</span>{f}
            </li>
          ))}
        </ul>
      )}
      {remediation.code_example && (
        <pre className="text-[11px] bg-slate-950 border border-slate-700 rounded-lg p-2.5 overflow-x-auto text-slate-300 whitespace-pre">
          {remediation.code_example}
        </pre>
      )}
    </div>
  )
}

function ResponseBox({ response }) {
  if (response === null || response === undefined) return null
  return (
    <pre className="text-xs bg-slate-950 border border-slate-700 rounded-lg p-3 overflow-x-auto text-slate-300 whitespace-pre-wrap">
      {typeof response === 'string' ? response : JSON.stringify(response, null, 2)}
    </pre>
  )
}

function ProgressStepper({ steps }) {
  return (
    <div className="flex items-center gap-1.5">
      {steps.map((s, i) => (
        <div key={s.id} className="flex items-center gap-1.5 flex-1">
          <div className={`flex items-center gap-1.5 flex-1 rounded-lg px-3 py-2 text-xs font-medium border transition-colors ${
            s.solved ? 'bg-green-500/10 border-green-500/40 text-green-400' : 'bg-slate-800 border-slate-700 text-slate-500'
          }`}>
            {s.solved ? <Check size={13} /> : <span className="w-3.5 text-center">{i + 1}</span>}
            <span className="truncate">{s.label}</span>
          </div>
          {i < steps.length - 1 && <span className="text-slate-600 shrink-0">→</span>}
        </div>
      ))}
    </div>
  )
}

function downloadFile(blobData, filename) {
  const url = URL.createObjectURL(new Blob([blobData], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function stageById(stages, id) {
  return stages.find(s => s.id === id)
}

export default function AdAttackLab() {
  const [stages, setStages] = useState([])
  const [roe, setRoe] = useState('')
  const [domain, setDomain] = useState('CORP.LOCAL')

  const [reconQuery, setReconQuery] = useState('all')
  const [reconResult, setReconResult] = useState(null)

  const [spn, setSpn] = useState('MSSQLSvc/db01.corp.local:1433')
  const [ticket, setTicket] = useState(null)
  const [krbAccount, setKrbAccount] = useState('')
  const [krbPassword, setKrbPassword] = useState('')
  const [krbCrackResult, setKrbCrackResult] = useState(null)
  const [cracking, setCracking] = useState(false)

  const [asrepUsername, setAsrepUsername] = useState('svc_scan')
  const [asrepResult, setAsrepResult] = useState(null)
  const [asrepPassword, setAsrepPassword] = useState('')
  const [asrepCrackResult, setAsrepCrackResult] = useState(null)

  const [dcsyncUser, setDcsyncUser] = useState('')
  const [dcsyncPass, setDcsyncPass] = useState('')
  const [dcsyncResult, setDcsyncResult] = useState(null)

  const [flagInput, setFlagInput] = useState('')
  const [verifyResult, setVerifyResult] = useState(null)

  useEffect(() => {
    axios.get('/api/ad-attack-lab/stages').then(r => {
      setStages(r.data.stages)
      setRoe(r.data.roe)
      setDomain(r.data.domain)
    }).catch(() => {})
  }, [])

  const runRecon = async () => {
    try {
      const res = await axios.get('/api/ad-attack-lab/recon', { params: { query: reconQuery } })
      setReconResult(res.data.output)
    } catch (err) {
      setReconResult(err.response?.data?.detail ?? err.message)
    }
  }

  const runKerberoast = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/kerberoast', { spn })
      setTicket(res.data)
      if (res.data.account) setKrbAccount(res.data.account)
    } catch (err) {
      setTicket(err.response?.data ?? { error: err.message })
    }
  }

  const runCrack = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/crack', { account: krbAccount, password_guess: krbPassword })
      setKrbCrackResult(res.data)
      if (res.data.cracked) {
        setDcsyncUser(res.data.account)
        setDcsyncPass(res.data.password)
      }
    } catch (err) {
      setKrbCrackResult(err.response?.data ?? { error: err.message })
    }
  }

  const runAutoCrack = async () => {
    setCracking(true)
    try {
      const { data: wordlistText } = await axios.get('/api/ad-attack-lab/wordlist', { responseType: 'text' })
      const words = wordlistText.split('\n').map(w => w.trim()).filter(Boolean)
      for (const guess of words) {
        const res = await axios.post('/api/ad-attack-lab/crack', { account: krbAccount, password_guess: guess })
        if (res.data.cracked) {
          setKrbCrackResult(res.data)
          setKrbPassword(guess)
          setDcsyncUser(res.data.account)
          setDcsyncPass(res.data.password)
          setCracking(false)
          return
        }
      }
      setKrbCrackResult({ cracked: false, note: '워드리스트 안에서 찾지 못했습니다.' })
    } finally {
      setCracking(false)
    }
  }

  const runAsrep = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/asrep-roast', { username: asrepUsername })
      setAsrepResult(res.data)
    } catch (err) {
      setAsrepResult(err.response?.data ?? { error: err.message })
    }
  }

  const runAsrepCrack = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/crack', { account: asrepUsername, password_guess: asrepPassword })
      setAsrepCrackResult(res.data)
    } catch (err) {
      setAsrepCrackResult(err.response?.data ?? { error: err.message })
    }
  }

  const runDcsync = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/dcsync', { username: dcsyncUser, password: dcsyncPass })
      setDcsyncResult(res.data)
      if (res.data.flag) setFlagInput(res.data.flag)
    } catch (err) {
      setDcsyncResult(err.response?.data ?? { error: err.message })
    }
  }

  const submitFlag = async () => {
    try {
      const res = await axios.post('/api/ad-attack-lab/verify', { flag: flagInput })
      setVerifyResult(res.data.correct)
    } catch {
      setVerifyResult(false)
    }
  }

  const runDownloadTemplate = async () => {
    try {
      const res = await axios.get('/api/ad-attack-lab/exploit-template', { responseType: 'blob' })
      downloadFile(res.data, 'ad_attack_lab_exploit.py')
    } catch {
      alert('템플릿 다운로드 실패')
    }
  }

  const runDownloadWordlist = async () => {
    try {
      const res = await axios.get('/api/ad-attack-lab/wordlist', { responseType: 'blob' })
      downloadFile(res.data, 'ad_wordlist.txt')
    } catch {
      alert('워드리스트 다운로드 실패')
    }
  }

  const reconSolved = !!reconResult && reconQuery !== ''
  const kerberoastSolved = !!krbCrackResult?.cracked
  const asrepSolved = !!asrepCrackResult?.cracked
  const dcsyncSolved = !!dcsyncResult?.flag

  const progressSteps = [
    { id: 'recon', label: '정찰', solved: reconSolved },
    { id: 'kerberoast', label: 'Kerberoasting', solved: kerberoastSolved },
    { id: 'dcsync', label: 'DCSync', solved: dcsyncSolved },
  ]

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-5xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Fingerprint className="text-violet-400" size={26} /> AD/Kerberos 공격 실습
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            가상 Active Directory 도메인({domain})을 대상으로 Kerberoasting → (선택) AS-REP Roasting → DCSync 권한 오용까지,
            실제 기업 침해사고에서 가장 흔한 AD 공격 흐름을 처음부터 끝까지 실습합니다.
          </p>
        </div>

        <GuidePanel title="AD/Kerberos 공격 실습 사용 가이드" steps={LAB_STEPS} tips={LAB_TIPS} />

        {roe && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex gap-2.5">
            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-200">{roe}</p>
          </div>
        )}

        <ProgressStepper steps={progressSteps} />

        <div className="flex gap-2 flex-wrap">
          <button onClick={runDownloadWordlist} className="flex items-center gap-1.5 text-xs bg-slate-700 text-slate-300 border border-slate-600 rounded-lg px-3 py-1.5 hover:bg-slate-600">
            <Download size={13} /> 워드리스트 다운로드 (wordlist.txt)
          </button>
          <button onClick={runDownloadTemplate} className="flex items-center gap-1.5 text-xs bg-violet-600/20 text-violet-300 border border-violet-600/40 rounded-lg px-3 py-1.5 hover:bg-violet-600/30">
            <Download size={13} /> 익스플로잇 템플릿 다운로드 (Python)
          </button>
        </div>

        <StageCard stage={stageById(stages, 'recon')} solved={reconSolved}>
          <div className="flex gap-2">
            <select
              value={reconQuery}
              onChange={e => setReconQuery(e.target.value)}
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-violet-500"
            >
              <option value="all">all (전체 계정)</option>
              <option value="spn">spn (Kerberoasting 대상)</option>
              <option value="preauth">preauth (AS-REP Roasting 대상)</option>
            </select>
            <button onClick={runRecon} className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">
              <Radar size={14} /> 조회
            </button>
          </div>
          <ResponseBox response={reconResult} />
        </StageCard>

        <StageCard stage={stageById(stages, 'kerberoast')} solved={kerberoastSolved}>
          <div className="space-y-2">
            <div className="flex gap-2">
              <input
                value={spn}
                onChange={e => setSpn(e.target.value)}
                placeholder="MSSQLSvc/db01.corp.local:1433"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-violet-500"
              />
              <button onClick={runKerberoast} className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">
                <Send size={14} /> TGS 요청
              </button>
            </div>
            <ResponseBox response={ticket} />
            {ticket?.account && (
              <div className="flex gap-2 pt-1">
                <input
                  value={krbAccount}
                  onChange={e => setKrbAccount(e.target.value)}
                  placeholder="account"
                  className="w-40 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-violet-500"
                />
                <input
                  value={krbPassword}
                  onChange={e => setKrbPassword(e.target.value)}
                  placeholder="비밀번호 추측값"
                  className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-violet-500"
                />
                <button onClick={runCrack} className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">
                  <KeyRound size={14} /> 크랙 시도
                </button>
                <button onClick={runAutoCrack} disabled={cracking} className="flex items-center gap-1.5 px-3 py-2 bg-violet-600 hover:bg-violet-700 disabled:bg-slate-700 rounded-lg text-sm font-medium">
                  <Unlock size={14} /> {cracking ? '크랙 중...' : '워드리스트로 자동 크랙'}
                </button>
              </div>
            )}
            <ResponseBox response={krbCrackResult} />
          </div>
        </StageCard>

        <StageCard stage={stageById(stages, 'asrep_roast')} solved={asrepSolved}>
          <div className="space-y-2">
            <div className="flex gap-2">
              <input
                value={asrepUsername}
                onChange={e => setAsrepUsername(e.target.value)}
                placeholder="svc_scan"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-amber-500"
              />
              <button onClick={runAsrep} className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">
                <Send size={14} /> AS-REP 요청
              </button>
            </div>
            <ResponseBox response={asrepResult} />
            {asrepResult?.as_rep_hash && (
              <div className="flex gap-2 pt-1">
                <input
                  value={asrepPassword}
                  onChange={e => setAsrepPassword(e.target.value)}
                  placeholder="비밀번호 추측값 (예: Winter2022!)"
                  className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-amber-500"
                />
                <button onClick={runAsrepCrack} className="flex items-center gap-1.5 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm">
                  <KeyRound size={14} /> 크랙 시도
                </button>
              </div>
            )}
            <ResponseBox response={asrepCrackResult} />
          </div>
        </StageCard>

        <StageCard stage={stageById(stages, 'dcsync')} solved={dcsyncSolved}>
          <div className="space-y-2">
            <div className="flex gap-2">
              <input
                value={dcsyncUser}
                onChange={e => setDcsyncUser(e.target.value)}
                placeholder="username (크랙 성공 시 자동 입력)"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-rose-500"
              />
              <input
                value={dcsyncPass}
                onChange={e => setDcsyncPass(e.target.value)}
                placeholder="password"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-rose-500"
              />
              <button onClick={runDcsync} className="flex items-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-700 rounded-lg text-sm font-medium">
                <Database size={14} /> DCSync 실행
              </button>
            </div>
            <ResponseBox response={dcsyncResult} />
          </div>
        </StageCard>

        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <p className="text-sm font-semibold mb-2 flex items-center gap-1.5"><ShieldAlert size={15} className="text-violet-400" /> 최종 flag 제출</p>
          <div className="flex gap-2">
            <input
              value={flagInput}
              onChange={e => { setFlagInput(e.target.value); setVerifyResult(null) }}
              placeholder="AD{...}"
              className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-violet-500"
            />
            <button onClick={submitFlag} disabled={!flagInput.trim()} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-medium">
              제출
            </button>
          </div>
          {verifyResult === true && (
            <p className="mt-2 text-sm text-green-400 flex items-center gap-1.5"><CheckCircle2 size={15} /> 정답입니다! 도메인 전체 권한 장악까지 성공했습니다.</p>
          )}
          {verifyResult === false && (
            <p className="mt-2 text-sm text-red-400 flex items-center gap-1.5"><XCircle size={15} /> 아직 정답이 아닙니다.</p>
          )}
        </div>
      </div>
    </div>
  )
}
