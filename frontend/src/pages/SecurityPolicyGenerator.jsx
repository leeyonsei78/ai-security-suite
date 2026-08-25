import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  ScrollText, Server, Cloud, Network, Boxes, Database, ListOrdered,
  ClipboardCheck, ShieldCheck, AlertTriangle, Trash2, Download, BadgeCheck, Terminal,
} from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const POLICY_STEPS = [
  "'환경 유형'에서 정책을 생성할 대상을 선택합니다 (웹 서버 / 클라우드 / 사내 네트워크 / 컨테이너 / 데이터베이스).",
  '해당 조직에 적용되는 컴플라이언스가 있다면 선택합니다 (선택하지 않으면 일반 모범사례 기준으로 생성됩니다).',
  "'환경 설명'에 실제 구성(열린 포트, 사용 중인 서비스, 다루는 데이터, 알고 있는 문제점 등)을 구체적으로 입력합니다.",
  '[AI로 정책 초안 생성] 버튼을 클릭합니다.',
  "결과에서 '적용 우선순위'로 무엇부터 처리할지, 각 정책의 '검증 방법'으로 어떻게 테스트할지 확인합니다.",
  '방화벽 규칙 표와 정책 상세를 검토한 뒤 [Markdown 다운로드]로 초안 문서를 저장합니다.',
]
const POLICY_TIPS = [
  '환경 설명이 구체적일수록(실제 포트 번호, 알려진 위험 요소 등) 더 실질적인 초안이 생성됩니다.',
  "생성된 결과는 어디까지나 '초안'입니다 — 실제 운영 반영 전 반드시 담당자 검토와 테스트 환경 검증을 거치세요.",
  "위쪽 '정책 수립 전에 무엇부터 해야 할까?' 패널에서 준비 단계·우선순위 원칙·검증 방법론 전체를 확인할 수 있습니다.",
]

const ENV_TYPES = [
  { id: 'web_server', icon: Server, label: '웹 서버' },
  { id: 'cloud', icon: Cloud, label: '클라우드 인프라' },
  { id: 'internal_network', icon: Network, label: '사내 네트워크' },
  { id: 'container', icon: Boxes, label: '컨테이너 (Docker/K8s)' },
  { id: 'database', icon: Database, label: '데이터베이스' },
]

const COMPLIANCE_OPTIONS = ['PCI-DSS', 'ISMS-P', '개인정보보호법', 'GDPR', 'HIPAA']

const PLACEHOLDERS = {
  web_server: `nginx 리버스 프록시 + Node.js WAS로 구성된 커머스 웹사이트.\nSSH(22)가 0.0.0.0에 열려 비밀번호 인증으로 접속 가능.\nDB(MySQL)는 웹서버와 같은 인스턴스에 설치되어 있고 3306이 외부에도 열려있음.\n회원 정보(이름, 이메일, 전화번호)와 결제 내역을 저장.`,
  cloud: `AWS 기반, EC2 다수 + RDS + S3 버킷 운영.\nIAM 정책에 Action:"*" 권한을 가진 사용자가 존재.\nS3 버킷 하나가 정적 리소스 호스팅 목적으로 퍼블릭 읽기 허용 상태.\nCloudTrail 미설정.`,
  internal_network: `임직원 200명 규모 사내망. 전 직원이 동일 VLAN에서 파일서버·인사시스템에 접근 가능.\n게스트 Wi-Fi가 사내망과 분리되어 있지 않음.\nUSB 저장매체 사용 제한 없음.`,
  container: `Kubernetes 클러스터, 네임스페이스 분리 없이 전체 Pod가 자유롭게 통신 가능.\n일부 Pod가 privileged 모드로 실행 중.\nDB 비밀번호가 환경변수에 평문으로 하드코딩됨.`,
  database: `MySQL 8.0, 고객 개인정보(주민등록번호 포함) 및 결제정보 저장.\n공인 IP로 직접 개방되어 있고 root 계정을 애플리케이션에서도 그대로 사용 중.\n백업은 로컬 디스크에만 저장.`,
}

export default function SecurityPolicyGenerator() {
  const [envType, setEnvType] = useState('web_server')
  const [compliance, setCompliance] = useState([])
  const [description, setDescription] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [guide, setGuide] = useState(null)
  const [guideOpen, setGuideOpen] = useState(false)
  const [reconOpen, setReconOpen] = useState(false)

  useEffect(() => {
    axios.get('/api/policy/guide').then(r => setGuide(r.data)).catch(() => {})
  }, [])

  const toggleCompliance = (c) => setCompliance(cs => cs.includes(c) ? cs.filter(x => x !== c) : [...cs, c])

  const generate = async () => {
    if (!description.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await axios.post('/api/policy/generate', { environment_type: envType, compliance, description })
      setResult(res.data)
      setHistory(h => [res.data, ...h].slice(0, 10))
    } catch (err) {
      alert('생성 실패: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (id) => {
    try {
      const res = await axios.get(`/api/policy/report/${id}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/markdown' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `security-policy-${id}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('리포트 다운로드 실패')
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ScrollText className="text-teal-400" size={26} /> 보안 정책 생성기
          </h1>
          <p className="text-slate-400 text-sm mt-1">시스템 환경을 설명하면 AI가 방화벽 규칙과 보안 정책 초안, 적용 우선순위와 검증 방법까지 생성합니다.</p>
        </div>

        <GuidePanel title="보안 정책 생성기 사용 가이드" steps={POLICY_STEPS} tips={POLICY_TIPS} />

        {guide && (
          <div className="bg-amber-950/20 border border-amber-500/20 rounded-xl overflow-hidden">
            <button
              onClick={() => setGuideOpen(o => !o)}
              className="w-full flex items-center gap-2 px-4 py-3 hover:bg-amber-900/10 transition-colors text-left"
            >
              <ListOrdered size={15} className="text-amber-400 shrink-0" />
              <span className="text-sm font-medium text-amber-300">정책 수립 전에 무엇부터 해야 할까? (준비 단계 · 우선순위 원칙 · 검증 방법론)</span>
              <span className="ml-auto text-xs text-amber-500 shrink-0">{guideOpen ? '접기' : '펼치기'}</span>
            </button>

            {guideOpen && (
              <div className="px-4 pb-4 border-t border-amber-500/20 pt-3 space-y-5">
                <div>
                  <p className="text-xs font-semibold text-amber-400 mb-2">1. 시작하기 전 준비 단계</p>
                  <ol className="space-y-2">
                    {guide.getting_started.map(s => (
                      <li key={s.step} className="flex gap-2 text-xs text-slate-300">
                        <span className="shrink-0 w-5 h-5 rounded-full bg-amber-600/30 text-amber-300 flex items-center justify-center font-bold text-[10px]">
                          {s.step}
                        </span>
                        <span className="pt-0.5"><b className="text-slate-200">{s.title}</b> — {s.detail}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <p className="text-xs font-semibold text-amber-400 mb-2">2. 기존 정책 중 무엇부터? (우선순위 원칙)</p>
                  <p className="text-xs text-slate-300 mb-2">{guide.priority_framework.principle}</p>
                  <ul className="space-y-1 mb-2">
                    {guide.priority_framework.general_order.map((o, i) => (
                      <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                        <span className="text-amber-500 shrink-0">•</span>{o}
                      </li>
                    ))}
                  </ul>
                  <p className="text-xs text-slate-500 italic">{guide.priority_framework.caveat}</p>
                </div>

                <div>
                  <p className="text-xs font-semibold text-amber-400 mb-2">3. 적용 후 어떻게 테스트·검증할까?</p>
                  <div className="space-y-2">
                    {guide.validation_methodology.map((v, i) => (
                      <div key={i}>
                        <p className="text-xs font-semibold text-slate-300">{v.phase}</p>
                        <ul className="space-y-1 mt-1">
                          {v.steps.map((s, j) => (
                            <li key={j} className="text-xs text-slate-400 flex gap-1.5">
                              <span className="text-amber-500 shrink-0">•</span>{s}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>

                <p className="text-xs text-slate-500 border-t border-amber-500/10 pt-3">{guide.disclaimer}</p>
              </div>
            )}
          </div>
        )}

        <div className="grid md:grid-cols-5 gap-6">
          {/* Input Panel */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">환경 유형</p>
              <div className="grid grid-cols-2 gap-2">
                {ENV_TYPES.map(({ id, icon: Icon, label }) => (
                  <button
                    key={id}
                    onClick={() => setEnvType(id)}
                    className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                      envType === id ? 'bg-teal-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    <Icon size={14} />{label}
                  </button>
                ))}
              </div>
            </div>

            {guide?.environment_recon?.[envType] && (
              <div className="bg-slate-950/60 border border-slate-700 rounded-xl overflow-hidden">
                <button
                  onClick={() => setReconOpen(o => !o)}
                  className="w-full flex items-center gap-2 px-3 py-2.5 hover:bg-slate-800/60 transition-colors text-left"
                >
                  <Terminal size={14} className="text-cyan-400 shrink-0" />
                  <span className="text-xs font-medium text-cyan-300">
                    이 환경에서 As-Is 파악하기: 명령어 &amp; 확인 위치 ({guide.environment_recon[envType].label})
                  </span>
                  <span className="ml-auto text-xs text-cyan-500 shrink-0">{reconOpen ? '접기' : '펼치기'}</span>
                </button>

                {reconOpen && (
                  <div className="px-3 pb-3 border-t border-slate-700 pt-3 space-y-3">
                    {guide.environment_recon[envType].note && (
                      <p className="text-xs text-slate-500 italic">{guide.environment_recon[envType].note}</p>
                    )}
                    {guide.environment_recon[envType].checks.map((check, i) => (
                      <div key={i}>
                        <p className="text-xs font-semibold text-slate-300">{check.category}</p>
                        <p className="text-[11px] text-slate-500 mb-1">확인 위치: {check.where}</p>
                        <pre className="bg-slate-900 border border-slate-700 rounded-lg p-2 overflow-x-auto">
                          <code className="text-[11px] text-cyan-300 font-mono whitespace-pre">
                            {check.commands.join('\n')}
                          </code>
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">적용 대상 컴플라이언스 (선택)</p>
              <div className="flex flex-wrap gap-1.5">
                {COMPLIANCE_OPTIONS.map(c => (
                  <button
                    key={c}
                    onClick={() => toggleCompliance(c)}
                    className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                      compliance.includes(c) ? 'bg-blue-600 border-blue-500 text-white' : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-400 mb-2">환경 설명</p>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder={PLACEHOLDERS[envType]}
                rows={10}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl p-4 text-sm font-mono resize-none focus:outline-none focus:border-teal-500 placeholder-slate-600"
              />
            </div>

            <button
              onClick={generate}
              disabled={loading || !description.trim()}
              className="w-full py-3 bg-teal-600 hover:bg-teal-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-xl font-semibold transition-colors"
            >
              {loading ? '생성 중...' : 'AI로 정책 초안 생성'}
            </button>
          </div>

          {/* Result Panel */}
          <div className="md:col-span-3 space-y-4">
            {!result && !loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center text-slate-500 h-48 flex flex-col items-center justify-center gap-2">
                <ScrollText size={32} className="text-slate-600" />
                <p className="text-sm">생성된 정책 초안이 여기에 표시됩니다</p>
              </div>
            )}
            {loading && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 text-center h-48 flex flex-col items-center justify-center gap-2">
                <div className="w-8 h-8 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-sm text-slate-400">AI가 정책 초안을 생성 중...</p>
              </div>
            )}

            {result && (
              <div className="space-y-4">
                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm text-slate-300">{result.summary}</p>
                    <button
                      onClick={() => downloadReport(result.id)}
                      className="shrink-0 flex items-center gap-1.5 text-xs bg-teal-600/20 text-teal-300 border border-teal-600/40 rounded-lg px-3 py-1.5 hover:bg-teal-600/30"
                    >
                      <Download size={13} /> Markdown 다운로드
                    </button>
                  </div>
                </div>

                {result.risk_notes?.length > 0 && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                    <p className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-1.5">
                      <AlertTriangle size={13} /> 주의가 필요한 사항
                    </p>
                    <ul className="space-y-1">
                      {result.risk_notes.map((n, i) => (
                        <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                          <span className="text-red-400 mt-0.5 shrink-0">•</span>{n}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.priority_order?.length > 0 && (
                  <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                    <p className="text-xs font-semibold text-teal-400 mb-3 flex items-center gap-1.5">
                      <ListOrdered size={13} /> 적용 우선순위
                    </p>
                    <div className="space-y-2">
                      {result.priority_order.map(p => (
                        <div key={p.rank} className="flex items-start gap-3">
                          <span className="shrink-0 w-6 h-6 rounded-full bg-teal-600/30 text-teal-300 flex items-center justify-center font-bold text-xs">
                            {p.rank}
                          </span>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-medium text-slate-200">{p.category}</span>
                              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                p.level.startsWith('즉시') ? 'bg-red-500/20 text-red-400' : p.level.startsWith('단기') ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-600/40 text-slate-400'
                              }`}>
                                {p.level}
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 mt-0.5">{p.reason}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                  <p className="text-xs font-semibold text-teal-400 mb-3">방화벽 규칙</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-slate-500 border-b border-slate-700">
                          <th className="text-left py-1.5 pr-2">동작</th>
                          <th className="text-left py-1.5 pr-2">프로토콜</th>
                          <th className="text-left py-1.5 pr-2">포트</th>
                          <th className="text-left py-1.5 pr-2">출발지</th>
                          <th className="text-left py-1.5 pr-2">목적지</th>
                          <th className="text-left py-1.5">설명</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.firewall_rules?.map(r => (
                          <tr key={r.id} className="border-b border-slate-700/50">
                            <td className="py-1.5 pr-2">
                              <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${r.action === 'ALLOW' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                {r.action}
                              </span>
                            </td>
                            <td className="py-1.5 pr-2 text-slate-300">{r.protocol}</td>
                            <td className="py-1.5 pr-2 text-slate-300 font-mono">{r.port}</td>
                            <td className="py-1.5 pr-2 text-slate-400">{r.source}</td>
                            <td className="py-1.5 pr-2 text-slate-400">{r.destination}</td>
                            <td className="py-1.5 text-slate-400">{r.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {result.firewall_validation_tip && (
                    <div className="mt-3 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                      <ClipboardCheck size={13} className="text-blue-400 shrink-0 mt-0.5" />
                      <p className="text-xs text-slate-400">{result.firewall_validation_tip}</p>
                    </div>
                  )}
                </div>

                <div className="space-y-3">
                  {result.policies?.map((p, i) => (
                    <div key={i} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-[10px] font-bold bg-teal-500/15 text-teal-300 border border-teal-500/30 rounded-full px-2 py-0.5">
                          {p.category}
                        </span>
                        <p className="text-sm font-semibold text-slate-200">{p.title}</p>
                      </div>
                      <ul className="space-y-1 mt-2">
                        {p.rules?.map((r, j) => (
                          <li key={j} className="text-xs text-slate-300 flex gap-1.5">
                            <span className="text-teal-400 mt-0.5 shrink-0">•</span>{r}
                          </li>
                        ))}
                      </ul>
                      <p className="text-xs text-slate-500 mt-2 italic">근거: {p.rationale}</p>
                      {p.validation?.method && (
                        <div className="mt-2 bg-slate-900/60 rounded-lg p-2.5 flex gap-1.5">
                          <ClipboardCheck size={13} className="text-blue-400 shrink-0 mt-0.5" />
                          <p className="text-xs text-slate-400">
                            <span className="text-blue-300 font-medium">검증 방법: </span>
                            {p.validation.method}
                            {p.validation.example && <span className="text-slate-500"> ({p.validation.example})</span>}
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                {result.compliance_mapping?.length > 0 && (
                  <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                    <p className="text-xs font-semibold text-blue-400 mb-3 flex items-center gap-1.5">
                      <BadgeCheck size={13} /> 컴플라이언스 매핑
                    </p>
                    <div className="space-y-3">
                      {result.compliance_mapping.map((c, i) => (
                        <div key={i}>
                          <p className="text-xs font-semibold text-slate-300 mb-1">{c.framework}</p>
                          <ul className="space-y-1">
                            {c.items?.map((item, j) => (
                              <li key={j} className="text-xs text-slate-400 flex gap-1.5">
                                <span className="text-blue-400 mt-0.5 shrink-0">•</span>{item}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ))}
                    </div>
                    <p className="text-[10px] text-slate-500 mt-2">참고용 매핑이며, 정확한 인증기준 충족 여부는 전문가 검토가 필요합니다.</p>
                  </div>
                )}
              </div>
            )}

            {history.length > 0 && (
              <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
                <div className="flex justify-between items-center mb-3">
                  <p className="text-xs font-semibold text-slate-400">최근 생성 ({history.length}건)</p>
                  <button onClick={() => setHistory([])} className="text-slate-500 hover:text-red-400">
                    <Trash2 size={13} />
                  </button>
                </div>
                <div className="space-y-2">
                  {history.map((h, i) => (
                    <button
                      key={i}
                      onClick={() => setResult(h)}
                      className="w-full text-left flex items-center gap-2 p-2 rounded-lg hover:bg-slate-700 transition-colors"
                    >
                      <ShieldCheck size={14} className="text-teal-400" />
                      <span className="text-xs text-slate-300 truncate flex-1">{h.preview}</span>
                      <span className="text-xs text-slate-500 shrink-0">{ENV_TYPES.find(e => e.id === h.environment_type)?.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
