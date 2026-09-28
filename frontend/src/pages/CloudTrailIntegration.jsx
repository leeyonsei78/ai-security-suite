import { useState, useEffect } from 'react'
import axios from 'axios'
import { Cloud, Trash2, Plus, AlertTriangle, Copy, CheckCircle } from 'lucide-react'
import GuidePanel from '../components/GuidePanel'

const CT_STEPS = [
  '고객사(모니터링 대상) AWS 계정에 IAM Role을 만들고, 신뢰 정책에 우리 AWS 계정을 등록 + ExternalId를 설정합니다.',
  '그 Role에 대상 S3 버킷(CloudTrail 로그 저장소)에 대한 읽기 권한(s3:GetObject, s3:ListBucket)만 부여합니다.',
  'CloudTrail에 SNS 알림을 켜서(aws cloudtrail update-trail --sns-topic-name ...) 새 로그 파일이 생길 때마다 SNS 토픽으로 알리게 합니다.',
  '그 SNS 토픽에 아래 "웹훅 URL"을 HTTPS 구독으로 추가합니다 — 우리 서버가 SNS의 구독 확인 요청을 자동으로 처리합니다.',
  '아래 폼에 Role ARN·ExternalId·Region·Topic ARN을 입력해 등록하면, 그 순간 실제로 Role을 빌려 쓸 수 있는지 검증합니다.',
  '이후 새 CloudTrail 로그가 쌓일 때마다 자동으로 분석되어 App 1(대시보드) 히스토리에 쌓이고, CRITICAL이면 알림이 옵니다.',
]
const CT_TIPS = [
  '장기 AWS 액세스 키는 저장하지 않습니다 — Role ARN과 ExternalId만 우리 DB에 남고, 실제 접근은 매번 임시 자격증명(AssumeRole)으로만 이뤄집니다.',
  '우리 백엔드 서버 자체도 자기 AWS 계정으로 인증돼 있어야(boto3 표준 자격증명 체인) sts:AssumeRole을 호출할 수 있습니다 — 운영자가 서버에 설정해야 하는 부분입니다.',
  '자세한 IAM 정책 예시·CLI 명령어는 docs/cloudtrail-integration.md 참고.',
]

export default function CloudTrailIntegration() {
  const [connections, setConnections] = useState([])
  const [roleArn, setRoleArn] = useState('')
  const [externalId, setExternalId] = useState('')
  const [region, setRegion] = useState('us-east-1')
  const [topicArn, setTopicArn] = useState('')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  const webhookUrl = `${window.location.origin}/api/cloudtrail/webhook`

  const fetchConnections = () => {
    axios.get('/api/cloudtrail/connections').then(r => setConnections(r.data.connections)).catch(() => {})
  }

  useEffect(() => { fetchConnections() }, [])

  const copyWebhookUrl = () => {
    navigator.clipboard.writeText(webhookUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const createConnection = async () => {
    if (!roleArn.trim() || !topicArn.trim()) return
    setCreating(true)
    setError('')
    try {
      await axios.post('/api/cloudtrail/connections', {
        role_arn: roleArn, external_id: externalId, region, topic_arn: topicArn,
      })
      setRoleArn(''); setExternalId(''); setTopicArn('')
      fetchConnections()
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setCreating(false)
    }
  }

  const deleteConnection = async (id) => {
    await axios.delete(`/api/cloudtrail/connections/${id}`)
    fetchConnections()
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Cloud className="text-cyan-400" size={26} /> AWS CloudTrail 연동
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            고객사 AWS 계정의 CloudTrail 감사 로그를 S3+SNS 웹훅으로 실시간에 가깝게 받아 App 1(대시보드)에서 자동 분석합니다.
          </p>
        </div>

        <GuidePanel title="CloudTrail 연동 설정 가이드" steps={CT_STEPS} tips={CT_TIPS} />

        {/* Webhook URL */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-2">
          <p className="text-sm font-semibold text-slate-300">웹훅 URL (SNS 토픽 구독에 사용)</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 truncate">
              {webhookUrl}
            </code>
            <button onClick={copyWebhookUrl} className="flex items-center gap-1 px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs shrink-0">
              {copied ? <CheckCircle size={13} /> : <Copy size={13} />} {copied ? '복사됨' : '복사'}
            </button>
          </div>
          <p className="text-xs text-amber-400 flex items-center gap-1">
            <AlertTriangle size={12} /> 이 URL이 지금 보고 계신 브라우저 주소({window.location.origin})라, 실제로는 이 백엔드가 외부(AWS)에서 접근 가능한 공인 HTTPS 주소여야 합니다 — 로컬 개발 환경에서는 SNS가 직접 도달할 수 없습니다.
          </p>
        </div>

        {/* Create form */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-3">
          <p className="text-sm font-semibold text-slate-300">새 AWS 계정 연결 등록</p>
          <div className="grid sm:grid-cols-2 gap-3">
            <input
              value={roleArn}
              onChange={e => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/CloudTrailReadRole"
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
            <input
              value={externalId}
              onChange={e => setExternalId(e.target.value)}
              placeholder="ExternalId (고객사와 합의한 임의 문자열)"
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
            <input
              value={region}
              onChange={e => setRegion(e.target.value)}
              placeholder="us-east-1"
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
            <input
              value={topicArn}
              onChange={e => setTopicArn(e.target.value)}
              placeholder="arn:aws:sns:us-east-1:123456789012:cloudtrail-topic"
              className="bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          {error && <p className="text-xs text-red-400 break-all">{error}</p>}
          <button
            onClick={createConnection}
            disabled={creating || !roleArn.trim() || !topicArn.trim()}
            className="flex items-center gap-1.5 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold"
          >
            <Plus size={14} /> {creating ? 'IAM Role 확인 중...' : '등록 (즉시 AssumeRole 검증)'}
          </button>
        </div>

        {/* Connection list */}
        <div className="space-y-3">
          <p className="text-sm font-semibold text-slate-300">등록된 연결 ({connections.length}개)</p>
          {connections.length === 0 && (
            <p className="text-sm text-slate-500 text-center py-8">등록된 AWS 연결이 없습니다.</p>
          )}
          {connections.map(conn => (
            <div key={conn.id} className="bg-slate-800 border border-slate-700 rounded-xl p-4 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-xs font-mono text-slate-200 truncate">{conn.role_arn}</p>
                  <p className="text-xs text-slate-500 font-mono truncate">{conn.topic_arn}</p>
                </div>
                <button
                  onClick={() => deleteConnection(conn.id)}
                  className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-red-400 shrink-0"
                  title="삭제"
                >
                  <Trash2 size={14} />
                </button>
              </div>
              {conn.last_error && (
                <p className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle size={12} /> {conn.last_error}</p>
              )}
              <p className="text-xs text-slate-400">
                수집된 이벤트 {conn.events_ingested ?? 0}건
                {conn.last_event_at ? ` · 마지막 수신: ${new Date(conn.last_event_at).toLocaleString('ko-KR')}` : ' · 아직 수신 없음'}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
