import { useState } from 'react'
import { Copy, Check } from 'lucide-react'

// AttackMonitor.jsx(App 23)의 대응 제안 명령 복사 버튼을 공용 컴포넌트로 추출한 것 —
// 정보 수집 명령어(App3/11/16/18/20/24)에도 동일하게 재사용한다.
export default function CopyButton({ text, className = '' }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={async (e) => {
        e.stopPropagation()
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {}
      }}
      className={`flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 shrink-0 ${className}`}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
      {copied ? '복사됨' : '복사'}
    </button>
  )
}
