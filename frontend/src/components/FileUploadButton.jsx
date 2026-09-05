import { useState } from 'react'
import axios from 'axios'
import { Upload, Loader2 } from 'lucide-react'

// 여러 앱의 "붙여넣기" textarea에 공용으로 붙는 파일 업로드 버튼 — txt/csv 같은 텍스트 파일은
// 물론, Word(.docx)/PDF/Excel(.xlsx)처럼 파싱이 필요한 형식도 백엔드 `/api/extract-text`가
// 대신 텍스트를 뽑아 돌려준다(원본 파일은 서버에 저장되지 않음). 추출된 텍스트를 그대로
// 기존 textarea에 채워 넣도록 `onExtracted(text, filename)` 콜백만 넘기면 된다.
export const DEFAULT_ACCEPT = '.txt,.log,.md,.json,.yml,.yaml,.conf,.cfg,.ini,.csv,.docx,.pdf,.xlsx,.xls'

export default function FileUploadButton({ onExtracted, accept = DEFAULT_ACCEPT, label = '파일 업로드', className = '' }) {
  const [loading, setLoading] = useState(false)

  const handleChange = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post('/api/extract-text', form, { headers: { 'Content-Type': 'multipart/form-data' } })
      onExtracted(res.data.text, file.name)
      if (res.data.truncated) {
        alert(`파일이 커서 앞부분(최대 10만자)까지만 불러왔습니다: ${file.name}`)
      }
    } catch (err) {
      alert('파일을 읽지 못했습니다: ' + (err.response?.data?.detail ?? err.message))
    } finally {
      setLoading(false)
      e.target.value = ''
    }
  }

  return (
    <label
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs font-medium cursor-pointer transition-colors shrink-0 ${loading ? 'opacity-60 pointer-events-none' : ''} ${className}`}
    >
      {loading ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />}
      {loading ? '읽는 중...' : label}
      <input type="file" accept={accept} className="hidden" onChange={handleChange} disabled={loading} />
    </label>
  )
}
