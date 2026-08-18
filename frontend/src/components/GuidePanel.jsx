import { useState } from 'react'
import { ChevronDown, ChevronUp, BookOpen } from 'lucide-react'

export default function GuidePanel({ title, steps, tips }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="bg-blue-950/40 border border-blue-500/20 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-blue-900/20 transition-colors text-left"
      >
        <BookOpen size={15} className="text-blue-400 shrink-0" />
        <span className="text-sm font-medium text-blue-300">{title}</span>
        <span className="ml-auto text-xs text-blue-500">{open ? '접기' : '펼치기'}</span>
        {open ? <ChevronUp size={14} className="text-blue-500" /> : <ChevronDown size={14} className="text-blue-500" />}
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-blue-500/20 pt-3 space-y-4">
          {/* Steps */}
          <div>
            <p className="text-xs font-semibold text-blue-400 mb-2">사용 방법</p>
            <ol className="space-y-2">
              {steps.map((step, i) => (
                <li key={i} className="flex gap-2 text-xs text-slate-300">
                  <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600/40 text-blue-300 flex items-center justify-center font-bold text-[10px]">
                    {i + 1}
                  </span>
                  <span className="pt-0.5">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Tips */}
          {tips && tips.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-amber-400 mb-2">참고</p>
              <ul className="space-y-1">
                {tips.map((tip, i) => (
                  <li key={i} className="flex gap-1.5 text-xs text-slate-400">
                    <span className="text-amber-500 shrink-0">•</span>{tip}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
