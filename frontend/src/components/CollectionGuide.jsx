import { useState } from 'react'
import { ChevronDown, ChevronUp, MapPin, Info, Terminal } from 'lucide-react'
import CopyButton from './CopyButton'

// App 24(FsiCspAudit.jsx)에서 처음 만든 "분야별 정보 수집 가이드" 패턴을 공용화한 것 —
// "어디서/어떻게/무슨 명령어로" 실제 데이터를 수집하는지 앱마다 반복해서 만들지 않고 재사용한다.
function CollectionItemCard({ item, accentColor }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden bg-slate-900/60">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-800/60"
      >
        <span className={`text-xs font-medium flex-1 ${accentColor}`}>{item.category}</span>
        {open ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-slate-800 pt-2">
          {item.where && (
            <p className="text-[11px] text-slate-300 flex items-start gap-1.5">
              <MapPin size={12} className={`${accentColor} shrink-0 mt-0.5`} />
              <span><span className="text-slate-500">어디서:</span> {item.where}</span>
            </p>
          )}
          {item.how && (
            <p className="text-[11px] text-slate-400 flex items-start gap-1.5">
              <Info size={12} className="text-slate-500 shrink-0 mt-0.5" />
              <span><span className="text-slate-500">어떻게:</span> {item.how}</span>
            </p>
          )}
          {item.commands?.length > 0 && (
            <div className="flex items-start gap-1.5">
              <Terminal size={12} className="text-slate-500 shrink-0 mt-1" />
              <pre className="flex-1 bg-slate-950 border border-slate-800 rounded-lg p-2 overflow-x-auto">
                <code className={`text-[10.5px] font-mono whitespace-pre ${accentColor}`}>{item.commands.join('\n')}</code>
              </pre>
              <CopyButton text={item.commands.join('\n')} />
            </div>
          )}
          {item.note && <p className="text-[10.5px] text-amber-400 italic">{item.note}</p>}
        </div>
      )}
    </div>
  )
}

export default function CollectionGuide({
  items,
  usageNote,
  accentColor = 'text-cyan-300',
  title = '정보 수집 가이드 — 어디서 뭘 가져오는지',
}) {
  const [expanded, setExpanded] = useState(false)
  if (!items?.length) return null
  return (
    <div className="bg-slate-950/60 border border-slate-700 rounded-xl p-3 space-y-2">
      <button onClick={() => setExpanded(e => !e)} className="w-full flex items-center gap-2 text-left">
        <MapPin size={13} className={accentColor} />
        <span className={`text-xs font-semibold flex-1 ${accentColor}`}>{title}</span>
        {expanded ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
      </button>
      {expanded && (
        <div className="space-y-2 pt-1">
          {usageNote && (
            <p className="text-[11px] text-amber-200 bg-amber-950/40 border border-amber-500/30 rounded-lg px-2.5 py-2 flex items-start gap-1.5">
              <Info size={12} className="shrink-0 mt-0.5" />
              <span>{usageNote}</span>
            </p>
          )}
          <div className="space-y-1.5">
            {items.map((item, i) => <CollectionItemCard key={i} item={item} accentColor={accentColor} />)}
          </div>
        </div>
      )}
    </div>
  )
}
