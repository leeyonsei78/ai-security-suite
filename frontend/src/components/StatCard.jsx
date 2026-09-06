export default function StatCard({ label, value, color, hint, onClick, active }) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag
      onClick={onClick}
      className={`rounded-xl p-4 border ${color} bg-slate-800 text-left w-full ${onClick ? 'cursor-pointer hover:bg-slate-750 transition-colors' : ''} ${active ? 'ring-2 ring-offset-2 ring-offset-slate-900 ring-blue-400' : ''}`}
    >
      <p className="text-sm text-slate-400">{label}</p>
      <p className="text-3xl font-bold mt-1">{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-1.5 leading-snug">{hint}</p>}
      {onClick && <p className="text-[10px] text-blue-400 mt-1.5">{active ? '✓ 필터 적용됨 — 다시 클릭하면 해제' : '클릭하면 이 등급만 필터링'}</p>}
    </Tag>
  )
}
