export default function StatCard({ label, value, color, hint }) {
  return (
    <div className={`rounded-xl p-4 border ${color} bg-slate-800`}>
      <p className="text-sm text-slate-400">{label}</p>
      <p className="text-3xl font-bold mt-1">{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-1.5 leading-snug">{hint}</p>}
    </div>
  )
}
