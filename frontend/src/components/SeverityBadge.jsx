const colors = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
}

export default function SeverityBadge({ severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold ${colors[severity] ?? colors.INFO}`}>
      {severity}
    </span>
  )
}
