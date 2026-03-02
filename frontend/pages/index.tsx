import { useEffect, useState } from 'react'
import axios from 'axios'
import AttackFeed from '../components/AttackFeed'
import AttackPieChart from '../components/AttackPieChart'

export default function Dashboard() {
    const [summary, setSummary] = useState<any>(null)

    useEffect(() => {
        axios.get('http://localhost:8000/api/dashboard/summary')
            .then(r => setSummary(r.data))
    }, [])

    const pieData = summary ? Object.entries(summary.attack_breakdown)
        .map(([type, count]) => ({ type, count })) : []

    return (
        <div className="min-h-screen bg-gray-950 text-white p-8">
            <h1 className="text-3xl font-bold text-cyan-400 mb-8">
                🛡️ ML-WAF Dashboard
            </h1>

            {/* Stats Row */}
            <div className="grid grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'Total Requests', val: summary?.total_requests_24h, color: 'text-blue-400' },
                    { label: 'Blocked', val: summary?.malicious_24h, color: 'text-red-400' },
                    { label: 'Allowed', val: summary?.benign_24h, color: 'text-green-400' },
                    { label: 'Bypass Attempts', val: summary?.bypass_attempts_24h, color: 'text-yellow-400' },
                ].map(s => (
                    <div key={s.label} className="bg-gray-900 rounded-xl p-5 border border-gray-700">
                        <div className={`text-3xl font-bold ${s.color}`}>{s.val ?? '--'}</div>
                        <div className="text-xs text-gray-400 mt-1 uppercase tracking-wider">{s.label}</div>
                    </div>
                ))}
            </div>

            {/* Charts + Feed Row */}
            <div className="grid grid-cols-2 gap-6 mb-6">
                <AttackPieChart data={pieData} />
                <AttackFeed />
            </div>
        </div>
    )
}