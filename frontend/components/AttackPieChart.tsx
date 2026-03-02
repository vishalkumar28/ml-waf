import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts'

const COLORS = ['#00d4ff', '#7c3aed', '#ef4444', '#10b981', '#f59e0b']

export default function AttackPieChart({ data }: { data: any[] }) {
    return (
        <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
            <h3 className="text-sm font-bold text-cyan-400 mb-3 uppercase tracking-widest">
                Attack Type Breakdown
            </h3>
            <PieChart width={300} height={240}>
                <Pie data={data} dataKey="count" nameKey="type"
                    cx="50%" cy="50%" outerRadius={90} label>
                    {data.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1e3a5f' }} />
                <Legend />
            </PieChart>
        </div>
    )
}