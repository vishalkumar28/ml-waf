import { useEffect, useState } from 'react'

interface AttackEvent {
    request_id: string
    client_ip: string
    path: string
    decision: string
    attack_type: string
    confidence: number
}

export default function AttackFeed() {
    const [events, setEvents] = useState<AttackEvent[]>([])

    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8000/ws/attacks')
        ws.onmessage = (msg) => {
            const evt: AttackEvent = JSON.parse(msg.data)
            setEvents(prev => [evt, ...prev].slice(0, 100))
        }
        ws.onclose = () => setTimeout(() => { }, 3000)
        return () => ws.close()
    }, [])

    const colors: Record<string, string> = {
        BLOCK: 'bg-red-900/50 border-red-500/30 text-red-200',
        BYPASS_SUSPECT: 'bg-yellow-900/50 border-yellow-500/30 text-yellow-200',
        ALLOW: 'bg-green-900/50 border-green-500/30 text-green-200',
    }

    return (
        <div className="bg-gray-900 rounded-xl p-4 h-80 overflow-y-auto border border-gray-700">
            <h3 className="text-sm font-bold text-cyan-400 mb-3 uppercase tracking-widest">
                Live Attack Feed
            </h3>
            {events.map((e) => (
                <div key={e.request_id}
                    className={`p-2 mb-1 rounded border text-xs font-mono ${colors[e.decision]}`}>
                    <span className="font-bold">{e.decision}</span>{' '}
                    | {e.client_ip} | {e.attack_type}
                    | {(e.confidence * 100).toFixed(1)}%
                    | {e.path}
                </div>
            ))}
            {events.length === 0 && (
                <p className="text-gray-500 text-sm">Waiting for traffic...</p>
            )}
        </div>
    )
}