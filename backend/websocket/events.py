from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio, redis.asyncio as aioredis, os

ws_router = APIRouter()
clients: list[WebSocket] = []

@ws_router.websocket("/ws/attacks")
async def attack_stream(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    r = await aioredis.from_url(os.getenv("REDIS_URL"))
    pubsub = r.pubsub()
    await pubsub.subscribe("waf_events")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await ws.send_text(message["data"].decode())
    except WebSocketDisconnect:
        clients.remove(ws)
    finally:
        await r.close()