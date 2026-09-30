import json

from fastapi import WebSocket


class WebSocketManager:
    """WebSocket 连接管理 — 广播事件到所有连接的 Dashboard 客户端"""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, channel: str = "events") -> None:
        await ws.accept()
        if channel not in self._connections:
            self._connections[channel] = []
        self._connections[channel].append(ws)

    async def disconnect(self, ws: WebSocket, channel: str = "events") -> None:
        conns = self._connections.get(channel, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, event: dict, channel: str = "events") -> None:
        dead = []
        for ws in self._connections.get(channel, []):
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws, channel)

    async def send_to(self, ws: WebSocket, event: dict) -> None:
        await ws.send_text(json.dumps(event))
