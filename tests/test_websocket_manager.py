"""WebSocket 连接管理测试"""
import json
from unittest.mock import AsyncMock

import pytest

from src.engine.websocket_manager import WebSocketManager


def _mock_ws() -> AsyncMock:
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.receive_text = AsyncMock(return_value="ping")
    return ws


class TestWebSocketManagerUnit:
    """不依赖 FastAPI TestClient 的纯单元测试"""

    @pytest.mark.asyncio
    async def test_connect_adds_to_default_channel(self):
        wsm = WebSocketManager()
        ws = _mock_ws()
        await wsm.connect(ws)
        assert ws in wsm._connections["events"]
        ws.accept.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_custom_channel(self):
        wsm = WebSocketManager()
        ws = _mock_ws()
        await wsm.connect(ws, channel="alerts")
        assert "alerts" in wsm._connections
        assert ws in wsm._connections["alerts"]

    @pytest.mark.asyncio
    async def test_disconnect_removes_from_channel(self):
        wsm = WebSocketManager()
        ws = _mock_ws()
        await wsm.connect(ws)
        await wsm.disconnect(ws)
        assert ws not in wsm._connections["events"]

    @pytest.mark.asyncio
    async def test_disconnect_unknown_socket_no_error(self):
        wsm = WebSocketManager()
        ws = _mock_ws()
        # 从未连接就直接断开，不应抛异常
        await wsm.disconnect(ws)

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all_connections(self):
        wsm = WebSocketManager()
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        await wsm.connect(ws1)
        await wsm.connect(ws2)

        await wsm.broadcast({"type": "test", "msg": "hello"})
        ws1.send_text.assert_awaited_once()
        ws2.send_text.assert_awaited_once()

        payload = json.loads(ws1.send_text.call_args[0][0])
        assert payload["type"] == "test"

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self):
        wsm = WebSocketManager()
        ws_alive = _mock_ws()
        ws_dead = _mock_ws()
        ws_dead.send_text = AsyncMock(side_effect=RuntimeError("broken"))

        await wsm.connect(ws_alive)
        await wsm.connect(ws_dead)

        await wsm.broadcast({"type": "ping"})

        # 活着的还在
        assert ws_alive in wsm._connections["events"]
        # 死了的已被清理
        assert ws_dead not in wsm._connections["events"]
        ws_alive.send_text.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_to_single_connection(self):
        wsm = WebSocketManager()
        ws = _mock_ws()
        await wsm.send_to(ws, {"type": "direct"})
        ws.send_text.assert_awaited_once()
        payload = json.loads(ws.send_text.call_args[0][0])
        assert payload["type"] == "direct"

    @pytest.mark.asyncio
    async def test_channels_are_isolated(self):
        wsm = WebSocketManager()
        ws_a = _mock_ws()
        ws_b = _mock_ws()
        await wsm.connect(ws_a, channel="ch-a")
        await wsm.connect(ws_b, channel="ch-b")

        await wsm.broadcast({"type": "only-a"}, channel="ch-a")
        ws_a.send_text.assert_awaited_once()
        ws_b.send_text.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_empty_channel_no_error(self):
        wsm = WebSocketManager()
        await wsm.broadcast({"type": "nobody"}, channel="nonexistent")

    @pytest.mark.asyncio
    async def test_disconnect_removes_only_target_socket(self):
        wsm = WebSocketManager()
        ws1 = _mock_ws()
        ws2 = _mock_ws()
        await wsm.connect(ws1)
        await wsm.connect(ws2)
        await wsm.disconnect(ws1)

        assert ws1 not in wsm._connections["events"]
        assert ws2 in wsm._connections["events"]
