# tests/test_frida_bridge.py
import hashlib
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch

import httpx
import pytest


class TestFridaBridgePid:
    """_get_host_pid 测试"""

    def test_get_host_pid_with_namespace(self):
        """有 namespace 时返回 NSpid 第二列（宿主机 PID）"""
        from src.frida.bridge import FridaBridge
        m = MagicMock()
        m.return_value.__enter__.return_value = [
            "Name:\tpython\n", "NSpid:\t123\t45678\n"
        ]
        with patch("builtins.open", m):
            bridge = FridaBridge()
        assert bridge.host_pid == 45678

    def test_get_host_pid_no_namespace(self):
        """无 namespace 时回退到第一列 PID"""
        from src.frida.bridge import FridaBridge
        m = MagicMock()
        m.return_value.__enter__.return_value = [
            "Name:\tpython\n", "NSpid:\t12345\n"
        ]
        with patch("builtins.open", m):
            bridge = FridaBridge()
        assert bridge.host_pid == 12345

    def test_get_host_pid_no_nspid_falls_back(self):
        """没有 NSpid 行时回退到 os.getpid()"""
        from src.frida.bridge import FridaBridge
        m = MagicMock()
        m.return_value.__enter__.return_value = [
            "Name:\tpython\n", "Pid:\t9999\n"
        ]
        with patch("builtins.open", m):
            bridge = FridaBridge()
        assert bridge.host_pid == os.getpid()


class TestFridaBridgeAuditEngine:
    """审计引擎 HTTP 通信测试"""

    @pytest.mark.asyncio
    async def test_request_causal_id_allow(self):
        """审计引擎返回 ALLOW 决策 + causal_id"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "causal_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2",
            "decision": "allow",
            "taint_tags": [],
            "reason": "正常调用",
            "mode": "enforcing",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            result = await bridge.request_causal_id("summarize", "hello world", "user input")
            assert result["decision"] == "allow"
            assert result["causal_id"] is not None

    @pytest.mark.asyncio
    async def test_request_causal_id_timeout(self):
        """审计引擎超时 100ms → 降级为 UNVERIFIED"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.side_effect = httpx.TimeoutException("timeout")
            result = await bridge.request_causal_id("bash_exec", "ls -la", "user input")
            assert result["causal_id"] is None
            assert result["decision"] == "allow"
            assert result["reason"] == "timeout"

    @pytest.mark.asyncio
    async def test_request_causal_id_params_hash(self):
        """params 被 sha256 哈希后发送"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        params = "test params"
        expected_hash = hashlib.sha256(params.encode()).hexdigest()

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "causal_id": None, "decision": "ask", "taint_tags": [], "reason": "test", "mode": "ask"
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_post = mock_client.return_value.__aenter__.return_value.post
            mock_post.return_value = mock_response
            await bridge.request_causal_id("tool1", params, "input")
            call_args = mock_post.call_args
            assert call_args[1]["json"]["params_hash"] == expected_hash


class TestFridaBridgeSocket:
    """Unix Socket 通信测试"""

    def test_send_causal_id_success(self):
        """正常写入 Socket → 返回 True"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge.sock = MagicMock()
        bridge.sock.recv.return_value = b"\x01\x00"  # ACK status=0

        result = bridge._send_causal_id(b"\x01" * 32, "test_tool")
        assert result is True
        bridge.sock.sendall.assert_called_once()

    def test_send_causal_id_map_full(self):
        """BPF Map 满 → ACK status=1 → 返回 False"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge.sock = MagicMock()
        bridge.sock.recv.return_value = b"\x01\x01"  # ACK status=1

        result = bridge._send_causal_id(b"\x01" * 32, "test_tool")
        assert result is False

    def test_send_causal_id_no_socket(self):
        """Socket 不存在时尝试连接，失败返回 False"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge.sock = None
        with patch("socket.socket") as mock_socket_class:
            mock_socket_class.return_value.connect.side_effect = FileNotFoundError
            result = bridge._send_causal_id(b"\x01" * 32, "test_tool")
            assert result is False

    @pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                        reason="AF_UNIX 仅在类 Unix 平台可用")
    def test_send_causal_id_reconnect(self):
        """sock 为 None 时自动重连"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge.sock = None
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x01\x00"

        with patch("socket.socket", return_value=mock_sock):
            result = bridge._send_causal_id(b"\x01" * 32, "test_tool")
            assert result is True
            mock_sock.connect.assert_called_once_with("/var/run/causal-guardian.sock")


class TestFridaBridgeMessages:
    """on_message 消息分发测试"""

    def test_on_message_context_caches_input(self):
        """context 消息 → 缓存 input_messages"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        msg = {"type": "context", "input_messages": "User: summarize this file", "session_id": "abc"}
        bridge.on_message(msg, None)
        assert bridge._input_messages == "User: summarize this file"

    def test_on_message_tool_call_no_exception(self):
        """tool_call 消息 → 不抛异常"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        msg = {"type": "tool_call", "tool_name": "read_file", "params": "/tmp/test.txt"}
        bridge.on_message(msg, None)  # 不抛异常

    def test_on_message_request_causal_id_unverified(self):
        """request_causal_id → 审计引擎不可用 → 回传 UNVERIFIED"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge._script = MagicMock()
        msg = {"type": "request_causal_id", "tool_name": "bash_exec",
               "params": "ls", "request_id": "req-123", "input_messages": ""}

        with patch.object(bridge, "request_causal_id") as mock_req:
            mock_req.return_value = {"causal_id": None, "decision": "ask",
                                     "reason": "timeout", "mode": "ask"}
            bridge.on_message(msg, None)

        bridge._script.post.assert_called_once()
        posted = bridge._script.post.call_args[0][0]
        assert posted["type"] == "causal_id_response"
        assert posted["request_id"] == "req-123"
        assert posted["causal_id"].startswith("UNVERIFIED_")

    def test_on_message_request_causal_id_allowed(self):
        """request_causal_id → ALLOW + 有效 causal_id → Socket 注册 → 回传"""
        from src.frida.bridge import FridaBridge

        bridge = FridaBridge()
        bridge._script = MagicMock()
        msg = {"type": "request_causal_id", "tool_name": "bash_exec",
               "params": "ls", "request_id": "req-456", "input_messages": ""}

        causal_id_hex = "aa" * 32
        with patch.object(bridge, "request_causal_id") as mock_req:
            mock_req.return_value = {"causal_id": causal_id_hex, "decision": "allow",
                                     "reason": "ok", "mode": "enforcing"}
            with patch.object(bridge, "_send_causal_id", return_value=True):
                bridge.on_message(msg, None)

        bridge._script.post.assert_called_once()
        posted = bridge._script.post.call_args[0][0]
        assert posted["causal_id"] == causal_id_hex


class TestFridaBridge:
    """构造函数初始化测试"""

    def test_runtime_default_is_python(self):
        """默认 runtime 应为 'python'"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        assert bridge.runtime == "python"

    def test_runtime_node_explicit(self):
        """显式指定 runtime='node'"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge(runtime="node")
        assert bridge.runtime == "node"

    def test__system_prompt_initial_empty(self):
        """_system_prompt 初始为空字符串"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        assert bridge._system_prompt == ""

    def test__last_http_call_initial_none(self):
        """_last_http_call 初始为 None"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        assert bridge._last_http_call is None


class TestOnMessage:
    """on_message system_prompt 和 http_outbound 消息测试"""

    def test_on_message_system_prompt_updates_field(self):
        """system_prompt 消息应更新 _system_prompt"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        msg = {"type": "system_prompt", "content": "You are a helpful assistant."}
        bridge.on_message(msg, b"")
        assert bridge._system_prompt == "You are a helpful assistant."

    def test_on_message_system_prompt_empty_content(self):
        """system_prompt 消息无 content 时设为空字符串"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        bridge._system_prompt = "old"
        msg = {"type": "system_prompt"}
        bridge.on_message(msg, b"")
        assert bridge._system_prompt == ""

    def test_on_message_http_outbound_records_call(self):
        """http_outbound 消息应记录最后一次 HTTP 调用"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        msg = {"type": "http_outbound", "method": "POST", "url": "http://evil.com/api"}
        bridge.on_message(msg, b"")
        assert bridge._last_http_call == {"method": "POST", "url": "http://evil.com/api"}

    def test_on_message_http_outbound_overwrites_previous(self):
        """连续的 http_outbound 消息应覆盖上一次记录"""
        from src.frida.bridge import FridaBridge
        bridge = FridaBridge()
        bridge.on_message({"type": "http_outbound", "method": "GET", "url": "http://a.com"}, b"")
        bridge.on_message({"type": "http_outbound", "method": "POST", "url": "http://b.com"}, b"")
        assert bridge._last_http_call == {"method": "POST", "url": "http://b.com"}


# ── TCP 消息帧 + PSK 认证测试 ──────────────────────────

import socket
import struct
import threading
import time

import pytest


class TestTcpFraming:
    """TCP 消息帧编解码"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from src.frida.bridge import _recv_msg, _send_msg
        self._recv_msg = _recv_msg
        self._send_msg = _send_msg

    def test_roundtrip_small(self):
        """小消息往返"""
        a, b = socket.socketpair()
        msg = {"type": "test", "data": "hello"}
        assert self._send_msg(a, msg)
        received = self._recv_msg(b, timeout=1.0)
        assert received == msg
        a.close(); b.close()

    def test_roundtrip_large(self):
        """大消息往返 (>4KB)"""
        a, b = socket.socketpair()
        msg = {"type": "test", "data": "x" * 8192}
        assert self._send_msg(a, msg)
        received = self._recv_msg(b, timeout=1.0)
        assert received == msg
        a.close(); b.close()

    def test_recv_timeout(self):
        """超时返回 None"""
        a, b = socket.socketpair()
        received = self._recv_msg(b, timeout=0.1)
        assert received is None
        a.close(); b.close()

    def test_recv_closed_socket(self):
        """对端关闭返回 None"""
        a, b = socket.socketpair()
        a.close()
        received = self._recv_msg(b, timeout=1.0)
        assert received is None
        b.close()

    def test_oversized_message_rejected(self):
        """超 64KB 消息被拒绝"""
        a, b = socket.socketpair()
        header = struct.pack(">I", 65537)
        a.sendall(header)
        received = self._recv_msg(b, timeout=0.5)
        assert received is None
        a.close(); b.close()


class TestPskAuth:
    """PSK 认证集成测试"""

    def test_auth_ok_and_rejected(self):
        """PSK 匹配 → ok, 不匹配 → rejected"""
        from src.frida.bridge import GadgetBridge, _recv_msg, _send_msg

        tmp_psk = tempfile.NamedTemporaryFile(delete=False, suffix=".psk")
        tmp_psk.write(b"test_auth_psk_32bytes_xxxxxxxxx")
        tmp_psk.close()

        import src.frida.bridge as bridge_mod
        old_psk_path = bridge_mod.PSK_PATH
        bridge_mod.PSK_PATH = tmp_psk.name

        bridge = GadgetBridge()
        t = threading.Thread(target=bridge.start, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            # 错误 PSK → rejected
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 27042))
            _send_msg(sock, {"type": "auth", "psk": "wrong_psk", "pid": 1})
            resp = _recv_msg(sock, timeout=1.0)
            assert resp is not None and resp["status"] == "rejected"
            sock.close()

            # 正确 PSK → ok
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect(("127.0.0.1", 27042))
            _send_msg(sock2, {"type": "auth", "psk": "test_auth_psk_32bytes_xxxxxxxxx", "pid": 42})
            resp2 = _recv_msg(sock2, timeout=1.0)
            assert resp2 is not None and resp2["status"] == "ok"
            sock2.close()
        finally:
            bridge.stop()
            bridge_mod.PSK_PATH = old_psk_path
            t.join(timeout=2.0)

    def test_auth_timeout(self):
        """3 秒内不发 auth → bridge 断开连接"""
        from src.frida.bridge import GadgetBridge

        bridge = GadgetBridge()
        t = threading.Thread(target=bridge.start, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 27042))
            # 不发 auth，等待超时
            time.sleep(3.5)
            try:
                data = sock.recv(4)
                assert len(data) == 0  # 正常关闭 (FIN)
            except (TimeoutError, ConnectionError):
                pass  # 异常关闭也可接受
            sock.close()
        finally:
            bridge.stop()
            t.join(timeout=2.0)
