import os
import socket

import pytest

from src.engine.key_manager import KeyManager, _send_key_update


class TestKeyManager:
    def test_derive_session_key_returns_32_bytes(self):
        km = KeyManager()
        mk = os.urandom(32)
        sk = km.derive_session_key(mk, 0)
        assert isinstance(sk, bytes)
        assert len(sk) == 32

    def test_derive_different_rounds_different_keys(self):
        km = KeyManager()
        mk = os.urandom(32)
        k0 = km.derive_session_key(mk, 0)
        k1 = km.derive_session_key(mk, 1)
        assert k0 != k1

    def test_derive_deterministic(self):
        km = KeyManager()
        mk = b"f" * 32
        assert km.derive_session_key(mk, 3) == km.derive_session_key(mk, 3)

    def test_initialize_creates_session_keys(self, tmp_path, monkeypatch):
        # 隔离全局轮换状态文件，避免依赖机器上的历史状态
        monkeypatch.setattr("src.engine.key_manager.STATE_PATH",
                            str(tmp_path / "state.json"))
        key_file = tmp_path / "master.key"
        key_file.write_bytes(os.urandom(32))
        km = KeyManager()
        keys = km.initialize(str(key_file))
        assert len(keys.active) == 32
        assert keys.grace == b""
        assert keys.round == 1

    @pytest.mark.asyncio
    async def test_rotate_swaps_active_to_grace(self, tmp_path, monkeypatch):
        key_file = tmp_path / "master.key"
        key_file.write_bytes(os.urandom(32))
        monkeypatch.setattr(KeyManager, "_save_state", lambda *a, **kw: None)
        km = KeyManager()
        k1 = km.initialize(str(key_file))
        k2 = await km.rotate()
        assert k2.active != k1.active
        assert k2.grace == k1.active
        assert k2.round == k1.round + 1

    def test_master_key_too_short_raises(self, tmp_path):
        """master key 不足 32 字节时抛出 ValueError"""
        km = KeyManager()
        key_file = tmp_path / "short.key"
        key_file.write_bytes(b"short")
        with pytest.raises(ValueError, match="Master key too short"):
            km.initialize(str(key_file))

    @pytest.mark.asyncio
    async def test_rotate_before_initialize_raises(self):
        """未初始化即轮换密钥应抛出 RuntimeError"""
        km = KeyManager()
        with pytest.raises(RuntimeError, match="KeyManager not initialized"):
            await km.rotate()

    def test_send_key_update_socket_not_found(self):
        """socket 不存在时返回 False (不抛异常)"""
        result = _send_key_update(b"\x01" * 32, b"\x02" * 32)
        assert result is False

    def test_send_key_update_connection_refused(self):
        """Socket 路径存在但无人监听 → 返回 False"""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            sock_path = tf.name
        try:
            from src.engine import key_manager
            key_manager.SOCKET_PATH = sock_path
            os.remove(sock_path)  # 删除文件使其成为不存在但可写的路径
            result = _send_key_update(b"\x01" * 32, b"\x02" * 32)
            assert result is False
        finally:
            key_manager.SOCKET_PATH = "/var/run/causal-guardian.sock"

    @pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                        reason="AF_UNIX 仅在类 Unix 平台可用")
    def test_send_key_update_ack_rejected(self, monkeypatch):
        """Socket ACK status != 0 → 返回 False"""
        from unittest.mock import MagicMock
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x01\x01"  # status=1 (write fail)
        monkeypatch.setattr("socket.socket", lambda *a, **kw: mock_sock)

        result = _send_key_update(b"\x01" * 32, b"\x02" * 32)
        assert result is False
        mock_sock.connect.assert_called_once()
        mock_sock.sendall.assert_called_once()
        mock_sock.close.assert_called_once()

    def test_rotate_grace_key_is_previous_active(self, tmp_path, monkeypatch):
        """轮换后 grace key 等于之前 active key"""
        key_file = tmp_path / "master.key"
        key_file.write_bytes(os.urandom(32))
        monkeypatch.setattr(KeyManager, "_save_state", lambda *a, **kw: None)
        km = KeyManager()
        keys1 = km.initialize(str(key_file))

        import asyncio
        keys2 = asyncio.run(km.rotate())
        assert keys2.grace == keys1.active
