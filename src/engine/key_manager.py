import hashlib
import hmac
import json
import logging
import os
import socket
import struct
from dataclasses import dataclass


@dataclass
class SessionKeys:
    active: bytes
    grace: bytes
    round: int


logger = logging.getLogger(__name__)

SOCKET_PATH = "/var/run/causal-guardian.sock"
STATE_PATH = "/var/lib/agent-guardian/state.json"


def _send_key_update(active_key: bytes, grace_key: bytes) -> bool:
    """通过 Unix Socket 向 causal-guardian 推送新 Session Key"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect(SOCKET_PATH)
        msg = struct.pack("<B32s32s", 0x02, active_key, grace_key)
        sock.sendall(msg)
        ack = sock.recv(2)
        sock.close()
        if ack[1] != 0:
            logger.warning(f"MSG_KEY_UPDATE 被拒绝: status={ack[1]}")
            return False
        logger.info("MSG_KEY_UPDATE 成功 (round active_key 已推送)")
        return True
    except FileNotFoundError:
        logger.warning(f"causal-guardian socket 不存在 ({SOCKET_PATH})，密钥轮换跳过")
        return False
    except Exception as e:
        logger.warning(f"MSG_KEY_UPDATE 发送失败: {e}")
        return False


class KeyManager:
    """Session Key 管理: HKDF-Expand 派生 + 轮换 + 持久化"""

    @staticmethod
    def _load_state() -> int:
        try:
            with open(STATE_PATH) as f:
                return json.load(f)["round"]
        except Exception:
            return 1

    @staticmethod
    def _save_state(round: int) -> None:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump({"round": round}, f)

    def derive_session_key(self, master_key: bytes, round: int) -> bytes:
        info = f"session-{round}".encode()
        # HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
        # master_key 已是高熵随机密钥，跳过 Extract 阶段，直接 Expand
        return hmac.new(master_key, info + b"\x01", hashlib.sha256).digest()

    def initialize(self, master_key_path: str) -> SessionKeys:
        with open(master_key_path, "rb") as f:
            raw = f.read()
        # 兼容文本格式密钥文件 (末尾换行)；但二进制密钥恰好以 \r/\n
        # 结尾时不能剥离，否则会破坏密钥内容
        master_key = raw.rstrip(b"\r\n")
        if len(master_key) < 32 <= len(raw):
            master_key = raw
        if len(master_key) < 32:
            raise ValueError(f"Master key too short: {len(master_key)} bytes")

        self._master_key = master_key[:32]
        start_round = self._load_state()
        self._round = start_round
        self._active = self.derive_session_key(self._master_key, start_round)
        self._grace = b""
        logger.info(f"KeyManager 初始化: round={start_round}")
        return SessionKeys(active=self._active, grace=self._grace, round=self._round)

    async def rotate(self) -> SessionKeys:
        if not hasattr(self, "_master_key"):
            raise RuntimeError("KeyManager not initialized")
        new_round = self._round + 1
        new_active = self.derive_session_key(self._master_key, new_round)
        old_active = self._active
        keys = SessionKeys(active=new_active, grace=old_active, round=new_round)
        self._active = new_active
        self._grace = old_active
        self._round = new_round
        self._save_state(new_round)
        _send_key_update(keys.active, keys.grace)
        return keys
