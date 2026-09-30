import hashlib
import hmac
import secrets

# 与 src/ebpf/causal_chain.h 中 CAUSAL_ID_TTL_NS 保持一致
CAUSAL_ID_TTL_NS = 5_000_000_000  # 5 秒


class HmacSigner:
    """HMAC-SHA256 CausalID 签名器

    Payload 格式: {pid}|{tool_name}|{timestamp_ns}|{ttl_ns}
    TTL 嵌入签名防止重放攻击 — 窃取的 CausalID 仅在签发 + TTL 窗口内有效。
    """

    def sign(self, session_key: bytes, pid: int, tool_name: str,
             timestamp_ns: int, ttl_ns: int = CAUSAL_ID_TTL_NS) -> bytes:
        payload = f"{pid}|{tool_name}|{timestamp_ns}|{ttl_ns}".encode()
        return hmac.new(session_key, payload, hashlib.sha256).digest()

    def verify(self, key: bytes, causal_id: bytes, pid: int,
               tool_name: str, timestamp_ns: int,
               ttl_ns: int = CAUSAL_ID_TTL_NS) -> bool:
        expected = self.sign(key, pid, tool_name, timestamp_ns, ttl_ns)
        return hmac.compare_digest(expected, causal_id)


def generate_unverified_token() -> bytes:
    """生成降级 token — 审计引擎无法决策时允许 Agent 继续但标记为未验证"""
    nonce = secrets.token_hex(8)
    return f"UNVERIFIED_{nonce}".encode()
