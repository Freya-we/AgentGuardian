import time
from enum import Enum


class TaintTag(Enum):
    USER_INPUT = "USER_INPUT"
    UNTRUSTED_FILE = "UNTRUSTED_FILE"
    UNTRUSTED_API = "UNTRUSTED_API"
    SYSTEM_TRUSTED = "SYSTEM_TRUSTED"
    DERIVED_UNTRUSTED = "DERIVED_UNTRUSTED"
    TAINTED = "TAINTED"


# 只有这两个不可信来源会触发传播
UNTRUSTED_SOURCES = {TaintTag.UNTRUSTED_FILE, TaintTag.UNTRUSTED_API}

DEFAULT_TTL_SECONDS = 3600


class TaintTracker:
    """污点追踪器 — 仅追加，支持会话过期清理"""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._sessions: dict[str, list[TaintTag]] = {}
        self._last_access: dict[str, float] = {}
        self._ttl_seconds = ttl_seconds

    def _ensure_session(self, session_id: str) -> None:
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        self._last_access[session_id] = time.monotonic()

    def tag_source(self, session_id: str, source_type: TaintTag) -> None:
        self._ensure_session(session_id)
        tags = self._sessions[session_id]
        if source_type not in tags:
            tags.append(source_type)

    def propagate(self, session_id: str, tool_name: str,
                  params_hash: str) -> list[TaintTag]:
        self._ensure_session(session_id)
        tags = self._sessions[session_id]
        has_untrusted = any(t in UNTRUSTED_SOURCES for t in tags)
        if has_untrusted:
            if TaintTag.DERIVED_UNTRUSTED not in tags:
                tags.append(TaintTag.DERIVED_UNTRUSTED)
            if TaintTag.TAINTED not in tags:
                tags.append(TaintTag.TAINTED)
        return list(tags)

    def get_active_tags(self, session_id: str) -> list[TaintTag]:
        return list(self._sessions.get(session_id, []))

    def is_tainted(self, session_id: str) -> bool:
        return len(self._sessions.get(session_id, [])) > 0

    def cleanup_old_sessions(self, ttl_seconds: int | None = None) -> int:
        """清理超过 TTL 未访问的会话，返回清理数量"""
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl_seconds
        now = time.monotonic()
        expired = [
            sid for sid, last in self._last_access.items()
            if now - last > ttl
        ]
        for sid in expired:
            self._sessions.pop(sid, None)
            self._last_access.pop(sid, None)
        return len(expired)
