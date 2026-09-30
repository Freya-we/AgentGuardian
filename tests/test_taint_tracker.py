import time

from src.engine.taint_tracker import TaintTag, TaintTracker


class TestTaintTracker:
    def test_tag_source_adds_tag(self):
        tt = TaintTracker()
        tt.tag_source("s1", TaintTag.UNTRUSTED_FILE)
        assert TaintTag.UNTRUSTED_FILE in tt.get_active_tags("s1")

    def test_propagate_derives_tainted(self):
        tt = TaintTracker()
        tt.tag_source("s1", TaintTag.UNTRUSTED_API)
        tags = tt.propagate("s1", "summarize", "abc123")
        assert TaintTag.DERIVED_UNTRUSTED in tags
        assert TaintTag.TAINTED in tags

    def test_no_source_no_taint(self):
        tt = TaintTracker()
        tags = tt.propagate("s2", "read_file", "hash1")
        assert len(tags) == 0

    def test_is_tainted_true(self):
        tt = TaintTracker()
        tt.tag_source("s3", TaintTag.UNTRUSTED_FILE)
        assert tt.is_tainted("s3") is True

    def test_is_tainted_false(self):
        tt = TaintTracker()
        assert tt.is_tainted("s4") is False

    def test_get_active_tags_distinct(self):
        tt = TaintTracker()
        tt.tag_source("s5", TaintTag.UNTRUSTED_FILE)
        tt.tag_source("s5", TaintTag.UNTRUSTED_API)
        tags = {t.value for t in tt.get_active_tags("s5")}
        assert "UNTRUSTED_FILE" in tags
        assert "UNTRUSTED_API" in tags

    def test_trusted_source_no_propagation(self):
        tt = TaintTracker()
        tt.tag_source("s6", TaintTag.SYSTEM_TRUSTED)
        tags = tt.propagate("s6", "read_file", "hash2")
        assert TaintTag.DERIVED_UNTRUSTED not in tags

    def test_cleanup_removes_expired_sessions(self):
        tt = TaintTracker(ttl_seconds=0)  # TTL=0, 立即过期
        tt.tag_source("old", TaintTag.UNTRUSTED_FILE)
        time.sleep(0.1)
        removed = tt.cleanup_old_sessions()
        assert removed >= 1
        assert tt.get_active_tags("old") == []

    def test_cleanup_keeps_active_sessions(self):
        tt = TaintTracker(ttl_seconds=60)
        tt.tag_source("active", TaintTag.UNTRUSTED_FILE)
        removed = tt.cleanup_old_sessions()
        assert removed == 0
        assert len(tt.get_active_tags("active")) == 1

    def test_cleanup_custom_ttl_override(self, monkeypatch):
        tt = TaintTracker(ttl_seconds=60)
        tt.tag_source("soon", TaintTag.UNTRUSTED_FILE)
        # 时钟前进 61s，超过 TTL，强制清理（避免依赖真实时钟推进）
        now = time.monotonic()
        monkeypatch.setattr("src.engine.taint_tracker.time.monotonic",
                            lambda: now + 61)
        removed = tt.cleanup_old_sessions()
        assert removed == 1
