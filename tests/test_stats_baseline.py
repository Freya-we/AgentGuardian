"""统计基线引擎测试 — 边界条件和异常路径"""
from src.engine.stats_baseline import StatsBaseline


class TestStatsBaseline:
    def test_snapshot_defaults_for_unknown_session(self):
        """未知 session → 返回全零快照"""
        sb = StatsBaseline()
        snap = sb.get_snapshot("nonexistent")
        assert snap.interval_p95_ms == 0.0
        assert snap.entropy_current == 0.0
        assert snap.taint_ratio == 0.0
        assert snap.graph_unknown_count == 0

    def test_snapshot_single_call(self):
        """单次调用: P95 = 该间隔, 熵 = 0 (单一工具)"""
        sb = StatsBaseline()
        sb.record_call("s1", "read_file", 50.0, tainted=False, graph_matched=True)
        snap = sb.get_snapshot("s1")
        assert snap.interval_p95_ms == 50.0
        assert snap.entropy_current == 0.0  # 仅一种工具
        assert snap.taint_ratio == 0.0
        assert snap.graph_unknown_count == 0

    def test_snapshot_multiple_calls_p95(self):
        """100 次调用: P95 正确计算"""
        sb = StatsBaseline(window_size=100)
        for i in range(100):
            sb.record_call("s1", f"tool_{i % 5}", float(i + 1),
                          tainted=(i % 10 == 0), graph_matched=(i % 5 != 0))
        snap = sb.get_snapshot("s1")
        assert snap.interval_p95_ms == 96.0  # intervals[95] with 100 values 1-100
        assert snap.entropy_current > 0.0
        assert snap.taint_ratio == 0.1  # 10/100
        assert snap.graph_unknown_count == 20  # 1/5 未匹配

    def test_reset_clears_session(self):
        """reset 后快照归零"""
        sb = StatsBaseline()
        sb.record_call("s1", "read_file", 10.0, tainted=False, graph_matched=True)
        sb.reset("s1")
        snap = sb.get_snapshot("s1")
        assert snap.interval_p95_ms == 0.0

    def test_entropy_multiple_tools(self):
        """多工具调用的熵值计算"""
        sb = StatsBaseline()
        for tool in ["read_file", "summarize", "send_email"]:
            for _ in range(10):
                sb.record_call("s1", tool, 1.0, tainted=False, graph_matched=True)
        snap = sb.get_snapshot("s1")
        # 3 种工具均匀分布 → log2(3) ≈ 1.585
        assert abs(snap.entropy_current - 1.585) < 0.01
