import math
from collections import deque
from dataclasses import dataclass


@dataclass
class StatsSnapshot:
    interval_p95_ms: float = 0.0
    entropy_current: float = 0.0
    entropy_heuristic_upper: float = 0.0
    taint_ratio: float = 0.0
    graph_unknown_count: int = 0


class StatsBaseline:
    """统计基线引擎 — 仅输出到可视化大屏，不参与决策"""

    def __init__(self, window_size: int = 100):
        self._window_size = window_size
        self._sessions: dict[str, dict] = {}

    def _ensure_session(self, session_id: str) -> None:
        if session_id not in self._sessions:
            self._sessions[session_id] = {
                "intervals": deque(maxlen=self._window_size),
                "tools": deque(maxlen=self._window_size),
                "tainted_count": 0,
                "graph_unknown": 0,
                "total": 0,
            }

    def record_call(self, session_id: str, tool_name: str,
                    interval_ms: float, tainted: bool,
                    graph_matched: bool) -> None:
        self._ensure_session(session_id)
        s = self._sessions[session_id]
        s["intervals"].append(interval_ms)
        s["tools"].append(tool_name)
        s["total"] += 1
        if tainted:
            s["tainted_count"] += 1
        if not graph_matched:
            s["graph_unknown"] += 1

    def get_snapshot(self, session_id: str) -> StatsSnapshot:
        s = self._sessions.get(session_id)
        if not s or s["total"] == 0:
            return StatsSnapshot()
        intervals = list(s["intervals"])
        intervals.sort()
        p95_idx = max(int(len(intervals) * 0.95 + 0.5), 0)
        p95_idx = min(p95_idx, len(intervals) - 1)
        p95 = intervals[p95_idx] if intervals else 0.0

        tool_counts = {}
        for t in s["tools"]:
            tool_counts[t] = tool_counts.get(t, 0) + 1
        total_tools = sum(tool_counts.values())
        if total_tools > 0:
            probs = [c / total_tools for c in tool_counts.values()]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        else:
            entropy = 0.0

        taint_ratio = s["tainted_count"] / s["total"] if s["total"] > 0 else 0.0

        return StatsSnapshot(
            interval_p95_ms=p95,
            entropy_current=entropy,
            entropy_heuristic_upper=entropy * 1.5,
            taint_ratio=taint_ratio,
            graph_unknown_count=s["graph_unknown"],
        )

    def reset(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
