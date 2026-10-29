"""工具调用图的会话隔离与 fail-closed 行为（P0-3 / P0-4）。"""

from src.engine.graph_constraint import Decision, GraphConstraint
from src.engine.template_matcher import TaskTemplate


def _tpl(tid: str, graph: dict, forbidden: list[str] | None = None) -> TaskTemplate:
    return TaskTemplate(
        id=tid,
        label=tid,
        graph=graph,
        terminals=[],
        forbidden_tool_categories=forbidden or [],
        require_slm_review=[],
    )


RESUME = _tpl("resume_summary", {
    "read_file": ["summarize"],
    "summarize": ["send_email"],
})

DB = _tpl("db_query_optimization", {
    "db_query": ["summarize"],
    "summarize": [],
}, forbidden=["DDL"])


def test_sessions_do_not_share_templates():
    """A 会话装载模板后，B 会话装载自己的模板不能影响 A 的判定（P0-4）"""
    gc = GraphConstraint()
    gc.load_template(RESUME, "sess-A")
    gc.load_template(DB, "sess-B")

    # A：read_file → summarize 是合法边
    assert gc.check("sess-A", "read_file", []).decision == Decision.ALLOW
    assert gc.check("sess-A", "summarize", []).decision == Decision.ALLOW

    # B：从 read_file 出发没有任何边，应当 ASK（不是沿用 A 的图）
    assert gc.check("sess-B", "read_file", []).decision == Decision.ALLOW  # 入口节点
    assert gc.check("sess-B", "summarize", []).decision == Decision.ASK    # 图上无边

    # A 继续走自己的图，仍然合法
    assert gc.check("sess-A", "send_email", []).decision == Decision.ALLOW


def test_forbidden_categories_are_per_session():
    """禁止类别也必须按会话取，不能读到别的会话的模板"""
    gc = GraphConstraint()
    gc.load_template(RESUME, "sess-A")
    gc.load_template(DB, "sess-B")

    assert gc.forbidden_for("sess-A") == []
    assert gc.forbidden_for("sess-B") == ["DDL"]


def test_no_template_is_fail_closed():
    """模板未命中时不得无条件放行（P0-3）"""
    gc = GraphConstraint()
    result = gc.check("sess-unknown", "bash_exec", [])
    assert result.decision == Decision.ASK
    assert "fail-closed" in result.reason


def test_no_template_can_be_relaxed_explicitly():
    """只有显式关闭 fail_closed 才允许放行（留出测试/演示的口子）"""
    gc = GraphConstraint()
    gc._fail_closed = False
    result = gc.check("sess-unknown", "bash_exec", [])
    assert result.decision == Decision.ALLOW


def test_blacklist_still_wins_without_template():
    """即使没有模板，全局黑名单也必须阻断"""
    gc = GraphConstraint()
    gc.set_blacklist(["bash_exec"])
    result = gc.check("sess-x", "bash_exec", [])
    assert result.decision == Decision.BLOCK


def test_forget_session_clears_state():
    """会话结束后清理，避免字典无界增长"""
    gc = GraphConstraint()
    gc.load_template(RESUME, "sess-C")
    gc.check("sess-C", "read_file", [])
    assert gc.get_path("sess-C") == ["read_file"]

    gc.forget_session("sess-C")
    assert gc.get_path("sess-C") == []
    # 清理后回到 fail-closed
    assert gc.check("sess-C", "read_file", []).decision == Decision.ASK


def test_default_template_still_works():
    """不带 session_id 的装载仍写入默认模板（兼容既有调用与测试）"""
    gc = GraphConstraint()
    gc.load_template(RESUME)
    assert gc.check("any", "read_file", []).decision == Decision.ALLOW
