import pytest

from src.engine.graph_constraint import Decision, GraphConstraint
from src.engine.template_matcher import TaskTemplate


class TestGraphConstraint:
    @pytest.fixture
    def template(self):
        return TaskTemplate(
            id="test_task", label="测试",
            graph={"read_file": ["summarize", "search_web"],
                   "summarize": ["send_email"],
                   "search_web": ["summarize"]},
            terminals=["send_email"],
            forbidden_tool_categories=["DDL"],
            require_slm_review=["send_email"],
        )

    def test_valid_edge_without_taint_is_allowed(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        result = gc.check("s1", "read_file", [])
        assert result.decision == Decision.ALLOW

    def test_entry_node_with_taint_is_ask(self, template):
        """入口节点 + 污点标签 → ASK（交内容审查而非直接放行）"""
        gc = GraphConstraint()
        gc.load_template(template)
        result = gc.check("s1-taint", "read_file", ["UNTRUSTED_FILE"])
        assert result.decision == Decision.ASK
        assert "污点" in result.reason

    def test_valid_edge_sequence(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s2", "read_file", [])
        result = gc.check("s2", "summarize", [])
        assert result.decision == Decision.ALLOW

    def test_valid_edge_with_taint_is_ask(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s3", "read_file", [])
        result = gc.check("s3", "summarize", ["UNTRUSTED_FILE"])
        assert result.decision == Decision.ASK

    def test_no_edge_high_risk_is_blocked(self, template):
        gc = GraphConstraint()
        gc.set_blacklist(["bash_exec", "file_delete", "config_modify"])
        gc.load_template(template)
        gc.check("s4", "read_file", [])
        result = gc.check("s4", "bash_exec", [])
        assert result.decision == Decision.BLOCK

    def test_set_blacklist_updates_blocked_tools(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s0", "read_file", [])

        # 初始无黑名单，已注册工具允许
        r1 = gc.check("s0", "summarize", [])
        assert r1.decision == Decision.ALLOW

        # 动态添加黑名单后，图中边存在但仍放行（不受黑名单影响）
        gc.set_blacklist(["some_other_tool"])
        r2 = gc.check("s0", "bash_exec", [])
        # bash_exec 不在图中，不在 forbidden_categories，不新在黑名单中
        # 所以是 ASK（非敏感工具，图中无边）
        assert r2.decision == Decision.ASK

        # 将 bash_exec 加入黑名单后应被阻断
        gc.set_blacklist(["bash_exec"])
        r3 = gc.check("s0", "bash_exec", [])
        assert r3.decision == Decision.BLOCK

    def test_forbidden_category_blocked(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s5", "read_file", [])
        # 模拟 DDL 类工具在 forbidden_categories 中
        gc._forbidden_categories = ["DROP_TABLE"]
        result = gc.check("s5", "DROP_TABLE", [])
        assert result.decision == Decision.BLOCK

    def test_get_path_returns_history(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s6", "read_file", [])
        gc.check("s6", "summarize", [])
        assert gc.get_path("s6") == ["read_file", "summarize"]

    def test_add_edge_allows_new_path(self, template):
        gc = GraphConstraint()
        gc.load_template(template)
        gc.check("s7", "read_file", [])
        gc.add_edge("s7", "read_file", "new_tool")
        result = gc.check("s7", "new_tool", [])
        assert result.decision == Decision.ALLOW
