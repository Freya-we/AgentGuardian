"""工具调用图约束引擎。

设计要点（P0-3 / P0-4 修复）：

1. **按会话持有模板**：早期实现把模板存在实例字段上，多个会话并发时会互相覆盖，
   导致 A 会话按 B 会话的图判定。现在按 session_id 隔离，
   全局字段只作为"无会话上下文"时的默认值（测试与兼容用）。

2. **无模板时 fail-closed**：早期实现中，模板未命中时图是空的，
   而"入口节点"分支会无条件放行，等于任何未被模板识别的会话第一次工具调用必然 ALLOW。
   现在没有可用模板时返回 ASK（不签发票据 → 内核层阻断），需要放行必须显式配置策略。

实现边界（保持原有说明）：
本模块是静态邻接表白名单，非因果推断引擎。它检查当前工具是否在上一工具的
合法后继集合中，但无法检测"图路径合法但参数恶意"的攻击（如 read_file →
summarize → send_email 路径中 summarize 结果含窃取的 SSH 密钥）。
该场景依赖污点追踪 + 规则引擎的多层交叉验证。
"""

import threading
from dataclasses import dataclass
from enum import Enum

from src.engine.template_matcher import TaskTemplate


class Decision(Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


@dataclass
class GraphCheckResult:
    decision: Decision
    reason: str
    current_path: list[str]


class GraphConstraint:
    """工具调用图约束引擎 — O(1) 字典查询，按会话隔离模板，threading.Lock 保护并发访问"""

    def __init__(self) -> None:
        # 默认模板（无会话上下文时使用；正常路径下由 load_template 按会话写入）
        self._graph: dict[str, list[str]] = {}
        self._terminals: list[str] = []
        self._forbidden_categories: list[str] = []

        self._session_templates: dict[str, TaskTemplate] = {}
        self._session_paths: dict[str, list[str]] = {}
        self._blacklist: set[str] = set()
        self._lock = threading.Lock()
        # 无可用策略时是否阻断（fail-closed）。生产环境不要关掉。
        self._fail_closed = True

    # ── 策略装载 ────────────────────────────────────

    def set_blacklist(self, blacklist: list[str]) -> None:
        with self._lock:
            self._blacklist = set(blacklist)

    def load_template(self, template: TaskTemplate, session_id: str | None = None) -> None:
        """装载模板。带 session_id 时按会话隔离；不带时写入默认模板。"""
        if template is None:
            raise ValueError("template 不能为 None")
        if not template.graph:
            raise ValueError(f"模板 {template.id} 的 graph 为空")
        with self._lock:
            if session_id is None:
                self._graph = {k: list(v) for k, v in template.graph.items()}
                self._terminals = list(template.terminals)
                self._forbidden_categories = list(template.forbidden_tool_categories)
            else:
                self._session_templates[session_id] = template

    def forget_session(self, session_id: str) -> None:
        """会话结束时清理，避免字典无界增长"""
        with self._lock:
            self._session_templates.pop(session_id, None)
            self._session_paths.pop(session_id, None)

    def session_ids(self) -> list[str]:
        """当前持有路径或模板的全部会话 id（跨容器清理联动用）"""
        with self._lock:
            return list(set(self._session_paths) | set(self._session_templates))

    @property
    def forbidden_categories(self) -> list[str]:
        with self._lock:
            return list(self._forbidden_categories)

    @forbidden_categories.setter
    def forbidden_categories(self, value: list[str]) -> None:
        with self._lock:
            self._forbidden_categories = list(value)

    def forbidden_for(self, session_id: str) -> list[str]:
        """返回该会话实际生效的禁止类别"""
        with self._lock:
            template = self._session_templates.get(session_id)
            if template is not None:
                return list(template.forbidden_tool_categories)
            return list(self._forbidden_categories)

    def _effective(self, session_id: str) -> tuple[dict[str, list[str]] | None, list[str]]:
        """返回 (图, 禁止类别)；图不存在时返回 (None, ...) 表示没有可用策略"""
        template = self._session_templates.get(session_id)
        if template is not None:
            return template.graph, list(template.forbidden_tool_categories)
        if self._graph:
            return self._graph, list(self._forbidden_categories)
        return None, list(self._forbidden_categories)

    # ── 判定 ────────────────────────────────────────

    def check(self, session_id: str, tool_name: str,
              taint_tags: list[str]) -> GraphCheckResult:
        with self._lock:
            return self._check_impl(session_id, tool_name, taint_tags)

    def _check_impl(self, session_id: str, tool_name: str,
                    taint_tags: list[str]) -> GraphCheckResult:
        path = self._session_paths.setdefault(session_id, [])
        prev_tool = path[-1] if path else None
        has_taint = len(taint_tags) > 0
        graph, forbidden = self._effective(session_id)

        # 1. 全局黑名单优先
        if tool_name in self._blacklist:
            path.append(tool_name)
            return GraphCheckResult(Decision.BLOCK,
                                    f"工具 {tool_name} 在全局黑名单中",
                                    list(path))

        # 2. 没有可用策略 → fail-closed（P0-3）
        if graph is None:
            path.append(tool_name)
            if self._fail_closed:
                return GraphCheckResult(
                    Decision.ASK,
                    "无匹配的任务模板，按 fail-closed 处理（不签发票据）",
                    list(path),
                )
            return GraphCheckResult(Decision.ALLOW, "无可用模板且 fail_closed 已关闭",
                                    list(path))

        # 3. 入口节点：图中无前驱 → 无污点时允许；已受污点时转 ASK 交内容审查
        if prev_tool is None:
            path.append(tool_name)
            if has_taint:
                return GraphCheckResult(Decision.ASK, "入口节点但已受污点标记", list(path))
            return GraphCheckResult(Decision.ALLOW, "入口节点", list(path))

        # 4. 合法边
        allowed_next = graph.get(prev_tool, [])
        if tool_name in allowed_next:
            path.append(tool_name)
            if has_taint:
                return GraphCheckResult(Decision.ASK, "图中边存在但已受污点标记", list(path))
            return GraphCheckResult(Decision.ALLOW, "图中边存在", list(path))

        # 5. 非法边
        path.append(tool_name)
        if tool_name in forbidden:
            return GraphCheckResult(Decision.BLOCK,
                                    f"工具 {tool_name} 在当前任务模板中被禁止",
                                    list(path))
        return GraphCheckResult(Decision.ASK,
                                f"图中未找到从 {prev_tool} 到 {tool_name} 的边",
                                list(path))

    def add_edge(self, session_id: str, from_tool: str, to_tool: str) -> None:
        with self._lock:
            template = self._session_templates.get(session_id)
            graph = template.graph if template is not None else self._graph
            target = graph.setdefault(from_tool, [])
            if to_tool not in target:
                target.append(to_tool)

    def get_path(self, session_id: str) -> list[str]:
        with self._lock:
            return list(self._session_paths.get(session_id, []))
