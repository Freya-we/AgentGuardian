"""工具调用图约束引擎 — O(1) 邻接表查询。

实现边界 (P2-13):
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
    """工具调用图约束引擎 — O(1) 字典查询，threading.Lock 保护并发访问"""

    def __init__(self):
        self._graph: dict[str, list[str]] = {}
        self._terminals: list[str] = []
        self._forbidden_categories: list[str] = []
        self._session_paths: dict[str, list[str]] = {}
        self._blacklist: set[str] = set()
        self._lock = threading.Lock()

    def set_blacklist(self, blacklist: list[str]) -> None:
        self._blacklist = set(blacklist)

    def load_template(self, template: TaskTemplate) -> None:
        if template is None:
            raise ValueError("template 不能为 None")
        if not template.graph:
            raise ValueError(f"模板 {template.id} 的 graph 为空")
        self._graph = {k: list(v) for k, v in template.graph.items()}
        self._terminals = list(template.terminals)
        self._forbidden_categories = list(template.forbidden_tool_categories)

    @property
    def forbidden_categories(self) -> list[str]:
        return list(self._forbidden_categories)

    @forbidden_categories.setter
    def forbidden_categories(self, value: list[str]) -> None:
        self._forbidden_categories = list(value)

    def check(self, session_id: str, tool_name: str,
              taint_tags: list[str]) -> GraphCheckResult:
        with self._lock:
            return self._check_impl(session_id, tool_name, taint_tags)

    def _check_impl(self, session_id: str, tool_name: str,
                    taint_tags: list[str]) -> GraphCheckResult:
        if session_id not in self._session_paths:
            self._session_paths[session_id] = []

        path = self._session_paths[session_id]
        prev_tool = path[-1] if path else None
        has_taint = len(taint_tags) > 0

        if tool_name in self._blacklist:
            return GraphCheckResult(Decision.BLOCK,
                                    f"工具 {tool_name} 在全局黑名单中",
                                    list(path))

        # 入口节点: 图中无前驱 → 无污点时允许；已受污点时转 ASK 交内容审查
        if prev_tool is None:
            path.append(tool_name)
            if has_taint:
                return GraphCheckResult(Decision.ASK, "入口节点但已受污点标记", list(path))
            return GraphCheckResult(Decision.ALLOW, "入口节点", list(path))

        allowed_next = self._graph.get(prev_tool, [])
        if tool_name in allowed_next:
            path.append(tool_name)
            if has_taint:
                return GraphCheckResult(Decision.ASK, "图中边存在但已受污点标记", list(path))
            return GraphCheckResult(Decision.ALLOW, "图中边存在", list(path))

        path.append(tool_name)
        if tool_name in self._forbidden_categories:
            return GraphCheckResult(Decision.BLOCK,
                                    f"工具 {tool_name} 在当前任务模板中被禁止",
                                    list(path))
        return GraphCheckResult(Decision.ASK,
                                f"图中未找到从 {prev_tool} 到 {tool_name} 的边",
                                list(path))

    def add_edge(self, session_id: str, from_tool: str, to_tool: str) -> None:
        if from_tool not in self._graph:
            self._graph[from_tool] = []
        if to_tool not in self._graph[from_tool]:
            self._graph[from_tool].append(to_tool)

    def get_path(self, session_id: str) -> list[str]:
        with self._lock:
            return list(self._session_paths.get(session_id, []))
