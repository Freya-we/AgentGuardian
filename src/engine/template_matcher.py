import hashlib
import json
import re
from dataclasses import dataclass

from datasketch import MinHash


@dataclass
class TaskTemplate:
    id: str
    label: str
    graph: dict
    terminals: list[str]
    forbidden_tool_categories: list[str]
    require_slm_review: list[str]
    minhash_signature: list[int] | None = None
    structured_tag_hash: str | None = None


def _template_to_text(template: TaskTemplate) -> str:
    """将模板转为可做 MinHash 匹配的文本，包含任务描述和工具集"""
    tools = " ".join(template.graph.keys())
    terminals = " ".join(template.terminals)
    forbidden = " ".join(template.forbidden_tool_categories)
    return f"task: {template.id} {template.label}. tools: {tools}. terminals: {terminals}. forbidden: {forbidden}"


class TemplateMatcher:
    """三层匹配: 结构化标签 -> MinHash 近似 -> 保守兜底"""

    def __init__(self, config_path: str = "config/task_templates.json"):
        self._config_path = config_path
        self._templates: list[TaskTemplate] = []
        self._tag_index: dict[str, TaskTemplate] = {}
        self._load()

    def _load(self) -> None:
        with open(self._config_path) as f:
            config = json.load(f)
        self._templates = []
        self._tag_index = {}
        for t in config["templates"]:
            template = TaskTemplate(
                id=t["id"], label=t["label"],
                graph=t["graph"], terminals=t["terminals"],
                forbidden_tool_categories=t.get("forbidden_tool_categories", []),
                require_slm_review=t.get("require_slm_review", []),
            )
            template.structured_tag_hash = hashlib.sha256(t["id"].encode()).hexdigest()
            self._templates.append(template)
            self._tag_index[t["id"]] = template

    def match(self, system_prompt: str) -> tuple[TaskTemplate | None, str]:
        tag_match = re.search(r"<task>(.*?)</task>|<goal>(.*?)</goal>",
                              system_prompt, re.IGNORECASE)
        if tag_match:
            tag_value = tag_match.group(1) or tag_match.group(2)
            if tag_value.strip() in self._tag_index:
                return self._tag_index[tag_value.strip()], "exact"

        # MinHash 近似匹配作为结构化标签之外的召回增强路径。
        if self._templates:
            input_mh = self._make_minhash(system_prompt)
            best_score = 0.0
            best_template = None
            for template in self._templates:
                if template.minhash_signature is None:
                    template_text = _template_to_text(template)
                    template.minhash_signature = self.compute_minhash(template_text)
                template_mh = self._make_minhash_from_sig(template.minhash_signature)
                jaccard = input_mh.jaccard(template_mh)
                if jaccard > best_score:
                    best_score = jaccard
                    best_template = template
            if best_score >= 0.80:
                return best_template, "minhash_high"
            if best_score >= 0.60 and best_template:
                return best_template, "minhash_low"

        # 保守兜底
        return None, "none"

    def reload(self) -> int:
        self._load()
        return len(self._templates)

    @staticmethod
    def _make_minhash(text: str, num_perm: int = 128) -> MinHash:
        m = MinHash(num_perm=num_perm)
        s = text.lower()
        if len(s) < 3:
            for word in s.split():
                m.update(word.encode())
        else:
            for i in range(len(s) - 2):
                m.update(s[i:i + 3].encode())
        return m

    @staticmethod
    def compute_minhash(text: str, num_perm: int = 128) -> list[int]:
        return TemplateMatcher._make_minhash(text, num_perm).hashvalues.tolist()

    @staticmethod
    def _make_minhash_from_sig(sig: list[int], num_perm: int = 128) -> MinHash:
        import numpy as np
        m = MinHash(num_perm=num_perm)
        m.hashvalues = np.array(sig, dtype=np.uint64)
        return m
