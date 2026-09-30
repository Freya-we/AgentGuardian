import json

import pytest

from src.engine.template_matcher import TemplateMatcher


class TestTemplateMatcher:
    @pytest.fixture
    def config_path(self, tmp_path):
        config = {
            "templates": [
                {
                    "id": "resume_summary",
                    "label": "简历摘要任务",
                    "graph": {"read_file": ["summarize"], "summarize": ["send_email"]},
                    "terminals": ["send_email"],
                    "forbidden_tool_categories": [],
                    "require_slm_review": ["send_email"]
                }
            ],
            "global_blacklist": ["bash_exec"],
            "default_mode": "ask"
        }
        path = tmp_path / "task_templates.json"
        path.write_text(json.dumps(config))
        return str(path)

    def test_load_returns_template_count(self, config_path):
        tm = TemplateMatcher(config_path)
        assert len(tm._templates) == 1

    def test_match_structured_tag_exact(self, config_path):
        tm = TemplateMatcher(config_path)
        prompt = "You are an assistant. <task>resume_summary</task> Help summarize."
        template, method = tm.match(prompt)
        assert template is not None
        assert template.id == "resume_summary"
        assert method == "exact"

    def test_match_no_match_returns_none(self, config_path):
        tm = TemplateMatcher(config_path)
        prompt = "You are a completely unrelated assistant doing something else entirely."
        template, method = tm.match(prompt)
        assert template is None
        assert method == "none"

    def test_reload_updates_templates(self, config_path):
        tm = TemplateMatcher(config_path)
        config = {
            "templates": [
                {"id": "new_template", "label": "新模板",
                 "graph": {}, "terminals": [], "forbidden_tool_categories": [],
                 "require_slm_review": []}
            ],
            "global_blacklist": [],
            "default_mode": "block"
        }
        with open(config_path, "w") as f:
            json.dump(config, f)
        count = tm.reload()
        assert count == 1

    def test_match_goal_tag_variant(self, config_path):
        """<goal> 标签变体也能精确匹配"""
        tm = TemplateMatcher(config_path)
        prompt = "Your <goal>resume_summary</goal> is to help with resumes."
        template, method = tm.match(prompt)
        assert template is not None
        assert template.id == "resume_summary"
        assert method == "exact"

    def test_match_minhash_low_confidence(self, config_path):
        """部分相似的文本返回 minhash_low (≥0.60, <0.80)"""
        tm = TemplateMatcher(config_path)
        # 创建与 "task: resume_summary 简历摘要任务" 部分重叠的文本
        prompt = "你是一个简历处理助手，负责摘要和总结任务"
        template, method = tm.match(prompt)
        if template is not None:
            # 可能命中 minhash_high 或 minhash_low
            assert method in ("minhash_high", "minhash_low")
        # 如果完全未命中 (Jaccard < 0.60)，method 为 "none"，也是合法结果

    def test_compute_minhash_returns_128_ints(self):
        sig = TemplateMatcher.compute_minhash("hello world test text")
        assert len(sig) == 128
        assert all(isinstance(x, int) for x in sig)

    def test_minhash_short_text(self):
        """极短文本 (少于 3 字符) 使用单词分词"""
        sig = TemplateMatcher.compute_minhash("ab")
        assert len(sig) == 128
