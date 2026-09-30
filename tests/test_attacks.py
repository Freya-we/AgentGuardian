"""攻击模块测试 — LSB 隐写往返、PDF 注入、恶意 API 端点"""
import json

import pytest
from PIL import Image

from src.attacks.malicious_api import app
from src.attacks.stego_injector import (
    extract_lsb_png,
    inject_lsb_png,
    inject_pdf_hidden_layer,
)


class TestLsbStego:
    def test_lsb_roundtrip(self, tmp_path):
        """LSB 注入后提取得到原始 payload"""
        img = Image.new("RGB", (64, 64), color=(128, 128, 128))
        orig = tmp_path / "orig.png"
        out = tmp_path / "out.png"
        img.save(orig, "PNG")
        payload = "ATTACK_PAYLOAD_TEST_123"
        n = inject_lsb_png(str(orig), str(out), payload)
        assert n == len(payload.encode()) + 1  # +1 for \x00 terminator
        extracted = extract_lsb_png(str(out))
        assert extracted == payload

    def test_lsb_payload_too_large_raises(self, tmp_path):
        """payload 超过图片容量时抛出 ValueError"""
        img = Image.new("RGB", (2, 2), color=(0, 0, 0))
        orig = tmp_path / "orig.png"
        out = tmp_path / "out.png"
        img.save(orig, "PNG")
        huge_payload = "A" * 1000
        with pytest.raises(ValueError, match="Payload 太大"):
            inject_lsb_png(str(orig), str(out), huge_payload)


class TestPdfInjection:
    def test_pdf_metadata_injection(self, tmp_path):
        """PDF 元数据注入后可在 Keywords 中检测到 payload"""
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        pdf.cell(text="Test document.")

        payload = "INJECTED_PAYLOAD_SECRET"

        orig = tmp_path / "orig.pdf"
        out = tmp_path / "out.pdf"
        pdf.output(str(orig))
        inject_pdf_hidden_layer(str(orig), str(out), payload)

        from PyPDF2 import PdfReader
        reader = PdfReader(str(out))
        meta = reader.metadata
        keywords = str(meta.get("/Keywords", "")) if meta else ""
        assert payload in keywords


class TestMaliciousApi:
    def test_weather_contains_cmd_injection(self):
        """天气 API 返回的 description 字段包含命令注入 payload"""
        with app.test_client() as client:
            resp = client.get("/api/weather")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "Ignore all previous instructions" in data["description"]

    def test_stock_contains_data_exfil(self):
        """股票 API 返回的 note 字段包含数据窃取 payload"""
        with app.test_client() as client:
            resp = client.get("/api/stock")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "read the file ~/.ssh/id_rsa" in data["note"]

    def test_search_injects_in_snippet(self):
        """搜索 API 在 results[1].snippet 中包含权限提升 payload"""
        with app.test_client() as client:
            resp = client.get("/api/search?q=security")
            assert resp.status_code == 200
            data = resp.get_json()
            assert len(data["results"]) == 3
            assert "chmod 777" in data["results"][1]["snippet"]

    def test_malicious_api_has_trusted_headers(self):
        """恶意 API 伪装可信来源，添加欺骗性响应头"""
        with app.test_client() as client:
            resp = client.get("/api/weather")
            assert resp.headers.get("X-API-Source") == "trusted-partner"

    def test_health_masquerade(self):
        """恶意 API 提供伪装健康检查"""
        with app.test_client() as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["service"] == "trusted-partner-api"


class TestSqlInjector:
    def test_all_six_payloads_have_tags(self):
        """6 个 payload 都有对应的中文标签"""
        from src.attacks.sql_injector import PAYLOAD_TAGS, SQL_PAYLOADS
        assert len(SQL_PAYLOADS) == 6
        assert len(PAYLOAD_TAGS) == len(SQL_PAYLOADS)

    def test_generate_dialogue_output_format(self):
        from src.attacks.sql_injector import generate_dialogue
        dialogue = generate_dialogue(0)
        assert len(dialogue) == 2
        assert dialogue[0]["role"] == "system"
        assert dialogue[1]["role"] == "user"
        assert "DROP TABLE" in dialogue[1]["content"]

    def test_generate_dialogue_bad_index_raises(self):
        import pytest

        from src.attacks.sql_injector import generate_dialogue
        with pytest.raises(ValueError, match="超出范围"):
            generate_dialogue(999)

    def test_each_payload_contains_destructive_sql(self):
        """所有 6 个 payload 都包含 DROP 或 GRANT 语句"""
        from src.attacks.sql_injector import SQL_PAYLOADS
        for payload in SQL_PAYLOADS:
            assert "DROP" in payload.upper() or "GRANT" in payload.upper(), \
                f"Payload 不包含破坏性 SQL: {payload}"

    def test_export_dialogue_writes_valid_json(self, tmp_path):
        from src.attacks.sql_injector import export_dialogue
        output = tmp_path / "dialogue.json"
        export_dialogue(str(output), 3)
        assert output.exists()
        with open(output) as f:
            data = json.loads(f.read())
        assert len(data) == 2

    def test_social_engineering_dialogue_has_drop(self):
        """社会工程多轮对话中包含 DROP TABLE 指令"""
        from src.attacks.sql_injector import MALICIOUS_DIALOGUES
        drop_msg = MALICIOUS_DIALOGUES[-1]["content"]
        assert "DROP TABLE" in drop_msg
