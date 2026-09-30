# tests/test_exec_whitelist.py
"""执行白名单配置解析与哈希验证 - 单元测试"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scripts.gen_whitelist import compute_sha256


def _parse_line(line: str) -> tuple[str, str] | None:
    """解析配置文件的一行，返回 (sha256, path) 或 None"""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split(maxsplit=1)
    if len(parts) != 2:
        return None
    sha_hex, path = parts
    if len(sha_hex) != 64:
        return None
    # 验证 sha_hex 是合法 hex 字符串
    try:
        bytes.fromhex(sha_hex)
    except ValueError:
        return None
    return (sha_hex, path)


def _verify_entry(sha_hex: str, path: str) -> tuple[bool, str]:
    """验证单条白名单条目，返回 (ok, reason)"""
    if not os.path.exists(path):
        return (False, f"文件不存在: {path}")
    if not os.path.isfile(path):
        return (False, f"不是普通文件: {path}")
    try:
        actual = compute_sha256(path)
    except PermissionError:
        return (False, f"权限拒绝: {path}")
    except OSError as e:
        return (False, f"读取失败: {path}: {e}")

    expected_bytes = bytes.fromhex(sha_hex)
    actual_bytes = bytes.fromhex(actual)
    if len(expected_bytes) != 32:
        return (False, f"无效 SHA256 hex: {sha_hex}")
    if expected_bytes != actual_bytes:
        return (False, f"哈希不匹配: 期望 {sha_hex[:16]}..., 实际 {actual[:16]}...")
    return (True, "ok")


class TestConfigParsing:
    """配置行解析测试"""

    def test_normal_line(self):
        sha = "a" * 64
        line = f"{sha}  /usr/bin/python3"
        result = _parse_line(line)
        assert result is not None
        assert result[0] == sha
        assert result[1] == "/usr/bin/python3"

    def test_comment_line(self):
        assert _parse_line("# this is a comment") is None

    def test_empty_line(self):
        assert _parse_line("") is None
        assert _parse_line("   ") is None

    def test_short_hash(self):
        assert _parse_line("abc  /bin/ls") is None

    def test_invalid_hex(self):
        assert _parse_line("z" * 64 + "  /bin/ls") is None

    def test_no_path(self):
        assert _parse_line("a" * 64) is None

    def test_extra_whitespace(self):
        sha = "b" * 64
        result = _parse_line(f"  {sha}    /usr/bin/git  ")
        assert result is not None
        assert result[1] == "/usr/bin/git"


class TestHashVerification:
    """哈希验证测试"""

    def test_hash_match(self, tmp_path):
        path = tmp_path / "test_wl_match"
        path.write_bytes(b"hello world")
        sha = hashlib.sha256(b"hello world").hexdigest()
        ok, reason = _verify_entry(sha, str(path))
        assert ok, f"应匹配: {reason}"

    def test_hash_mismatch(self, tmp_path):
        path = tmp_path / "test_wl_mismatch"
        path.write_bytes(b"hello world")
        wrong_sha = hashlib.sha256(b"different content").hexdigest()
        ok, reason = _verify_entry(wrong_sha, str(path))
        assert not ok
        assert "哈希不匹配" in reason

    def test_file_not_found(self):
        ok, reason = _verify_entry("a" * 64, "/nonexistent/path/12345")
        assert not ok
        assert "不存在" in reason

    def test_directory_rejected(self, tmp_path):
        ok, reason = _verify_entry("a" * 64, str(tmp_path))
        assert not ok
        assert "普通文件" in reason
