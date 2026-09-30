# tests/test_gen_whitelist.py
"""gen_whitelist.py 辅助脚本 - 单元测试"""
import hashlib
import os
import subprocess
import sys
import tempfile

GEN_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "scripts", "gen_whitelist.py"
)


class TestGenWhitelist:
    """gen_whitelist.py 功能测试"""

    def test_single_file_output_format(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test payload content")
            path = f.name

        try:
            result = subprocess.run(
                [sys.executable, GEN_SCRIPT, path],
                capture_output=True, text=True,
            )
            assert result.returncode == 0, f"stderr: {result.stderr}"
            sha = hashlib.sha256(b"test payload content").hexdigest()
            expected = f"{sha}  {path}"
            assert result.stdout.strip() == expected, (
                f"期望: {expected}\n实际: {result.stdout.strip()}"
            )
        finally:
            os.unlink(path)

    def test_multiple_files(self):
        paths = []
        contents = [b"aaa", b"bbb", b"ccc"]
        for content in contents:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(content)
                paths.append(f.name)

        try:
            result = subprocess.run(
                [sys.executable, GEN_SCRIPT] + paths,
                capture_output=True, text=True,
            )
            assert result.returncode == 0
            lines = result.stdout.strip().split("\n")
            assert len(lines) == 3
            for line, content in zip(lines, contents):
                expected_sha = hashlib.sha256(content).hexdigest()
                assert line.startswith(expected_sha), (
                    f"行 '{line[:80]}...' 哈希不匹配"
                )
        finally:
            for p in paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_nonexistent_file(self):
        result = subprocess.run(
            [sys.executable, GEN_SCRIPT, "/nonexistent/path/xyz123"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "不存在" in result.stderr or "ERROR" in result.stderr

    def test_directory_rejected(self):
        result = subprocess.run(
            [sys.executable, GEN_SCRIPT, "/tmp"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "目录" in result.stderr or "ERROR" in result.stderr

    def test_no_args_shows_usage(self):
        result = subprocess.run(
            [sys.executable, GEN_SCRIPT],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "用法" in result.stderr
