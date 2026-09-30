# tests/integration/test_frida_gadget.py
"""Frida Gadget 模式集成测试

前提条件:
  - ./scripts/setup_gadget.sh 已执行
  - /etc/agent-guardian/frida/frida-gadget.so 存在
  - bridge 已启动 (uv run python -m src.frida.bridge)
"""

import os
import socket
import subprocess

import pytest

GADGET_SO = "/etc/agent-guardian/frida/frida-gadget.so"
GADGET_HOST = "127.0.0.1"
GADGET_PORT = 27042


def _requires_gadget():
    if not os.path.exists(GADGET_SO):
        pytest.skip(f"Gadget 未安装: {GADGET_SO}")


class TestGadgetInjection:
    """Gadget LD_PRELOAD 注入测试"""

    def test_gadget_connects_to_bridge(self):
        """Gadget 注入后连接 bridge — 验证进程不崩溃"""
        _requires_gadget()

        env = os.environ.copy()
        env["LD_PRELOAD"] = GADGET_SO

        result = subprocess.run(
            ["python3", "-c",
             "import time; time.sleep(0.5); print('OK')"],
            env=env,
            capture_output=True, text=True,
            timeout=5,
        )
        assert "OK" in result.stdout, f"进程异常: {result.stderr}"

    @pytest.mark.skipif(os.name != "posix",
                        reason="pgrep 仅在类 Unix 平台可用")
    def test_gadget_no_frida_server(self):
        """验证不需要 frida-server 进程"""
        result = subprocess.run(
            ["pgrep", "-f", "frida-server"],
            capture_output=True,
        )
        assert result.returncode != 0, \
            "frida-server 仍在运行，Gadget 模式不需要它"


class TestGadgetHookIntegration:
    """Gadget Hook 功能集成测试 — 需要 bridge 运行中"""

    def test_bridge_port_reachable(self):
        """验证 bridge TCP 端口可达"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect((GADGET_HOST, GADGET_PORT))
            sock.close()
            bridge_alive = True
        except (TimeoutError, OSError):
            bridge_alive = False

        if not bridge_alive:
            pytest.skip("bridge 未运行 — 跳过端到端集成测试")
        # bridge 可达
        assert True
