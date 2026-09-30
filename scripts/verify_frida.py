#!/usr/bin/env python3
"""Frida 最小验证: 注入 lowlevel_hooks.js → 捕获 subprocess.Popen → 验证审计引擎通信"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
TARGET_SCRIPT = os.path.join(SCRIPT_DIR, "_frida_target.py")
HOOK_SCRIPT = os.path.join(PROJECT_DIR, "src", "frida", "lowlevel_hooks.js")
AUDIT_ENGINE_URL = "http://127.0.0.1:8000"


def check_prerequisites() -> None:
    """检查审计引擎是否在运行"""
    try:
        req = urllib.request.Request(f"{AUDIT_ENGINE_URL}/health")
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        if data.get("status") != "ok":
            raise SystemExit(f"审计引擎异常: {data}")
    except (urllib.error.URLError, ConnectionRefusedError) as e:
        raise SystemExit(f"审计引擎未启动 ({AUDIT_ENGINE_URL}/health): {e}")


def run() -> None:
    check_prerequisites()
    print(f"审计引擎: OK ({AUDIT_ENGINE_URL}/health)")

    # 1. 启动目标进程
    print(f"启动目标进程: {TARGET_SCRIPT}")
    target = subprocess.Popen(
        [sys.executable, TARGET_SCRIPT],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(0.5)

    if target.poll() is not None:
        raise SystemExit(
            f"目标进程启动失败: "
            f"{target.stdout.read() if target.stdout else '<no output>'}"
        )

    target_pid = target.pid
    print(f"目标进程 PID: {target_pid}")

    # 2. Frida 附加
    import frida
    try:
        session = frida.attach(target_pid)
    except frida.ProcessNotFoundError:
        target.terminate()
        raise SystemExit(
            f"无法附加到 PID {target_pid}，检查 frida-server 或 ptrace 权限"
        )

    events: list[dict] = []

    def on_message(message: dict, data: bytes) -> None:
        payload = message.get("payload", message)
        print(f"  [Frida] {json.dumps(payload, ensure_ascii=False)}")
        events.append(
            payload if isinstance(payload, dict) else {"raw": str(payload)}
        )

    # 3. 加载 Hook 脚本
    with open(HOOK_SCRIPT) as f:
        script_code = f.read()
    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()
    print(f"Hook 已注入: {HOOK_SCRIPT}")

    # 4. 等待目标进程产生事件
    timeout = 10
    print(f"等待事件 (timeout={timeout}s)...")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and target.poll() is None:
        time.sleep(0.5)

    target.terminate()
    session.detach()

    # 5. 验证
    print(f"\n捕获事件数: {len(events)}")
    if not events:
        raise SystemExit("FAIL: 未捕获任何 Frida 事件")

    # 6. 审计引擎通信验证
    print("发送签名请求到审计引擎...")
    payload = json.dumps({
        "pid": target_pid,
        "tool_name": "subprocess.Popen",
        "params_hash":
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "input_messages": "<task>resume_summary</task>",
        "session_id": f"frida-verify-{int(time.time())}",
    }).encode()
    req = urllib.request.Request(
        f"{AUDIT_ENGINE_URL}/api/v1/causal-id/sign",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=5)
    result = json.loads(resp.read())
    print(f"审计引擎响应: {json.dumps(result, ensure_ascii=False)}")
    if "decision" not in result:
        raise SystemExit("FAIL: 审计引擎响应格式错误")

    print(
        f"\n[PASS] Frida 验证通过 "
        f"({len(events)} 事件, 审计引擎决策={result['decision']})"
    )


if __name__ == "__main__":
    run()
