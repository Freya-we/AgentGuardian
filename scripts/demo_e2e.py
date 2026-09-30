#!/usr/bin/env python3
"""AgentGuardian E2E 验证: HTTP 全链路 + WebSocket 断言"""
import argparse
import asyncio
import json
import time
import urllib.error
import urllib.request

import websockets

BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/events"
PASS = 0
FAIL = 0


def _post(path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise SystemExit(f"POST {path} failed: {e.code} {detail}")


def _put(path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=body,
        headers={"Content-Type": "application/json"}, method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise SystemExit(f"PUT {path} failed: {e.code} {detail}")


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{BASE_URL}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise SystemExit(f"GET {path} failed: {e.code} {detail}")


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def sign(pid: int, tool_name: str, params_hash: str, session_id: str,
         input_messages: str = "<task>resume_summary</task>") -> dict:
    return _post("/api/v1/causal-id/sign", {
        "pid": pid, "tool_name": tool_name,
        "params_hash": params_hash, "input_messages": input_messages,
        "session_id": session_id,
    })


async def collect_ws_events(duration_s: float = 3.0) -> list[dict]:
    """连接 WebSocket 收集广播事件"""
    events: list[dict] = []
    try:
        async with websockets.connect(WS_URL) as ws:
            deadline = asyncio.get_event_loop().time() + duration_s
            while asyncio.get_event_loop().time() < deadline:
                try:
                    text = await asyncio.wait_for(ws.recv(), timeout=0.5)
                    events.append(json.loads(text))
                except TimeoutError:
                    continue
                except Exception:
                    break
    except Exception as exc:
        print(f"  [WARN] WebSocket 连接失败: {exc}")
    return events


async def main_async(session_id: str) -> None:
    global PASS, FAIL
    PASS = 0
    FAIL = 0

    print(f"session_id={session_id}\n")

    # ── 健康检查 ──
    health = _get("/health")
    check("health endpoint", health["status"] == "ok",
          f"status={health.get('status')}")

    # ── 加载配置 ──
    print("\n--- 加载模板 ---")
    original_config = _get("/api/v1/config/task-templates")
    check("config loaded", len(original_config.get("templates", [])) > 0,
          f"templates={len(original_config.get('templates', []))}")

    # ── 正常调用链 ──
    print("\n--- 正常调用链 ---")

    # 先开始收集 WebSocket 事件
    ws_task = asyncio.create_task(collect_ws_events(6.0))

    await asyncio.sleep(0.3)

    r1 = sign(4101, "read_file", "hash-read", session_id)
    check("read_file allow", r1["decision"] == "allow",
          f"decision={r1['decision']} reason={r1.get('reason')}")
    check("read_file has causal_id", r1.get("causal_id") is not None,
          f"causal_id={r1.get('causal_id')}")

    time.sleep(0.2)

    r2 = sign(4101, "summarize", "hash-summary", session_id)
    check("summarize allow", r2["decision"] == "allow",
          f"decision={r2['decision']} reason={r2.get('reason')}")

    time.sleep(0.2)

    # ── 攻击注入 ──
    print("\n--- 攻击注入 ---")

    taint_r = _post("/api/v1/taint/source", {
        "session_id": session_id,
        "source_type": "UNTRUSTED_FILE",
    })
    check("taint source", taint_r["status"] == "ok",
          f"status={taint_r.get('status')} "
          f"active_tags={taint_r.get('active_tags')}")

    time.sleep(0.2)

    r3 = sign(4101, "send_email",
              "hash-sensitive-content-with-id-rsa-and-password-token",
              session_id)
    check("send_email with taint", r3["decision"] in ("block", "ask"),
          f"decision={r3['decision']} reason={r3.get('reason')}")

    time.sleep(0.2)

    # ── eBPF 拦截模拟 ──
    print("\n--- eBPF 拦截模拟 ---")
    ebpf_r = _post("/api/v1/ebpf/intercept", {
        "pid": 4101,
        "syscall": "execve",
        "causal_id_valid": False,
        "action": "block",
        "reason": "missing or invalid causal id",
    })
    check("ebpf intercept", ebpf_r["status"] == "ok",
          f"status={ebpf_r.get('status')}")

    # ── 收集 WS 事件 ──
    ws_events = await ws_task
    print(f"\nWebSocket 收集事件数: {len(ws_events)}")

    event_types = {e.get("type") for e in ws_events}
    expected_types = {"tool_call", "causal_id_issued", "rule_alert",
                      "ebpf_intercept", "stats_update", "taint_update"}
    found = expected_types & event_types
    missing = expected_types - event_types
    check("WS event types coverage",
          len(found) >= 5,
          f"found={sorted(found)} missing={sorted(missing)}")

    # ── 结果 ──
    print(f"\n{'='*40}")
    print(f"结果: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentGuardian E2E verification"
    )
    parser.add_argument("--session-id", default=f"e2e-{int(time.time())}")
    args = parser.parse_args()
    asyncio.run(main_async(args.session_id))


if __name__ == "__main__":
    main()
