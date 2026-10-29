import asyncio
import json
import os
import time
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from src.engine import server
from src.engine.server import SignRequest


def test_tool_call_event_shape():
    req = SignRequest(
        pid=123,
        tool_name="read_file",
        params_hash="abc",
        input_messages="task",
        session_id="s1",
    )

    event = server._tool_call_event(
        req,
        decision="allow",
        causal_id="deadbeef",
        taint_tags=["TAINTED"],
        reason="图中边存在",
        timestamp=42,
    )

    assert event == {
        "type": "tool_call",
        "session_id": "s1",
        "tool_name": "read_file",
        "decision": "allow",
        "causal_id": "deadbeef",
        "taint_tags": ["TAINTED"],
        "reason": "图中边存在",
        "timestamp": 42,
        "pid": 123,
    }


def test_taint_update_event_shape():
    event = server._taint_update_event("s1", ["UNTRUSTED_FILE", "TAINTED"], 42)

    assert event == {
        "type": "taint_update",
        "session_id": "s1",
        "source_type": "UNTRUSTED_FILE",
        "active_tags": ["UNTRUSTED_FILE", "TAINTED"],
        "timestamp": 42,
    }


def test_ebpf_intercept_event_shape():
    req = server.EbpfInterceptRequest(
        pid=123,
        syscall="execve",
        causal_id_valid=False,
        action="block",
        reason="missing causal id",
        timestamp=42,
    )

    assert server._ebpf_intercept_event(req) == {
        "type": "ebpf_intercept",
        "pid": 123,
        "syscall": "execve",
        "causal_id_valid": False,
        "action": "block",
        "reason": "missing causal id",
        "timestamp": 42,
    }


async def test_sign_request_broadcasts_tool_call(monkeypatch):
    broadcasts = []

    async def capture(event):
        broadcasts.append(event)

    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock(side_effect=capture))
    monkeypatch.setattr(server.state, "keys", None)
    # 隔离图约束状态：本用例要验证的正是"没有匹配模板"的场景
    from src.engine.graph_constraint import GraphConstraint
    monkeypatch.setattr(server.state, "graph_constraint", GraphConstraint())

    req = SignRequest(
        pid=os.getpid(),
        tool_name="read_file",
        params_hash="abc",
        input_messages="no matching template",
        session_id="server-event-test",
    )

    response = await server.handle_sign_request(req)
    await asyncio.sleep(0)

    tool_events = [
        event for event in broadcasts if event.get("type") == "tool_call"
    ]
    # 没有匹配到任务模板 → fail-closed（P0-3），不再无条件放行
    assert response.decision == "ask"
    assert len(tool_events) == 1
    assert tool_events[0]["session_id"] == "server-event-test"
    assert tool_events[0]["tool_name"] == "read_file"
    assert tool_events[0]["decision"] == "ask"


async def test_taint_source_endpoint_broadcasts_taint_update(monkeypatch):
    broadcasts = []

    async def capture(event):
        broadcasts.append(event)

    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock(side_effect=capture))

    response = await server.tag_taint_source(
        server.TaintSourceRequest(
            session_id="taint-source-test",
            source_type=server.TaintTag.UNTRUSTED_FILE,
        )
    )

    assert response["status"] == "ok"
    assert "UNTRUSTED_FILE" in response["active_tags"]
    assert broadcasts[-1]["type"] == "taint_update"
    assert broadcasts[-1]["session_id"] == "taint-source-test"


async def test_ebpf_intercept_endpoint_broadcasts_event(monkeypatch):
    broadcasts = []

    async def capture(event):
        broadcasts.append(event)

    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock(side_effect=capture))

    response = await server.receive_ebpf_intercept(
        server.EbpfInterceptRequest(
            pid=456,
            syscall="openat",
            causal_id_valid=False,
            action="block",
            reason="invalid causal id",
        )
    )

    assert response["status"] == "ok"
    assert response["event"]["type"] == "ebpf_intercept"
    assert broadcasts[-1]["type"] == "ebpf_intercept"
    assert broadcasts[-1]["causal_id_valid"] is False


def test_task_templates_config_round_trip(tmp_path, monkeypatch):
    config_path = tmp_path / "task_templates.json"
    config_path.write_text(
        json.dumps({
            "templates": [
                {
                    "id": "demo",
                    "label": "Demo",
                    "graph": {"read_file": ["summarize"]},
                    "terminals": ["summarize"],
                    "forbidden_tool_categories": [],
                    "require_slm_review": [],
                }
            ],
            "global_blacklist": ["bash_exec"],
            "default_mode": "ask",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(server.state, "config_path", config_path)
    monkeypatch.setattr(server.state.template_matcher, "_config_path", str(config_path))
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())

    client = TestClient(server.app)
    read_response = client.get("/api/v1/config/task-templates")
    assert read_response.status_code == 200
    assert read_response.json()["templates"][0]["id"] == "demo"

    updated = read_response.json()
    updated["templates"].append({
        "id": "second",
        "label": "Second",
        "graph": {},
        "terminals": [],
        "forbidden_tool_categories": [],
        "require_slm_review": [],
    })

    write_response = client.put("/api/v1/config/task-templates", json=updated)
    assert write_response.status_code == 200
    assert write_response.json() == {"status": "ok", "templates_loaded": 2}
    assert json.loads(config_path.read_text(encoding="utf-8"))["templates"][1]["id"] == "second"


def test_task_templates_config_rejects_invalid_payload(tmp_path, monkeypatch):
    config_path = tmp_path / "task_templates.json"
    config_path.write_text(
        json.dumps({"templates": [], "global_blacklist": [], "default_mode": "ask"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(server.state, "config_path", config_path)

    client = TestClient(server.app)
    response = client.put(
        "/api/v1/config/task-templates",
        json={"templates": [], "global_blacklist": [], "default_mode": "invalid"},
    )

    assert response.status_code == 422


async def test_db_query_ddl_blocked(monkeypatch):
    """db_query + DROP TABLE → 当模板禁止 DDL 时返回 BLOCK"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)
    server.state.graph_constraint.forbidden_categories = ["DDL", "DCL"]

    req = SignRequest(
        pid=os.getpid(),
        tool_name="db_query",
        params_hash="hash_drop_table",
        params="DROP TABLE users;",
        input_messages="优化数据库查询",
        session_id="sql-ddl-test",
    )

    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "DDL" in response.reason


async def test_db_query_select_allowed(monkeypatch):
    """db_query + SELECT → 即使模板有 DDL 禁止，也应放行"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)
    server.state.graph_constraint.forbidden_categories = ["DDL", "DCL"]

    req = SignRequest(
        pid=os.getpid(),
        tool_name="db_query",
        params_hash="hash_select",
        params="SELECT * FROM users WHERE id = 1;",
        input_messages="查询用户数据",
        session_id="sql-select-test",
    )

    response = await server.handle_sign_request(req)
    assert response.decision in ("allow", "ask")


async def test_db_query_dcl_blocked(monkeypatch):
    """db_query + GRANT → 当模板禁止 DCL 时返回 BLOCK"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)
    server.state.graph_constraint.forbidden_categories = ["DDL", "DCL"]

    req = SignRequest(
        pid=os.getpid(),
        tool_name="db_query",
        params_hash="hash_grant",
        params="GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%';",
        input_messages="授予权限",
        session_id="sql-dcl-test",
    )

    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "DCL" in response.reason


async def test_db_query_comment_bypass_blocked(monkeypatch):
    """MySQL 条件注释绕过 /*!50000 DROP TABLE*/ → 仍应被检测为 DDL"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)
    server.state.graph_constraint.forbidden_categories = ["DDL", "DCL"]

    req = SignRequest(
        pid=os.getpid(),
        tool_name="db_query",
        params_hash="hash_comment_bypass",
        params="SELECT * FROM users; /*!50000 DROP TABLE audit_log; -- */",
        input_messages="优化查询",
        session_id="sql-comment-bypass",
    )

    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "DDL" in response.reason


async def test_session_sweep_cleans_all_containers(monkeypatch):
    """过期会话必须从污点/图约束/统计/last_call_ns 全部回收。

    forget_session 曾定义了但无人调用，导致除污点外的容器无界增长（接线缺口）。
    """
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)

    req = SignRequest(
        pid=os.getpid(),
        tool_name="read_file",
        params_hash="hash_sweep",
        input_messages="no matching template",
        session_id="sweep-me",
    )
    await server.handle_sign_request(req)
    # 确认会话确实写进了各个容器（state 是模块级单例，可能有其他测试的残留会话）
    assert server.state.last_call_ns.get("sweep-me") is not None
    assert "sweep-me" in server.state.taint_tracker.active_session_ids()

    # 时钟前进 2 小时，超过污点 TTL（1 小时）
    now = time.monotonic()
    monkeypatch.setattr("src.engine.taint_tracker.time.monotonic", lambda: now + 7200)
    removed = server._sweep_stale_sessions()

    assert removed >= 1
    assert server.state.taint_tracker.get_active_tags("sweep-me") == []
    assert server.state.graph_constraint.get_path("sweep-me") == []
    assert server.state.last_call_ns.get("sweep-me") is None


async def test_session_sweep_keeps_active_sessions(monkeypatch):
    """活跃会话不受清扫影响"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)

    req = SignRequest(
        pid=202,
        tool_name="read_file",
        params_hash="hash_active",
        input_messages="no matching template",
        session_id="keep-me",
    )
    await server.handle_sign_request(req)

    removed = server._sweep_stale_sessions()  # 不推进时钟
    assert "keep-me" in server.state.taint_tracker.active_session_ids()
    assert server.state.last_call_ns.get("keep-me") is not None


def test_ttl_cache_purge_expired():
    """_TtlCache 的惰性淘汰会漏掉长期不再访问的条目，purge_expired 兜底"""
    cache = server._TtlCache(maxsize=10, ttl_seconds=0)
    cache.set("k", "v")
    time.sleep(0.01)
    assert cache.purge_expired() == 1
    assert "k" not in cache


async def test_session_sweep_removes_prompt_only_orphans(monkeypatch):
    """只在 system-prompt 通道出现、从未走过 sign 链路的会话也要回收"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())

    server.state.session_system_prompts["prompt-only"] = "you are a helpful agent"
    assert "prompt-only" not in set(server.state.taint_tracker.active_session_ids())

    removed = server._sweep_stale_sessions()
    assert "prompt-only" not in server.state.session_system_prompts
    assert removed >= 1


async def test_sign_rejects_nonpositive_pid(monkeypatch):
    """P0-1b：pid <= 0 直接拒绝，不进入决策流程"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())

    req = SignRequest(
        pid=0,
        tool_name="read_file",
        params_hash="hash",
        input_messages="no matching template",
        session_id="pid-gate-test",
    )
    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "pid" in response.reason


async def test_sign_rejects_nonexistent_pid(monkeypatch):
    """P0-1b：引擎不可给不存在的进程签发票据（伪造 pid 铺票的第一道门）"""
    monkeypatch.setenv("AGENT_GUARDIAN_PID_GATE", "1")  # 显式开启才校验 /proc
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server, "_pid_exists", lambda pid: False)

    req = SignRequest(
        pid=999999,
        tool_name="read_file",
        params_hash="hash",
        input_messages="no matching template",
        session_id="pid-gate-test-2",
    )
    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "999999" in response.reason


async def test_sign_passes_live_pid(monkeypatch):
    """P0-1b：pid 合法时不被 pid 门禁拦截（走正常决策路径）"""
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server.state, "keys", None)
    monkeypatch.setattr(server, "_pid_exists", lambda pid: True)
    from src.engine.graph_constraint import GraphConstraint
    monkeypatch.setattr(server.state, "graph_constraint", GraphConstraint())

    req = SignRequest(
        pid=os.getpid(),
        tool_name="read_file",
        params_hash="attacker_chosen_hash",
        input_messages="no matching template",
        session_id="pid-gate-live",
    )
    response = await server.handle_sign_request(req)
    # 活 pid + 无模板 → fail-closed 的 ASK（而不是 pid 门禁的 block）
    assert response.decision == "ask"


async def test_pid_gate_disabled_by_default(monkeypatch):
    """默认不做 /proc 存活校验。

    跨命名空间部署时它既可能误杀也可能误放，真正的 pid 权威在 causal-guardian
    的 monitored_tgid 门禁。这里确认：即使进程"不存在"，也不会被这道门拦。
    """
    monkeypatch.delenv("AGENT_GUARDIAN_PID_GATE", raising=False)
    monkeypatch.setattr(server.state.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(server, "_pid_exists", lambda pid: False)

    req = SignRequest(
        pid=999999,
        tool_name="read_file",
        params_hash="hash",
        input_messages="no matching template",
        session_id="pid-gate-off",
    )
    response = await server.handle_sign_request(req)
    assert "不存在" not in response.reason
