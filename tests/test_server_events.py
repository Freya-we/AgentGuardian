import asyncio
import json
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

    req = SignRequest(
        pid=321,
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
    assert response.decision == "allow"
    assert len(tool_events) == 1
    assert tool_events[0]["session_id"] == "server-event-test"
    assert tool_events[0]["tool_name"] == "read_file"
    assert tool_events[0]["decision"] == "allow"


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
        pid=101,
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
        pid=102,
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
        pid=103,
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
        pid=104,
        tool_name="db_query",
        params_hash="hash_comment_bypass",
        params="SELECT * FROM users; /*!50000 DROP TABLE audit_log; -- */",
        input_messages="优化查询",
        session_id="sql-comment-bypass",
    )

    response = await server.handle_sign_request(req)
    assert response.decision == "block"
    assert "DDL" in response.reason
