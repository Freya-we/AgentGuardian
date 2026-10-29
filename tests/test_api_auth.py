"""引擎 API 认证（P0-1）。

修复前所有 /api/v1/* 无鉴权：任何本地进程都能拿任意 PID 换通行证、
改写安全策略、订阅事件流。这里锁定三种状态：
  · 未配置令牌（开发模式）→ 放行，但服务启动时会告警；
  · 配置令牌 → 缺失/错误令牌一律 401；
  · /health 始终开放，供探活使用。
"""

from fastapi.testclient import TestClient

from src.engine import server


def test_health_stays_open_even_with_token():
    server.state.api_token = "secret-token"
    try:
        client = TestClient(server.app)
        assert client.get("/health").status_code == 200
    finally:
        server.state.api_token = None


def test_api_rejects_missing_or_wrong_token():
    server.state.api_token = "secret-token"
    try:
        client = TestClient(server.app)
        url = "/api/v1/config/task-templates"

        assert client.get(url).status_code == 401
        assert client.get(url, headers={"X-Guardian-Token": "wrong"}).status_code == 401
        assert client.get(url,
                          headers={"X-Guardian-Token": "secret-token"}).status_code == 200
    finally:
        server.state.api_token = None


def test_sign_endpoint_rejects_unauthenticated_caller():
    """最关键的一条：未认证调用拿不到票据"""
    server.state.api_token = "secret-token"
    try:
        client = TestClient(server.app)
        resp = client.post("/api/v1/causal-id/sign", json={
            "pid": 1,
            "tool_name": "bash_exec",
            "params_hash": "x",
            "params": "",
            "input_messages": "",
            "session_id": "s",
        })
        assert resp.status_code == 401
    finally:
        server.state.api_token = None


def test_auth_disabled_when_token_not_configured():
    """开发模式：未配置令牌时不校验（启动时已打印告警）"""
    server.state.api_token = None
    client = TestClient(server.app)
    assert client.get("/api/v1/config/task-templates").status_code == 200
