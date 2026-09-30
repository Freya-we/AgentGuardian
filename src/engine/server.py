import asyncio
import atexit
import json
import logging
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, WebSocket
from pydantic import BaseModel, Field
from watchfiles import awatch

from src.engine.graph_constraint import Decision, GraphConstraint
from src.engine.hmac_signer import HmacSigner
from src.engine.key_manager import KeyManager, SessionKeys
from src.engine.rule_engine import RuleEngine
from src.engine.slm_reviewer import SlmReviewer
from src.engine.sql_parser import SqlParser
from src.engine.stats_baseline import StatsBaseline
from src.engine.taint_tracker import TaintTag, TaintTracker
from src.engine.template_matcher import TemplateMatcher
from src.engine.websocket_manager import WebSocketManager


class SignRequest(BaseModel):
    pid: int
    tool_name: str
    params_hash: str
    params: str = ""  # 原始参数文本 (SQL 解析和内容审查用)
    input_messages: str
    session_id: str


class SignResponse(BaseModel):
    causal_id: str | None = None
    decision: str = "ask"
    taint_tags: list[str] = []
    reason: str = ""
    mode: str = "ask"


class ToolCallEvent(BaseModel):
    type: str = "tool_call"
    session_id: str
    tool_name: str
    decision: str
    causal_id: str | None = None
    taint_tags: list[str] = []
    reason: str = ""
    timestamp: int
    pid: int


class TaintUpdateEvent(BaseModel):
    type: str = "taint_update"
    session_id: str
    source_type: str
    active_tags: list[str]
    timestamp: int


class TaskTemplateConfig(BaseModel):
    id: str = Field(min_length=1)
    label: str = Field(min_length=1)
    graph: dict[str, list[str]]
    terminals: list[str]
    forbidden_tool_categories: list[str] = []
    require_slm_review: list[str] = []


class TaskTemplatesConfig(BaseModel):
    templates: list[TaskTemplateConfig]
    global_blacklist: list[str] = []
    default_mode: Literal["allow", "ask", "block"] = "ask"


class SystemPromptRequest(BaseModel):
    system_prompt: str
    session_id: str


class ContextRequest(BaseModel):
    type: str
    tool_name: str
    params: str
    session_id: str
    agent_id: str | None = None


class TaintSourceRequest(BaseModel):
    session_id: str
    source_type: TaintTag


class EbpfInterceptRequest(BaseModel):
    pid: int
    syscall: str
    causal_id_valid: bool
    action: Literal["allow", "ask", "block"]
    reason: str = ""
    timestamp: int | None = None


# 防止 session_templates 无限制增长导致内存泄漏

class _TtlCache:
    """带 TTL 和容量限制的字符串缓存，用于会话级模板映射"""
    def __init__(self, maxsize: int = 4096, ttl_seconds: int = 3600):
        self._data: dict[str, tuple[str, float]] = {}
        self._maxsize = maxsize
        self._ttl = ttl_seconds

    def get(self, key: str) -> str | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.monotonic() - ts > self._ttl:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: str) -> None:
        if key in self._data:
            self._data[key] = (value, time.monotonic())
            return
        if len(self._data) >= self._maxsize:
            # 淘汰最旧条目
            oldest = min(self._data, key=lambda k: self._data[k][1])
            del self._data[oldest]
        self._data[key] = (value, time.monotonic())

    def clear(self) -> None:
        self._data.clear()

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __len__(self) -> int:
        return len(self._data)


class EventHistory:
    """进程内最近事件缓存，用于 Dashboard 刷新后的告警回放"""

    def __init__(self, maxlen: int = 200):
        self._events: deque[dict] = deque(maxlen=maxlen)

    def append(self, event: dict) -> None:
        payload = dict(event)
        payload.setdefault("received_at", int(time.time() * 1000))
        self._events.appendleft(payload)

    def recent(self, limit: int = 100, session_id: str | None = None) -> list[dict]:
        bounded_limit = max(1, min(limit, self._events.maxlen or 200))
        events = list(self._events)
        if session_id:
            events = [
                event for event in events
                if event.get("session_id") == session_id
            ]
        return events[:bounded_limit]

    def clear(self) -> None:
        self._events.clear()


@dataclass
class AppState:
    """审计引擎全局状态，所有服务实例集中管理，便于测试和生命周期控制"""
    hmac_signer: HmacSigner = field(default_factory=HmacSigner)
    key_manager: KeyManager = field(default_factory=KeyManager)
    template_matcher: TemplateMatcher = field(default_factory=lambda: TemplateMatcher("config/task_templates.json"))
    graph_constraint: GraphConstraint = field(default_factory=GraphConstraint)
    taint_tracker: TaintTracker = field(default_factory=TaintTracker)
    stats_baseline: StatsBaseline = field(default_factory=StatsBaseline)
    slm_reviewer: SlmReviewer = field(default_factory=SlmReviewer)
    rule_engine: RuleEngine = field(default_factory=RuleEngine)
    sql_parser: SqlParser = field(default_factory=SqlParser)
    ws_manager: WebSocketManager = field(default_factory=WebSocketManager)
    event_history: EventHistory = field(default_factory=lambda: EventHistory(maxlen=200))
    session_templates: _TtlCache = field(default_factory=lambda: _TtlCache(maxsize=4096, ttl_seconds=3600))
    session_system_prompts: dict[str, str] = field(default_factory=dict)
    keys: SessionKeys | None = None
    config_path: Path = Path("config/task_templates.json")


state = AppState()


def _tool_call_event(
    req: SignRequest,
    *,
    decision: str,
    causal_id: str | None,
    taint_tags: list[str],
    reason: str,
    timestamp: int,
) -> dict:
    return ToolCallEvent(
        session_id=req.session_id,
        tool_name=req.tool_name,
        decision=decision,
        causal_id=causal_id,
        taint_tags=taint_tags,
        reason=reason,
        timestamp=timestamp,
        pid=req.pid,
    ).model_dump()


def _taint_update_event(
    session_id: str,
    active_tags: list[str],
    timestamp: int,
) -> dict:
    return TaintUpdateEvent(
        session_id=session_id,
        source_type=active_tags[0] if active_tags else "none",
        active_tags=active_tags,
        timestamp=timestamp,
    ).model_dump()


def _ebpf_intercept_event(req: EbpfInterceptRequest) -> dict:
    return {
        "type": "ebpf_intercept",
        "pid": req.pid,
        "syscall": req.syscall,
        "causal_id_valid": req.causal_id_valid,
        "action": req.action,
        "reason": req.reason,
        "timestamp": req.timestamp or time.time_ns(),
    }


def _read_task_templates_config() -> dict:
    with state.config_path.open(encoding="utf-8") as f:
        return json.load(f)


def _write_task_templates_config(config: TaskTemplatesConfig) -> None:
    state.config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = config.model_dump()
    tmp_path = state.config_path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp_path, state.config_path)


logger = logging.getLogger("agent-guardian")


def _sync_blacklist() -> None:
    try:
        config_data = _read_task_templates_config()
        state.graph_constraint.set_blacklist(config_data.get("global_blacklist", []))
    except Exception as e:
        logger.warning("全局黑名单同步失败: %s", e)


async def _record_and_broadcast(event: dict) -> None:
    state.event_history.append(event)
    await state.ws_manager.broadcast(event)


_temp_key_path: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _temp_key_path
    try:
        state.keys = state.key_manager.initialize("/etc/agent-guardian/master.key")
    except FileNotFoundError:
        if os.environ.get("AGENT_GUARDIAN_ENV") == "production":
            raise RuntimeError(
                "生产模式要求 /etc/agent-guardian/master.key 存在"
            )
        logger.warning("master.key 不存在，使用临时密钥（仅开发模式）")
        import tempfile
        tmp_key = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        tmp_key.write(os.urandom(32))
        tmp_key.close()
        _temp_key_path = tmp_key.name
        atexit.register(_cleanup_temp_key)
        state.keys = state.key_manager.initialize(tmp_key.name)

    # 从配置加载全局黑名单
    try:
        config_data = _read_task_templates_config()
        state.graph_constraint.set_blacklist(config_data.get("global_blacklist", []))
    except Exception:
        pass

    asyncio.create_task(_rotate_keys())
    asyncio.create_task(_watch_config())
    asyncio.create_task(_cleanup_taint_sessions())

    yield
    # shutdown


def _cleanup_temp_key() -> None:
    global _temp_key_path
    if _temp_key_path and os.path.exists(_temp_key_path):
        try:
            os.unlink(_temp_key_path)
        except OSError:
            pass
        _temp_key_path = None


async def _cleanup_taint_sessions():
    """定时清理过期的污点追踪会话"""
    while True:
        await asyncio.sleep(1800)  # 每 30 分钟
        try:
            removed = state.taint_tracker.cleanup_old_sessions()
            if removed:
                await _record_and_broadcast({
                    "type": "session_cleanup",
                    "removed": removed,
                })
        except Exception:
            pass


app = FastAPI(title="Agent-Guardian", lifespan=lifespan)


async def _rotate_keys():
    while True:
        await asyncio.sleep(30)
        try:
            state.keys = await state.key_manager.rotate()
        except Exception:
            pass


async def _watch_config():
    """监听 config/ 目录，文件变更时自动热加载模板"""
    async for changes in awatch("config/"):
        count = state.template_matcher.reload()
        _sync_blacklist()
        await _record_and_broadcast({
            "type": "config_reloaded",
            "templates_loaded": count,
            "changes": [
                {"path": str(p), "kind": k.name} for k, p in changes
            ],
        })


_rate_buckets: dict[str, tuple[float, int]] = defaultdict(lambda: (time.monotonic(), 60))
_rate_lock = asyncio.Lock()
_RATE_LIMIT = 60   # 每分钟请求数
_RATE_WINDOW = 60  # 窗口秒数


async def _check_rate_limit(key: str) -> bool:
    """简易令牌桶，返回 True 表示未超限"""
    async with _rate_lock:
        window_start, tokens = _rate_buckets[key]
        now = time.monotonic()
        if now - window_start > _RATE_WINDOW:
            window_start = now
            tokens = _RATE_LIMIT
        if tokens <= 0:
            return False
        _rate_buckets[key] = (window_start, tokens - 1)
        return True


@app.post("/api/v1/causal-id/sign", response_model=SignResponse)
async def handle_sign_request(req: SignRequest) -> SignResponse:
    if not await _check_rate_limit(req.session_id):
        return SignResponse(
            decision="block",
            reason="请求频率超限，请稍后重试",
            mode="ask",
        )

    now_ns = time.time_ns()

    # 1. 模板匹配（首次匹配后缓存，TTL 1h + 容量限制 4096）
    if req.session_id not in state.session_templates:
        template, method = state.template_matcher.match(req.input_messages)
        if template is not None:
            state.session_templates.set(req.session_id, template.id)
            state.graph_constraint.load_template(template)

    # 2. 污点传播
    previous_tags = {
        t.value for t in state.taint_tracker.get_active_tags(req.session_id)
    }
    tags = state.taint_tracker.propagate(req.session_id, req.tool_name, req.params_hash)
    tags_str = [t.value for t in tags]
    if tags_str and set(tags_str) != previous_tags:
        asyncio.create_task(_record_and_broadcast(
            _taint_update_event(req.session_id, tags_str, now_ns)
        ))

    # 3. SQL 分析 (DDL/DCL 操作直接阻断)
    sql_tools = {"db_query", "sql_exec", "sql_query"}
    if req.tool_name in sql_tools and req.params:
        forbidden = state.graph_constraint.forbidden_categories
        if forbidden:
            sql_analysis_result = state.sql_parser.analyze(req.params)
            if (sql_analysis_result.has_ddl and "DDL" in forbidden):
                return SignResponse(
                    decision="block",
                    reason="SQL 中包含 DDL 操作 (被当前任务模板禁止)",
                    taint_tags=tags_str,
                    mode="ask",
                )
            if (sql_analysis_result.has_dcl and "DCL" in forbidden):
                return SignResponse(
                    decision="block",
                    reason="SQL 中包含 DCL 操作 (被当前任务模板禁止)",
                    taint_tags=tags_str,
                    mode="ask",
                )

    # 4. 图约束检查
    result = state.graph_constraint.check(req.session_id, req.tool_name, tags)
    reason = result.reason

    # 5. 决策 + 签名
    causal_id = None
    decision = result.decision.value

    if result.decision == Decision.ALLOW:
        if state.keys is not None:
            causal_id = state.hmac_signer.sign(
                state.keys.active, req.pid, req.tool_name, now_ns
            ).hex()
            asyncio.create_task(_record_and_broadcast({
                "type": "causal_id_issued",
                "session_id": req.session_id,
                "tool_name": req.tool_name,
                "pid": req.pid,
            }))

    elif result.decision == Decision.BLOCK:
        asyncio.create_task(_record_and_broadcast({
            "type": "tool_blocked",
            "session_id": req.session_id,
            "tool_name": req.tool_name,
            "reason": reason,
            "tags": tags_str,
        }))

    elif result.decision == Decision.ASK:
        write_send_tools = {"send_email", "write_file", "http_post", "upload"}
        has_untrusted_taint = bool(
            {"UNTRUSTED_FILE", "UNTRUSTED_API"} & set(tags_str))
        if has_untrusted_taint and req.tool_name in write_send_tools:
            risk, rule_reason = await state.rule_engine.review(
                req.params, req.session_id
            )
            if state.slm_reviewer.is_available():
                slm_risk, slm_reason = await state.slm_reviewer.review(
                    req.params, req.session_id
                )
                if slm_risk > risk:
                    risk, rule_reason = slm_risk, slm_reason
            if risk > 0.7:
                decision = "block"
                reason = f"规则引擎 高风险({risk:.2f}): {rule_reason}"
                asyncio.create_task(_record_and_broadcast({
                    "type": "rule_alert",
                    "session_id": req.session_id,
                    "tool_name": req.tool_name,
                    "risk_score": risk,
                    "reason": rule_reason,
                }))

    # 6. 统计记录
    graph_matched = result.decision == Decision.ALLOW
    call_count = len(state.graph_constraint.get_path(req.session_id))
    interval_ms = 100.0 if call_count > 1 else 0.0
    state.stats_baseline.record_call(
        req.session_id, req.tool_name, interval_ms,
        tainted=len(tags) > 0,
        graph_matched=graph_matched,
    )

    snap = state.stats_baseline.get_snapshot(req.session_id)
    asyncio.create_task(_record_and_broadcast(_tool_call_event(
        req,
        decision=decision,
        causal_id=causal_id,
        taint_tags=tags_str,
        reason=reason,
        timestamp=now_ns,
    )))
    asyncio.create_task(_record_and_broadcast({
        "type": "stats_update",
        "session_id": req.session_id,
        "snapshot": {
            "interval_p95_ms": snap.interval_p95_ms,
            "entropy_current": snap.entropy_current,
            "taint_ratio": snap.taint_ratio,
            "graph_unknown_count": snap.graph_unknown_count,
        },
    }))

    return SignResponse(
        causal_id=causal_id,
        decision=decision,
        taint_tags=tags_str,
        reason=reason,
        mode="ask",
    )


@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await state.ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except Exception:
        await state.ws_manager.disconnect(ws)


@app.get("/api/v1/events/recent")
async def get_recent_events(limit: int = 100, session_id: str | None = None):
    return {
        "events": state.event_history.recent(
            limit=limit,
            session_id=session_id,
        )
    }


@app.get("/api/v1/sessions/{session_id}/stats")
async def get_session_stats(session_id: str):
    snap = state.stats_baseline.get_snapshot(session_id)
    return {
        "interval_p95_ms": snap.interval_p95_ms,
        "entropy_current": snap.entropy_current,
        "taint_ratio": snap.taint_ratio,
        "graph_unknown_count": snap.graph_unknown_count,
    }


@app.get("/api/v1/sessions/{session_id}/graph")
async def get_session_graph(session_id: str):
    return {"path": state.graph_constraint.get_path(session_id)}


@app.post("/api/v1/frida/system-prompt")
async def receive_system_prompt(req: SystemPromptRequest):
    """接收 OpenClaw Plugin 发送的 System Prompt"""
    template, method = state.template_matcher.match(req.system_prompt)
    if template:
        state.session_templates.set(req.session_id, template.id)
        state.graph_constraint.load_template(template)
    else:
        state.session_system_prompts[req.session_id] = req.system_prompt
    return {
        "status": "ok",
        "template": template.id if template else None,
        "method": method,
    }


@app.post("/api/v1/frida/context")
async def receive_tool_context(req: ContextRequest):
    """接收 OpenClaw Plugin 发送的工具调用上下文"""
    return {"status": "ok"}


@app.post("/api/v1/taint/source")
async def tag_taint_source(req: TaintSourceRequest):
    state.taint_tracker.tag_source(req.session_id, req.source_type)
    active_tags = [t.value for t in state.taint_tracker.get_active_tags(req.session_id)]
    await _record_and_broadcast(_taint_update_event(
        req.session_id,
        active_tags,
        time.time_ns(),
    ))
    return {"status": "ok", "active_tags": active_tags}


@app.post("/api/v1/ebpf/intercept")
async def receive_ebpf_intercept(req: EbpfInterceptRequest):
    event = _ebpf_intercept_event(req)
    await _record_and_broadcast(event)
    return {"status": "ok", "event": event}


@app.post("/api/v1/config/reload")
async def reload_config():
    count = state.template_matcher.reload()
    return {"templates_loaded": count}


@app.get("/api/v1/config/task-templates")
async def get_task_templates_config():
    return _read_task_templates_config()


@app.put("/api/v1/config/task-templates")
async def update_task_templates_config(config: TaskTemplatesConfig):
    _write_task_templates_config(config)
    count = state.template_matcher.reload()
    _sync_blacklist()
    await _record_and_broadcast({
        "type": "config_reloaded",
        "templates_loaded": count,
        "changes": [
            {"path": str(state.config_path), "kind": "modified"},
        ],
    })
    return {"status": "ok", "templates_loaded": count}


@app.get("/health")
async def health():
    slm_available = state.slm_reviewer.is_available()
    return {
        "status": "ok",
        "slm_available": slm_available,
        "review_backend": "onnx" if slm_available else "rule_engine",
        "rule_engine_available": state.rule_engine.is_available(),
    }
