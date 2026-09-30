= 跨模块协议

AgentGuardian 各组件之间通过 4 种协议通信。本章描述每种协议的格式、消息类型和错误处理。

== 协议总览

#table(
  columns: (auto, auto, auto, auto),
  [*协议*], [*方向*], [*传输*], [*用途*],
  [HTTP], [Frida → 审计引擎], [TCP (localhost:8000)], [请求 CausalID 签名，查询会话状态。],
  [Unix Socket], [Frida → causal-guardian], [AF_UNIX (`/var/run/causal-guardian.sock`)], [注册 CausalID，更新会话密钥。],
  [WebSocket], [审计引擎 → Dashboard], [TCP (`/ws/events`)], [推送实时事件流。],
  [BPF Map], [causal-guardian ↔ eBPF], [内核共享内存], [CausalID 查表，会话密钥同步，白名单管理。],
)

== HTTP 协议

=== POST /api/v1/causal-id/sign

请求：
```json
{
  "pid": 12345,
  "tool_name": "bash_exec",
  "params_hash": "sha256 hex string",
  "params": "raw tool parameters",
  "input_messages": "Agent input context...",
  "session_id": "uuid-string"
}
```

响应：
```json
{
  "causal_id": "a1b2c3...32 bytes hex" | null,
  "decision": "allow" | "ask" | "block",
  "taint_tags": ["UNTRUSTED_API", "DERIVED_UNTRUSTED", "TAINTED"],
  "reason": "工具在全局黑名单中",
  "mode": "enforcing" | "ask" | "permissive"
}
```

错误处理：
- 100ms 超时 → Frida 侧降级为 `UNVERIFIED_`
- `causal_id` 为 null 时 eBPF 内核监控进入白名单/UNVERIFIED 路径

=== GET /api/v1/sessions/{session_id}/stats

响应：`StatsSnapshot` JSON
```json
{
  "interval_p95_ms": 42.5,
  "entropy_current": 1.85,
  "entropy_heuristic_upper": 2.77,
  "taint_ratio": 0.33,
  "graph_unknown_count": 2
}
```

=== GET /health

响应：
```json
{
  "status": "ok",
  "slm_available": false,
  "review_backend": "rule_engine",
  "rule_engine_available": true
}
```

=== GET /api/v1/events/recent

返回最近 Dashboard 事件，用于页面刷新后的告警回放。可通过 `limit` 控制返回数量，也可用 `session_id` 过滤单个会话。

响应：
```json
{
  "events": [
    {
      "type": "rule_alert",
      "session_id": "judge-demo",
      "tool_name": "send_email",
      "risk_score": 0.85,
      "reason": "敏感关键词命中",
      "received_at": 1719000000000
    }
  ]
}
```

== Unix Socket 协议

Socket 路径：`/var/run/causal-guardian.sock`

权限：`0600`（仅 root 可访问）

所有消息小端序，1 字节对齐。最大消息 64 字节。

=== MSG_REGISTER (0x01)

注册 CausalID 到 causal-guardian：

```text
请求:  {u8 type} {u64 pid} {u8[32] causal_id} {u64 timestamp_ns}
       ─ 43 字节 ─
响应:  {u8 type} {u8 status}
       ─ 2 字节 ─
```

状态码：
- `0` — 成功
- `1` — BPF Map 已满（4096 条）
- `2` — 无效参数（causal_id 全零等）

=== MSG_KEY_UPDATE (0x02)

更新 BPF Map 中的会话密钥：

```text
请求:  {u8 type} {u8[32] active_key} {u8[32] grace_key}
       ─ 65 字节 ─
响应:  {u8 type} {u8 status}
       ─ 2 字节 ─
```

密钥更新由 KeyManager 的 `rotate()` 触发，通过 Unix Socket 推送到 causal-guardian。

=== 错误处理

- connect() 失败 → FridaBridge 降级，所有后续调用返回 UNVERIFIED
- sendall() 失败 → 断开 socket，下次调用重连
- recv() 超时（50ms）→ 视为失败，不阻塞 Agent

== WebSocket 协议

WebSocket 端点：`ws://<host>:8000/ws/events`

消息格式：JSON 文本帧，每条消息包含 `type` 字段和对应 payload。广播触发点 4 个：

1. `causal_id_issued` — 审计引擎签发 CausalID 后
2. `tool_blocked` — 决策为 ASK/BLOCK 时
3. `rule_alert` — SLM 或规则引擎审查发现高风险时
4. `stats_update` — 统计指标更新时

=== tool_call 事件

```json
{
  "type": "tool_call",
  "session_id": "uuid",
  "tool_name": "send_email",
  "decision": "ask",
  "causal_id": "hex string | null",
  "taint_tags": ["UNTRUSTED_FILE", "TAINTED"],
  "reason": "UNTRUSTED_FILE + send 工具触发 SLM 审查",
  "timestamp": 1719000000
}
```

=== taint_update 事件

```json
{
  "type": "taint_update",
  "session_id": "uuid",
  "source_type": "UNTRUSTED_API",
  "active_tags": ["UNTRUSTED_API", "DERIVED_UNTRUSTED", "TAINTED"],
  "timestamp": 1719000000
}
```

=== ebpf_intercept 事件

```json
{
  "type": "ebpf_intercept",
  "pid": 67890,
  "tgid": 67890,
  "syscall": "execve",
  "causal_id_valid": false,
  "action": "block",
  "reason": "CausalID 未找到且不在白名单中",
  "timestamp": 1719000000
}
```

=== 连接管理

`WebSocketManager` 基于频道管理连接，默认频道 `"events"`。`broadcast()` 内部捕获 `WebSocketDisconnect` 异常并静默清理死连接。客户端应实现自动重连逻辑。

== BPF Map 协议

BPF Map 是内核和用户态之间的共享数据结构。causal-guardian 写入，eBPF 探针读取。

=== causal_chain (BPF_MAP_TYPE_LRU_HASH)

```c
struct causal_entry {
    __u8  causal_id[32];
    __u64 timestamp;   // 注册时间（纳秒）
    __u8  validated;   // 是否通过验证
    __u8  flags;       // bit0: UNVERIFIED (CAUSAL_FLAG_UNVERIFIED = 0x01)
};
// Key: __u64 pid_tgid (bpf_get_current_pid_tgid())
```

最大条目：4096。LRU 自动淘汰最久未使用的条目。TTL：5 秒（eBPF 侧 `bpf_ktime_get_ns()` 比较）。

=== session_key (BPF_MAP_TYPE_ARRAY)

```c
struct session_keys {
    __u8 active_key[32];
    __u8 grace_key[32];
};
// Key: 0 (只有一条记录)
```

=== exec_whitelist (BPF_MAP_TYPE_HASH)

```c
// Key: 路径字符串 (如 "/usr/bin/python")
// Value: __u8 (1 = 白名单中)
```

最大条目：128。用于 UNVERIFIED 兜底，仅允许白名单中的可执行文件。

=== alert_events (BPF_MAP_TYPE_PERF_EVENT_ARRAY)

```c
struct alert_event {
    __u32 pid;
    __u32 tgid;
    __u32 syscall;     // __NR_execve 等
    __u8  causal_id[32];
    __u8  reason[64];  // 拦截原因描述
};
```

causal-guardian 通过 perf buffer 订阅此事件，转发到审计引擎后再通过 WebSocket 广播给 Dashboard。

== 协议时序

```text
Frida 动态插桩          审计引擎            causal-guardian    eBPF 内核监控          Dashboard
    |                |                     |                |                 |
    |-- HTTP POST -->|                     |                |                 |
    |   sign req     |                     |                |                 |
    |<-- HTTP resp --|                     |                |                 |
    |   causal_id    |                     |                |                 |
    |                |                     |                |                 |
    |-- Unix Socket ---------------------->|                |                 |
    |   MSG_REGISTER |                     |                |                 |
    |                |                     |-- BPF Map ---->|                 |
    |                |                     |   causal_chain |                 |
    |<-- Unix Socket ----------------------|                |                 |
    |   ACK          |                     |                |                 |
    |                |                     |                |                 |
    |                |-- WebSocket -------------------------------->|
    |                |   tool_call event                           |
    |                |                     |                |                 |
    |                |                     |                |-- perf buffer ->|
    |                |                     |                |   alert_event   |
    |                |                     |                |                 |
    |                |                     |                |<- syscall ------|
    |                |                     |                |   check/block   |
```
