= 审计引擎

审计引擎是 AgentGuardian 的核心决策层，由 9 个 Python 模块和 1 个 FastAPI 入口组成。所有模块保持无状态或会话级状态，通过 server.py 中的全局实例协作。

== 模块总览

#table(
  columns: (auto, auto, 1fr),
  [*模块*], [*行数*], [*职责*],
  [`server.py`], [~544], [FastAPI 应用入口，生命周期管理，8 个 HTTP 端点 + 1 个 WebSocket 端点。],
  [`hmac_signer.py`], [22], [HMAC-SHA256 CausalID 签发和常量时间验签。],
  [`key_manager.py`], [93], [PBKDF2 会话密钥派生，30s 轮换，active/grace 双密钥，`_send_key_update` 推送，`_save_state`/`_load_state` 持久化到 `/var/lib/agent-guardian/state.json`。],
  [`template_matcher.py`], [99], [模板匹配：结构化标签 → MinHash 近似 → 兜底。],
  [`graph_constraint.py`], [83], [O(1) 边查询图约束引擎，决策矩阵 ALLOW/ASK/BLOCK。],
  [`taint_tracker.py`], [50], [仅追加污点追踪，6 标签系统，UNTRUSTED_SOURCES 触发传播。],
  [`sql_parser.py`], [84], [sqlparse 词法分析，DDL/DCL 检测，防注释混淆绕过。],
  [`stats_baseline.py`], [76], [滑动窗口统计基线，仅 Dashboard 可视化。],
  [`slm_reviewer.py`], [~149], [ONNX all-MiniLM-L6-v2 嵌入模型，384 维余弦相似度与基线样本比较。模型不存在时降级为中性分数 0.5。],
  [`websocket_manager.py`], [34], [基于频道的 WebSocket 连接管理。],
)

== hmac_signer.py

`HmacSigner` 类负责 CausalID 的签发和验证。

签名 payload 格式：`"{pid}|{tool_name}|{timestamp_ns}|{ttl_ns}"`，使用 `hmac.new(key, payload, hashlib.sha256).digest()` 生成 32 字节 HMAC。

验签使用 `hmac.compare_digest()` 常量时间比较，防止时序侧信道攻击。

降级路径：当 审计引擎超时或无法决策时，调用 `sign_unverified()` 返回 `b"UNVERIFIED_" + secrets.token_hex(8)`，允许 Agent 继续执行但标记为未验证。

#table(
  columns: (auto, auto, auto, 1fr),
  [*方法*], [*输入*], [*输出*], [*说明*],
  [`sign(key, pid, tool_name, ts, ttl_ns)`], [32 bytes key + int + str + int + int], [32 bytes], [HMAC-SHA256 签发 CausalID。],
  [`verify(key, cid, pid, tool_name, ts, ttl_ns)`], [同上 + 32 bytes CausalID], [bool], [常量时间验签。],
  [`sign_unverified()`], [无], [bytes], [降级标记 `UNVERIFIED_<nonce>`。],
)

== key_manager.py

`KeyManager` 类管理会话密钥的派生和轮换。主密钥从文件读取（最少 32 字节），截断为 32 字节后通过 PBKDF2-HMAC-SHA256 派生每轮会话密钥。

`SessionKeys` 数据结构：
- `active`: 32 bytes，当前签发用
- `grace`: 32 bytes，旧密钥仅用于验签，60s 后丢弃
- `round`: int，轮换计数

轮换策略：每 30 秒调用 `rotate()`，active 移入 grace，派生新的 active。eBPF 侧同步更新 BPF Map 中的 `session_key`。

#table(
  columns: (auto, 1fr),
  [*方法*], [*说明*],
  [`derive_session_key(master_key, round)`], [PBKDF2-HMAC-SHA256，info=`"session-{round}"`，1 次迭代，32 字节输出。确定性派生，同 round 必然产生相同 key。],
  [`initialize(master_key_path)`], [读文件 → 校验长度 → 截断 32 字节 → 派生 round=1 的 SessionKeys。],
  [`rotate()`], [round+1 → 新 active → 旧 active 移入 grace → 返回新 SessionKeys。],
)

== template_matcher.py

`TemplateMatcher` 通过结构化标签、MinHash 近似匹配和兜底策略识别 Agent 当前执行的任务类型，并加载对应的图约束。

#table(
  columns: (auto, auto, auto, 1fr),
  [*层*], [*方法*], [*阈值*], [*说明*],
  [第 1 层], [正则 `<task>(.*?)</task>` 或 `<goal>(.*?)</goal>`], [精确匹配], [从 System Prompt 提取结构化标签，在 `_tag_index` 中查找。命中率最高时为 `"exact"`。],
  [第 2 层], [MinHash + Jaccard 相似度], [≥0.80 命中，≥0.60 次优], [使用 datasketch MinHash（128 排列），将输入与模板的预计算签名比较。命中时为 `"minhash"`。],
  [第 3 层], [兜底], [无], [前两层均未命中时返回 `(None, "none")`，系统使用默认保守策略。],
)

`TaskTemplate` 数据结构：
- `id`: 模板标识符
- `graph`: 工具调用图（邻接表 dict）
- `terminals`: 终端工具列表
- `forbidden_tool_categories`: 禁止的工具类别
- `require_slm_review`: 需要 SLM 审查的工具
- `minhash_signature`: 预计算的 MinHash 签名（128 个 int）
- `structured_tag_hash`: 结构化标签值

静态方法 `compute_minhash(text, num_perm=128)` 可独立用于预计算模板签名。

== graph_constraint.py

`GraphConstraint` 是 审计引擎的决策核心。它维护每个会话的调用历史和当前图，通过 O(1) 边查询实现实时决策。

全局黑名单通过 `set_blacklist()` 方法动态加载（来自 `config/task_templates.json` 的 `global_blacklist` 配置）。典型值包含 `bash_exec`、`file_delete`、`config_modify`。命中黑名单直接 BLOCK，不进入图检查。

决策矩阵：

#table(
  columns: (auto, auto, 1fr),
  [*条件*], [*决策*], [*说明*],
  [工具在黑名单中], [BLOCK], [无条件阻断，不检查图。],
  [首次调用（无前驱）], [ALLOW], [入口节点，信任模板定义。],
  [图中边存在 + 无污点], [ALLOW], [正常工具调用流程。],
  [图中边存在 + 有污点], [ASK], [存在数据流风险，交由上层或 SLM 判断。],
  [无边 + 在禁止类别中], [BLOCK], [模板明确禁止的工具类别。],
  [无边 + 非敏感], [ASK], [不在图中但非高风险，保守询问。],
)

`GraphCheckResult` 包含 `decision`（Decision 枚举）、`reason`（解释字符串）、`current_path`（调用链历史）。

`add_edge(session_id, from_tool, to_tool)` 支持动态扩展图，允许 Agent 探索模板定义外的合法路径。

== taint_tracker.py

`TaintTracker` 实现仅追加的污点传播。6 种标签：

#table(
  columns: (auto, 1fr),
  [*标签*], [*含义*],
  [`USER_INPUT`], [来自用户直接输入。],
  [`UNTRUSTED_FILE`], [来自不受信任的文件（触发传播）。],
  [`UNTRUSTED_API`], [来自不受信任的外部 API（触发传播）。],
  [`SYSTEM_TRUSTED`], [系统信任来源，不触发传播。],
  [`DERIVED_UNTRUSTED`], [由不受信任来源派生。],
  [`TAINTED`], [传播标记，随 DERIVED_UNTRUSTED 一起添加。],
)

只有 `UNTRUSTED_SOURCES = {UNTRUSTED_FILE, UNTRUSTED_API}` 会触发 `propagate()` 添加 `DERIVED_UNTRUSTED` 和 `TAINTED` 标签。`SYSTEM_TRUSTED` 和 `USER_INPUT` 不触发传播。

`cleanup_old_sessions(ttl_seconds)` 方法定期清理过期会话的污点状态，防止内存泄漏。

== sql_parser.py

`SqlParser` 使用 `sqlparse` 库进行词法分析，解决正则无法可靠处理的 SQL 注释混淆问题。

处理流程：
1. 提取 MySQL 条件注释 `/*!12345 DROP TABLE*/`（这种注释会被 MySQL 执行）
2. 使用 `sqlparse.format(sql, strip_comments=True)` 去除普通 `--` 和 `/* */` 注释
3. 使用 `sqlparse.parse()` 解析得到语句 token 列表
4. 遍历每条语句：通过 `statement.get_type()` 获取类型、在展平的 token 中检测 DDL/DCL 关键字、通过 `Identifier.get_real_name()` 提取表名

DDL 关键字：`CREATE`、`DROP`、`ALTER`、`TRUNCATE`、`RENAME`
DCL 关键字：`GRANT`、`REVOKE`

`SqlAnalysis` 结果包含 `has_ddl`、`has_dcl`、`tables_touched`、`statement_types`。

== stats_baseline.py

`StatsBaseline` 提供仅用于 Dashboard 可视化的统计基线，不参与任何阻断决策。

统计指标（滑动窗口默认 100 次调用）：
- `interval_p95_ms`: 调用间隔 P95
- `entropy_current`: 工具调用的 Shannon 熵
- `entropy_heuristic_upper`: 启发式上限（`entropy * 1.5`）
- `taint_ratio`: 污点调用占比
- `graph_unknown_count`: 图中未匹配的调用计数

== slm_reviewer.py

`SlmReviewer` 实现基于 ONNX 嵌入模型的语义审查，用于补充规则引擎对自然语言外传意图的识别能力。使用 all-MiniLM-L6-v2 模型，经 ONNX 导出后运行在 CPU 推理后端。

=== 模型架构

- *基座模型*: all-MiniLM-L6-v2（Sentence-Transformers），导出为 ONNX 格式
- *嵌入维度*: 384 维向量，经二范数归一化
- *推理后端*: ONNX Runtime，CPUExecutionProvider
- *模型路径*: `~/.cache/agent-guardian/model.onnx`（约 90MB）
- *分词器路径*: `~/.cache/agent-guardian/`（transformers AutoTokenizer，local_files_only）
- *基线样本*: 47 条预计算嵌入（来自 `slm_baseline.py` 的 `get_embeddings_array()`）

=== 审查流程

```text
1. 输入文本 → 切分为 ≤256 字符的块（_chunk_text）
2. 每块 → tokenizer（max_length=128, padding/truncation）
       → ONNX 推理 → mean pooling → 二范数归一化 → 384 维向量
3. 多块结果取均值 → 再次二范数归一化
4. 与 47 条基线样本计算余弦相似度（sklearn.metrics.pairwise.cosine_similarity）
5. 取最大相似度 → 阈值判断
```

=== 阈值与决策

#table(
  columns: (auto, auto, 1fr),
  [*阈值区间*], [*风险评分*], [*说明*],
  [≥0.70], [max_sim], [高风险：语义匹配已知告警模式，建议阻断。],
  [0.45–0.70], [max_sim], [边界可疑：需人工或额外检查判断。],
  [低于 0.45], [max_sim], [语义安全：与基线样本无显著相似性，放行。],
)

=== 降级策略

当 `model.onnx` 不存在时，`is_available()` 返回 `False`，`review()` 返回 `(0.5, "slm_unavailable")` 中性分数。系统不因此阻断 Agent 正常运行。实测推理延迟约 8.4ms。

== websocket_manager.py

`WebSocketManager` 基于频道管理 WebSocket 连接，默认频道 `"events"`。`broadcast()` 向频道内所有连接发送 JSON 事件，自动清理死连接。`send_to()` 用于单播。

== server.py

FastAPI 应用入口，12 个 HTTP 端点 + WebSocket + 后台热重载。

=== 生命周期

使用 FastAPI `lifespan` context manager（非已弃用的 `@app.on_event`）：
1. 调用 `KeyManager.initialize("/etc/agent-guardian/master.key")`
2. 如果文件不存在 → 开发模式：生成临时 32 字节密钥
3. 启动后台 `_rotate_keys()` 协程，每 30 秒轮换一次
4. 启动后台 `_watch_config()` 协程，使用 `watchfiles.awatch("config/")` 监听 `task_templates.json` 变动 → 自动调用 `TemplateMatcher.reload()`

=== 端点

#table(
  columns: (auto, auto, 1fr),
  [*端点*], [*方法*], [*处理流程*],
  [`/api/v1/causal-id/sign`], [POST], [模板匹配（首次调用时）→ 污点传播 → 图约束检查 → ALLOW: HMAC 签名 / ASK: SLM 审查（条件触发）→ 结果降级 / BLOCK: 不签名。记录统计，在 4 个决策点 WebSocket 广播。],
  [`/api/v1/sessions/{id}/stats`], [GET], [返回 `StatsSnapshot`（P95、熵、污点比率、未匹配计数）。],
  [`/api/v1/sessions/{id}/graph`], [GET], [返回会话调用路径列表。],
  [`/api/v1/config/reload`], [POST], [调用 `TemplateMatcher.reload()` 热重载 `config/task_templates.json`。],
  [`/api/v1/config/task-templates`], [GET/PUT], [读取或保存任务模板配置；PUT 成功后热重载并广播 `config_reloaded`。],
  [`/ws/events`], [WebSocket], [连接 `WebSocketManager`，推送 `tool_call`、`taint_update`、`rule_alert`、`stats_update` 等事件。],
  [`/api/v1/frida/system-prompt`], [POST], [接收 OpenClaw System Prompt，调用 `TemplateMatcher.match()` 更新会话模板匹配状态。],
  [`/api/v1/frida/context`], [POST], [接收 OpenClaw 工具调用上下文，更新 `TaintTracker` 污点状态。],
  [`/health`], [GET], [返回服务状态、审查后端和规则引擎可用性。],
)

=== 请求/响应模型

`SignRequest`：`pid` (int)、`tool_name` (str)、`params_hash` (str)、`params` (str，原始参数文本，供 SQL 解析和内容审查)、`input_messages` (str)、`session_id` (str)

`SignResponse`：`causal_id` (str|None)、`decision` (str)、`taint_tags` (list[str])、`reason` (str)、`mode` (str)

`SystemPromptRequest`：`session_id` (str)、`system_prompt` (str)

`ContextRequest`：`type` (str)、`tool_name` (str)、`params` (str)、`session_id` (str)、`agent_id` (str|None)

=== 处理流水线（/api/v1/causal-id/sign）

```text
1. 首次调用 → TemplateMatcher.match(input_messages)
   -> 命中: 缓存模板 ID，加载图到 GraphConstraint
   -> 未命中: 使用默认保守策略
2. TaintTracker.propagate(session_id, tool_name, params_hash)
3. GraphConstraint.check(session_id, tool_name, active_tags)
4. 决策:
   -> ALLOW: HmacSigner.sign(active_key, pid, tool_name, ts, ttl_ns)
   -> ASK: 如果 UNTRUSTED_FILE + write/send 工具 → SLM 审查
           SLM 风险 >0.7 → 降级为 "block"，返回 UNVERIFIED
           否则 → 返回 UNVERIFIED（ASK 模式不签名）
   -> BLOCK: 返回 UNVERIFIED（不签名）
5. StatsBaseline.record_call(...)
6. WebSocketManager.broadcast("causal_id_issued", ...)
7. 决策为 ASK/BLOCK 时 → 再 broadcast("tool_blocked", ...)
```

决策时序：`graph_constraint.py` 中的黑名单通过 `set_blacklist()` 方法动态加载（来自 `config/task_templates.json` 的 `global_blacklist` 配置），不再硬编码。`bash_exec`、`file_delete`、`config_modify` 等工具无论图结构如何都会被阻断。
