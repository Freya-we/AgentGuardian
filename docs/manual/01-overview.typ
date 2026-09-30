= 项目概览

== 定位

AgentGuardian 是一个面向 LLM Agent 的零信任沙箱系统，通过 eBPF 内核探针、Frida 动态 Hook、密码学验证引擎和红队攻击脚本构成组件化纵深防御体系。系统不修改 Agent 源代码，所有监控通过旁路实现。

当前实现的中心路径：

```text
LLM Agent 进程
  -> Frida 动态插桩截获工具调用
  -> 审计引擎: 模板匹配 -> 污点传播 -> 图约束检查 -> HMAC 签名
  -> causal-guardian 宿主机守护进程写入 BPF Map
  -> eBPF 内核探针验证 CausalID 并拦截非法系统调用
  -> Dashboard 实时事件展示
```

这份手册按当前 checkout 编写，优先描述可以在源码中找到的模块、参数和产物。所有标注的状态均以当前 checkout 为准。

== 能力边界

#table(
  columns: (auto, 1fr),
  [*能力*], [*当前实现位置和说明*],
  [HMAC 签名], [`src/engine/hmac_signer.py`：HMAC-SHA256 CausalID 签发和常量时间验签，支持 UNVERIFIED 降级标记。],
  [密钥管理], [`src/engine/key_manager.py`：PBKDF2-HMAC-SHA256 派生会话密钥，30s 轮换，active/grace 双密钥结构。],
  [模板匹配], [`src/engine/template_matcher.py`：结构化 `<task>` 标签提取 → MinHash 近似匹配 (≥0.80) → 兜底返回 None。],
  [图约束], [`src/engine/graph_constraint.py`：O(1) 边查询，决策矩阵 ALLOW/ASK/BLOCK，全局黑名单 `bash_exec/file_delete/config_modify`。],
  [污点追踪], [`src/engine/taint_tracker.py`：6 标签系统，仅追加传播，UNTRUSTED_SOURCES 触发 DERIVED_UNTRUSTED + TAINTED 派生。],
  [SQL 分析], [`src/engine/sql_parser.py`：sqlparse 词法分析，防止注释混淆绕过，DDL/DCL 关键字检测，MySQL 条件注释提取。],
  [统计基线], [`src/engine/stats_baseline.py`：滑动窗口 P95 间隔、Shannon 熵、污点比率——仅 Dashboard 可视化，不参与决策。],
  [SLM 审查], [`src/engine/slm_reviewer.py`：ONNX all-MiniLM-L6-v2 嵌入模型，384 维余弦相似度与 47 条基线样本比较；阈值 ≥0.70 高风险、0.45-0.70 边界、低于 0.45 放行；模型不存在时降级为中性分数 0.5。],
  [WebSocket], [`src/engine/websocket_manager.py`：基于频道的连接管理，支持广播和单播，用于 Dashboard 实时事件推送。],
  [HTTP API], [`src/engine/server.py`：FastAPI 应用，12 个 HTTP 端点 + WebSocket，生命周期管理（密钥初始化+轮换），开发模式自动生成临时主密钥。],
  [攻击脚本], [`src/attacks/`：3 个场景（供应链投毒、多模态隐写、SQL 对话注入），可演示，自检验证通过。],
  [eBPF 探针], [已实现：`src/ebpf/execve_monitor.bpf.c` 7 个探针 (execve/openat/connect/chmod/fchmod/sendto)，4 个 BPF Map 固定，loader 就位。],
  [causal-guardian], [已实现：`src/causal_guardian/main.c` Unix Socket 守护进程，处理 MSG_REGISTER + MSG_KEY_UPDATE。],
  [Frida Hook], [已实现：14 个 Hook (LangChain 4 + Python 底层 6 + libuv 3 + OpenClaw Plugin 1)，bridge.py 就位。],
  [Dashboard], [已实现：`src/dashboard/` 下 10 个 React + TypeScript 组件，WebSocket 实时事件展示、统计图表、调用链可视化。],
)

== 纵深防御组件总览

#table(
  columns: (auto, 1fr, auto),
  [*组件*], [*职责*], [*状态*],
  [eBPF 内核监控], [内核探针监控 execve/openat/connect/chmod/fchmod/sendto 系统调用，BPF Map 存储 causal_chain/session_key/exec_whitelist/alert_events，perf buffer 推送告警。], [已实现, 7 探针],
  [Frida 动态插桩], [Python + Node.js 运行时动态 Hook，截获 LangChain AgentExecutor/BaseTool、Python 底层 subprocess/os、Node.js libuv、OpenClaw Plugin 调用，通过 Unix Socket 向 causal-guardian 注册 CausalID。], [已实现, 14 Hook],
  [审计引擎], [密码学验证引擎：模板匹配、污点传播、图约束检查、HMAC 签名、SQL 分析、SLM 审查。], [已实现],
  [攻击场景构造], [红队攻击脚本：供应链 API 投毒、多模态隐写、SQL 对话注入。], [已实现, 自检通过],
)

== 运行要求

最小运行环境：

- Python `>=3.11`
- `fastapi`、`uvicorn`、`httpx`、`sqlparse`、`datasketch`
- 开发模式自动生成临时主密钥，无需外部密钥文件

可选依赖：

- eBPF：Linux 内核 `>=5.8`、`libbpf`、`clang`、`bpftool`
- Frida：`frida-tools` Python 包（通过 `uv add frida-tools` 安装）
- Dashboard：Node.js、pnpm
- typst：用于编译技术手册 PDF

== 快速开始

```bash
# 安装依赖
uv sync

# 启动 审计引擎（开发模式，自动生成临时主密钥）
make dev

# 运行测试
make test

# 编译技术手册
make docs
```

`make dev` 默认监听 `0.0.0.0:8000`。开发模式下 `/etc/agent-guardian/master.key` 不存在时自动生成 32 字节临时密钥。

#pagebreak()
== 主要产物

审计引擎运行时不产生文件产物，所有状态在内存中管理。以下是 API 端点和 WebSocket 事件：

#table(
  columns: (auto, auto, 1fr),
  [*端点*], [*方法*], [*说明*],
  [`/api/v1/causal-id/sign`], [POST], [核心签名端点：模板匹配 → 污点传播 → 图约束检查 → 决策 → HMAC 签名。],
  [`/api/v1/sessions/{id}/stats`], [GET], [返回会话的统计快照（P95 间隔、熵、污点比率）。],
  [`/api/v1/sessions/{id}/graph`], [GET], [返回会话的调用路径历史。],
  [`/api/v1/events/recent`], [GET], [返回最近 Dashboard 事件，用于刷新后的告警回放。],
  [`/api/v1/config/reload`], [POST], [热重载 `config/task_templates.json`。],
  [`/ws/events`], [WebSocket], [实时事件流（ebpf_intercept、tool_call、taint_update）。],
  [`/api/v1/frida/system-prompt`], [POST], [OpenClaw System Prompt 接收，更新 TemplateMatcher 上下文。],
  [`/api/v1/frida/context`], [POST], [OpenClaw 工具调用上下文接收，更新污点追踪。],
  [`/health`], [GET], [健康检查，返回服务状态、审查后端和规则引擎可用性。],
)
