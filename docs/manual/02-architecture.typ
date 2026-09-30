= 系统架构

== 组件视图

AgentGuardian 的架构按"Frida 拦截 → 审计引擎决策 → eBPF 强制执行 → Dashboard 展示"理解。

#table(
  columns: (auto, 1fr, 1fr),
  [*组件*], [*职责*], [*实现位置*],
  [服务入口], [FastAPI 应用、生命周期管理、请求模型。], [`src/engine/server.py`],
  [Frida 动态插桩], [Python + Node.js 运行时 Hook，截获工具调用，向审计引擎请求签名。], [`src/frida/bridge.py`、`langchain_hooks.js`、`lowlevel_hooks.js`、`node_lowlevel.js`、`openclaw_plugin.ts`（已实现）],
  [审计引擎], [模板匹配、污点追踪、图约束检查、HMAC 签名、SQL 分析、SLM 审查、统计基线。], [`src/engine/` 下 9 个模块],
  [eBPF 内核监控], [内核系统调用拦截，BPF Map 查表验证 CausalID。], [`src/ebpf/execve_monitor.bpf.c`、`causal_chain.h`、`loader.c`（已实现）],
  [causal-guardian], [宿主机守护进程，Unix Socket 服务端，写入 BPF Map。], [`src/causal_guardian/main.c`（已实现）],
  [攻击场景构造], [红队攻击脚本，3 个场景。], [`src/attacks/`],
  [Dashboard], [React + TypeScript 前端，WebSocket 实时事件，D3.js 可视化。], [`src/dashboard/`（已实现，10 组件）],
)

== 当前目录树

```text
AgentGuardian/
├─ pyproject.toml          uv 项目配置，Python >=3.11
├─ Makefile                install/dev/test/docs/clean 目标
├─ .python-version         3.11
├─ config/
│  └─ task_templates.json  任务模板定义（图、终端节点、禁止类别、SLM 审查标记）
├─ src/
│  ├─ engine/              审计引擎
│  │  ├─ server.py         FastAPI 入口，REST API + WebSocket
│  │  ├─ hmac_signer.py    HMAC-SHA256 CausalID 签名/验签
│  │  ├─ key_manager.py    PBKDF2 会话密钥派生和轮换
│  │  ├─ template_matcher.py  模板匹配
│  │  ├─ graph_constraint.py  图约束引擎
│  │  ├─ taint_tracker.py     污点追踪器
│  │  ├─ sql_parser.py        sqlparse 词法分析
│  │  ├─ stats_baseline.py    统计基线（仅可视化）
│  │  ├─ slm_reviewer.py      ONNX 嵌入模型语义审查
│  │  └─ websocket_manager.py WebSocket 连接管理
│  ├─ frida/               Frida 动态插桩 Hook（已实现：langchain_hooks.js, lowlevel_hooks.js, bridge.py, node_lowlevel.js, openclaw_plugin.ts）
│  ├─ ebpf/                eBPF 内核监控（已实现：execve_monitor.bpf.c, causal_chain.h, loader.c）
│  ├─ causal_guardian/     宿主机守护进程（已实现：main.c）
│  ├─ attacks/             攻击场景构造（已实现）
│  │  ├─ malicious_api.py  场景 1：供应链 API 投毒
│  │  ├─ stego_injector.py 场景 2：多模态隐写
│  │  └─ sql_injector.py   场景 3：SQL 对话注入
│  └─ dashboard/           React 前端（已实现）
├─ tests/                  pytest 单元测试与集成测试
├─ docs/
│  ├─ design.md            比赛设计文档（早期版本）
│  ├─ security-risk-analysis.md  安全风险分析报告
│  ├─ manual/              技术手册 Typst 源文件
│  └─ technical-manual.pdf 编译产物
└─ start_server.sh         服务启动脚本
```

== 数据流

```text
LLM Agent 进程
  |
  |-- Frida Hook 截获工具调用
  |     bridge.py 获取 NSpid 宿主机 PID
  |     OpenClaw Plugin → before_tool_call → POST /api/v1/frida/context
  |
  |-- POST /api/v1/causal-id/sign
  |     审计引擎处理流水线:
  |       1. TemplateMatcher.match() 模板匹配
  |       2. TaintTracker.propagate() 污点传播
  |       3. GraphConstraint.check() 图约束检查
  |       4. HmacSigner.sign() / sign_unverified()
  |       5. SlmReviewer.review() (条件触发)
  |       6. StatsBaseline.record_call()
  |
  |-- inotify 热重载（后台异步）
  |     watchfiles.awatch("config/") → config/task_templates.json 变化
  |     → TemplateMatcher.reload() 自动生效
  |
  |-- 决策结果回传 Frida
  |     ALLOW: 通过 Unix Socket 向 causal-guardian 注册 CausalID
  |     ASK/BLOCK: 返回 UNVERIFIED_ 降级标记
  |     UNVERIFIED 兜底: eBPF 检查 exec_whitelist（flags & 0x01）
  |
  |-- causal-guardian 写入 BPF Map
  |     causal_chain[pid_tgid] = {causal_id, timestamp, validated, flags}
  |     session_key 由 key_manager.rotate() → MSG_KEY_UPDATE 同步
  |
  |-- Agent 执行工具（如 bash_exec）
  |     eBPF 探针 探针查 BPF Map:
  |       验证通过（flags & 0x01 == 0）→ 放行
  |       UNVERIFIED 命中白名单 → 放行
  |       验证失败 → 拦截 + perf buffer 告警
  |
  |-- WebSocket 广播到 Dashboard（4 个决策点）
        causal_id_issued / tool_blocked / rule_alert / stats_update 事件
```

== 关键设计约束

- 旁路而非侵入：所有监控通过 eBPF Hook 和 Frida 插桩实现，不修改 Agent 源代码。
- 机械阶段和 AI 阶段分离：模板匹配、图约束、SQL 分析等为确定性阶段；SLM 审查为可选 AI 阶段。
- 统计不参与决策：StatsBaseline 仅用于 Dashboard 可视化，不作为阻断依据。
- 降级而非阻断：Frida 100ms 超时、SLM 不可用时均降级为 UNVERIFIED，不阻断 Agent 正常运行。
- CausalID 两阶段删除：sys_enter_execve 验证，sys_exit_execve 成功时删除（处理 execve 失败场景）。
- PID 命名空间感知：通过 `/proc/self/status` NSpid 字段获取宿主机视角 PID。

== 配置

#table(
  columns: (auto, 1fr),
  [*来源*], [*职责*],
  [`config/task_templates.json`], [任务模板定义，包含图结构、终端节点、禁止工具类别、需要 SLM 审查的工具。可通过 `/api/v1/config/reload` 热重载。],
  [环境变量 `AGENT_SESSION_ID`], [Frida bridge 读取，标识当前 Agent 会话。],
  [`/etc/agent-guardian/master.key`], [主密钥文件，最少 32 字节。不存在时开发模式自动生成临时密钥。],
)
