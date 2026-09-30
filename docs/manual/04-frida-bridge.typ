= Frida 动态插桩

Frida 动态插桩组件截获 LLM Agent 进程中的工具调用，并向审计引擎请求签名。Frida 运行在 Agent 容器内，通过 Unix Socket 与宿主机上的 causal-guardian 守护进程通信。

#table(
  columns: (auto, auto, 1fr),
  [*状态*], [*文件*], [*说明*],
  [已实现], [`src/frida/bridge.py`], [Python 侧 Frida 控制脚本，PID 翻译、审计引擎 HTTP 通信、Unix Socket 通信、消息处理、Python/Node 运行时选择。],
  [已实现], [`src/frida/langchain_hooks.js`], [Frida JS 脚本：Hook AgentExecutor 和 BaseTool（含 `_arun`），截获上下文和工具调用。],
  [已实现], [`src/frida/lowlevel_hooks.js`], [Frida JS 脚本：Hook subprocess.Popen、os.system、os.popen、requests/urllib3 HTTP 调用。],
  [已实现], [`src/frida/node_lowlevel.js`], [Frida JS 脚本：Hook libuv C 层函数 (uv_spawn、uv_tcp_connect、uv_udp_send)，跨 Node.js 版本稳定。],
  [已实现], [`src/frida/openclaw_plugin.ts`], [OpenClaw Plugin：before_tool_call + before_agent_run 钩子，HTTP 推送至审计引擎，fail-open 设计。],
)

== 架构

```text
LLM Agent 进程（容器内）
  |
  |-- Frida attach (Python 运行时)
  |     langchain_hooks.js: AgentExecutor._take_next_step()
  |                          BaseTool._run() / BaseTool._arun()
  |                          ChatOpenAI._generate()（system prompt 捕获）
  |     lowlevel_hooks.js:  subprocess.Popen.$init / os.system / os.popen
  |                          requests.request / requests.Session.request
  |                          urllib3.HTTPConnectionPool.urlopen
  |
  |-- Frida attach (Node.js 运行时)
  |     node_lowlevel.js: libuv uv_spawn / uv_tcp_connect / uv_udp_send
  |
  |-- OpenClaw Plugin (Agent 框架内)
  |     openclaw_plugin.ts: before_tool_call → HTTP POST /api/v1/frida/context
  |                          before_agent_run → HTTP POST /api/v1/frida/system-prompt
  |
  |-- bridge.py (Python 核心桥)
  |     _get_host_pid(): 读取 /proc/self/status NSpid 获取宿主机 PID
  |     request_causal_id(): POST /api/v1/causal-id/sign (100ms 硬超时)
  |     _send_causal_id(): Unix Socket 注册到 causal-guardian
  |     _load_scripts(): 根据 RUNTIME_PYTHON / RUNTIME_NODE 选择加载脚本
  |
  |-- 降级路径
        超时 100ms / Socket 不可用 / SLM 不可用 → UNVERIFIED 降级
        不抛异常，不阻塞 Agent
```

== bridge.py

`FridaBridge` 类是 Python 侧的核心通信桥。

=== PID 翻译

`_get_host_pid()` 从 `/proc/self/status` 读取 `NSpid` 字段：

```python
# /proc/self/status 示例:
# NSpid:  12345  67890
# parts[1] = PID namespace 内 PID
# parts[2] = 宿主机 PID（如果存在）
```

若没有 namespace 隔离（只有一列），回退到 `os.getpid()`。

=== Unix Socket 通信

Socket 路径：`/var/run/causal-guardian.sock`

消息格式（小端序，1 字节对齐）：
```text
MSG_REGISTER (0x01): {type: u8, pid: u64, causal_id: [u8; 32], timestamp: u64}
响应: {type: u8, status: u8}  // status=0 表示成功
```

50ms Socket 超时。失败时 FridaBridge 将 `self.sock` 置 `None`，下次调用重新连接。

=== 审计引擎 HTTP 通信

`request_causal_id(tool_name, params, input_messages) -> dict`：
- 计算 `params_hash = sha256(params.encode()).hexdigest()`
- `POST /api/v1/causal-id/sign`，100ms 硬超时（`httpx.AsyncClient(timeout=0.1)`）
- 超时返回 `{"causal_id": None, "decision": "allow", "reason": "timeout", "mode": "ask"}`

=== 消息处理

`on_message(message, data)` 回调：
1. 收到 `request_causal_id` 消息
2. 同步调用审计引擎（`asyncio.run_until_complete`）
3. ALLOW + CausalID 存在 → Unix Socket 注册
4. 其他情况 → `UNVERIFIED_` 降级
5. 通过 `script.post()` 回传结果给 Frida JS

== 阻塞机制

Frida JS 中不能自旋等待（`while(...){}` 会卡死 JS 引擎）。系统采用两种可行方式：

#table(
  columns: (auto, auto, 1fr),
  [*方式*], [*推荐度*], [*说明*],
  [A: Python monkey-patch], [推荐], [在 Python 层拦截 `subprocess.Popen`，不使用 Frida JS 做阻塞。简单可靠，无跨语言通信延迟。],
  [B: Frida JS send/recv], [备选], [JS `send()` → Python `on_message()` → Python `script.post()` → JS `recv()`。Frida 的 send 不阻塞 JS，需要 recv 注册回调。比赛答辩时可展示 Frida 能力。],
)

建议先按方式 A 实现，比赛答辩需要展示 Frida 时再切换到方式 B。

== Hook 点

=== langchain_hooks.js

#table(
  columns: (auto, 1fr),
  [*Hook 点*], [*截获信息*],
  [`AgentExecutor._take_next_step()`], [Agent 每次决策循环入口。截获 `this.input`（当前输入消息，含用户 Query + 上一步 Observation）。`send({type: "context", input_messages, session_id})`],
  [`BaseTool._run(tool_input, ...)`], [工具执行入口。截获 `this.name`（工具名）、`tool_input`（参数）。`send({type: "tool_call", tool_name, params})`],
  [`BaseTool._arun(tool_input, ...)`], [异步工具执行入口。与 `_run` 同样的截获逻辑，覆盖异步调用路径。],
  [`ChatOpenAI._generate(messages, ...)`], [LLM 调用入口。截获 `messages[0]` 作为 System Prompt 内容，`send({type: "system_prompt", system_prompt, session_id})`。],
)

=== lowlevel_hooks.js

#table(
  columns: (auto, 1fr),
  [*Hook 点*], [*说明*],
  [`subprocess.Popen.$init`], [子进程入口，在进程创建前拦截。生成 requestId → send 到 Python → 等待 causal_id 回传。],
  [`os.system` / `os.popen`], [直接命令执行，与 `Popen.__init__` 处理方式一致。],
  [`requests.request`], [requests 库底层 `request()` 函数。截获 URL、method、headers，识别外部 API 调用。],
  [`requests.Session.request`], [Session 对象上的 `request()` 方法。与 `requests.request` 同样的截获逻辑，覆盖有状态会话场景。],
  [`urllib3.HTTPConnectionPool.urlopen`], [urllib3 连接池 `urlopen()` 方法。作为 requests 底层库的兜底 Hook。],
)

== node_lowlevel.js

Node.js 运行时的 Frida JS 脚本，通过 Hook libuv 的 C 层函数实现跨 Node.js 版本的稳定性。

=== Hook 点

#table(
  columns: (auto, 1fr),
  [*Hook 点*], [*说明*],
  [`uv_spawn`], [libuv 进程创建函数。截获子进程命令和参数，跨 Node.js 版本接口稳定。],
  [`uv_tcp_connect`], [TCP 连接发起函数。截获目标 IP 和端口，检测外部连接。],
  [`uv_udp_send`], [UDP 数据包发送函数。截获目标地址和数据包大小。],
)

=== 跨版本稳定性

libuv 是 Node.js 的底层 I/O 库，其 C API 在 Node.js 12.x~22.x 之间保持稳定。相比 Hook JS 层函数（可能随 Node.js 版本重构），Hook libuv C 函数提供更稳定的 Hook 点。脚本通过 Frida 的 `Module.findExportByName()` 定位 `libuv.so` 中的导出函数，不依赖 Node.js 内部 JS 对象布局。

== openclaw_plugin.ts

OpenClaw 框架插件，在 Agent 内部通过 HTTP 直接向 审计引擎推送信息，不依赖 Frida 进程外插桩。

=== 架构

```text
OpenClaw Agent
  |
  |-- before_agent_run(system_prompt, session_id)
  |     → HTTP POST /api/v1/frida/system-prompt
  |        审计引擎更新 TemplateMatcher 上下文
  |
  |-- before_tool_call(tool_name, input, session_id)
  |     → HTTP POST /api/v1/frida/context
  |        审计引擎更新 TaintTracker 和 GraphConstraint
  |
  |-- 正常执行工具（不被阻塞）
        通信失败不影响 Agent 运行（fail-open）
```

=== Hook 点

- `before_tool_call`: 工具执行前调用，发送工具名和输入参数到审计引擎
- `before_agent_run`: Agent 决策循环启动前调用，发送 System Prompt 到审计引擎

=== 通信方式

插件通过 HTTP POST 向 审计引擎发送数据，超时 100ms。通信失败时静默降级（catch 异常），不阻塞 Agent 执行。

== bridge.py 运行时选择

`FridaBridge` 支持 Python 和 Node.js 两种运行时：

=== 运行时常量

```python
RUNTIME_PYTHON = "python"  # 加载 langchain_hooks.js + lowlevel_hooks.js
RUNTIME_NODE   = "node"    # 加载 node_lowlevel.js
```

=== `_load_scripts()`

根据 `self.runtime` 选择加载对应的 JS 脚本文件：

- `RUNTIME_PYTHON`: 加载 `langchain_hooks.js`（Agent 层 Hook）和 `lowlevel_hooks.js`（Python 底层 Hook）
- `RUNTIME_NODE`: 加载 `node_lowlevel.js`（libuv C 层 Hook）

选择机制通过 Frida bridge 启动参数指定，适应不同 Agent 框架需求。

== 验收标准

1. `bridge.py` 启动后打印 `host_pid=<数字>`
2. 审计引擎运行时可正常调 `/api/v1/causal-id/sign` 并收到响应
3. 审计引擎不可用时 100ms 超时降级，不抛异常，返回 UNVERIFIED
4. causal-guardian 运行时可注册 CausalID 并收到 ACK
5. Frida 脚本可 attach 到 Python Agent 进程并截获工具调用
