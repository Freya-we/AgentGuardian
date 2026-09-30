= 附录

== 当前实现事实

以下数据来自当前 checkout 的本地核对：

#table(
  columns: (auto, auto),
  [*项目*], [*值*],
  [包版本], [`pyproject.toml` 中 `version = "0.1.0"`],
  [Python 要求], [`>=3.11`],
  [引擎模块], [9 个 Python 模块 + 1 个 FastAPI 入口（`src/engine/`）],
  [测试入口], [`tests/` 下包含单元测试、集成测试和演示链路测试；具体数量以当前 pytest 收集结果为准。],
  [已实现], [hmac_signer、key_manager、template_matcher、graph_constraint、taint_tracker、sql_parser、stats_baseline、slm_reviewer（ONNX 嵌入模型）、websocket_manager、server.py、eBPF 探针（7 probes）、causal-guardian（Unix Socket 守护进程 + HMAC 验签 + perf buffer 转发）、Frida Hook（14 hooks, 5 files）、安全风险分析报告],
  [已实现], [攻击脚本 3 个场景（`src/attacks/`）自检验证通过],
  [已实现], [Dashboard 前端（`src/dashboard/`，10 组件，WebSocket 实时事件）],
  [typst 版本], [0.15.0]，[`typst compile docs/technical-manual.typ` 可生成 PDF],
)

== 常见路径速查

#table(
  columns: (auto, 1fr),
  [*主题*], [*路径*],
  [FastAPI 入口], [`src/engine/server.py`],
  [HMAC 签名], [`src/engine/hmac_signer.py`],
  [密钥管理], [`src/engine/key_manager.py`],
  [模板匹配], [`src/engine/template_matcher.py`],
  [图约束], [`src/engine/graph_constraint.py`],
  [污点追踪], [`src/engine/taint_tracker.py`],
  [SQL 分析], [`src/engine/sql_parser.py`],
  [统计基线], [`src/engine/stats_baseline.py`],
  [SLM 审查], [`src/engine/slm_reviewer.py`（ONNX 嵌入模型）],
  [WebSocket], [`src/engine/websocket_manager.py`],
  [任务模板], [`config/task_templates.json`],
  [Frida bridge], [`src/frida/bridge.py`（已实现）],
  [Frida LangChain Hook], [`src/frida/langchain_hooks.js`（已实现）],
  [Frida 底层 Hook], [`src/frida/lowlevel_hooks.js`（已实现）],
  [Frida Node.js libuv Hook], [`src/frida/node_lowlevel.js`（已实现）],
  [OpenClaw Plugin], [`src/frida/openclaw_plugin.ts`（已实现）],
  [eBPF 探针], [`src/ebpf/execve_monitor.bpf.c`、`causal_chain.h`、`loader.c`（已实现）],
  [causal-guardian], [`src/causal_guardian/main.c`（已实现）],
  [SLM 审查测试], [`tests/test_slm_reviewer.py`（12 个测试，ONNX 嵌入模型语义审查）],
  [攻击脚本], [`src/attacks/malicious_api.py`、`stego_injector.py`、`sql_injector.py`],
  [测试], [`tests/` 下包含引擎、Frida、eBPF、Dashboard 事件和攻击场景相关测试。],
  [设计文档], [`docs/superpowers/specs/2026-06-29-agent-guardian-design.md`],
  [框架规范], [`docs/superpowers/specs/2026-06-29-framework-spec.md`],
)

== 关键设计决策速查

以下决策来自设计规范 v1.3，经过 3 轮专家评审：

#table(
  columns: (auto, 1fr),
  [*决策*], [*说明*],
  [Comm 方案废弃], [Frida 直接写 BPF Map（需 CAP_BPF）废弃，采用宿主机 causal-guardian 守护进程方案。],
  [ML 降级为统计基线], [RF+IF 集成方案废弃，统计基线仅用于 Dashboard 可视化，不参与决策。],
  [System Prompt 用 MinHash], [SHA256 精确匹配废弃（Append-Only 指令反复追加导致哈希不稳定），改用 MinHash 近似匹配。],
  [100ms 硬超时 + UNVERIFIED], [Frida onEnter 不能阻塞 Agent，100ms 超时降级为 UNVERIFIED，不阻断正常运行。],
  [CausalID 两阶段删除], [sys_enter_execve 验证，sys_exit_execve 成功时删除（处理 execve 失败场景）。],
  [NSpid 获取宿主机 PID], [不使用 SO_PEERCRED，通过 `/proc/self/status` NSpid 字段获取宿主机视角 PID。],
  [sqlparse 词法分析], [正则无法可靠处理 SQL 注释混淆，改用 sqlparse 库进行词法分析。],
  [SQL MySQL 条件注释], [提取 `/*!50000 DROP TABLE*/` 内容追加到分析文本中，防止绕过。],
)

== 测试覆盖入口

#table(
  columns: (auto, 1fr),
  [*测试文件*], [*覆盖模块*],
  [`test_hmac_signer.py`], [HMAC 签名/验签/降级标记。],
  [`test_key_manager.py`], [密钥派生/初始化/轮换/持久化。],
  [`test_template_matcher.py`], [模板加载/精确匹配/MinHash/重载。],
  [`test_graph_constraint.py`], [边检查/污点/禁止类别/黑名单/路径历史/动态边。],
  [`test_taint_tracker.py`], [污点源注册/传播/无源/活跃标签/可信源/会话清理。],
  [`test_sql_parser.py`], [DDL 检测/注释混淆/行注释/DCL/多语句。],
  [`test_frida_bridge.py`], [PID 翻译/审计引擎 HTTP/Unix Socket/消息处理/超时降级/脚本加载/运行时选择。],
  [`test_slm_reviewer.py`], [ONNX 嵌入模型语义审查：缺模型降级/恶意/良性/延迟/确定性。],
  [`test_stats_baseline.py`], [滑动窗口统计/熵值/P95/会话重置。],
  [`test_server_events.py`], [WebSocket 事件形状/签名广播/SQL 集成测试。],
  [`test_websocket_manager.py`], [广播/单播/自动清理死连接。],
  [`test_attacks.py`], [攻击脚本自检验证。],
  [`test_rule_engine.py`], [规则引擎兼容性测试。],
  [`tests/integration/`], [Frida、eBPF 和端到端链路集成测试。],
)

== 文档构建

技术手册源文件在 `docs/manual/`。构建脚本会拼接章节并生成 PDF：

```bash
make docs
# 等价于: bash docs/manual/build-typst.sh
```

脚本输出：
- `docs/technical-manual.typ`（拼接产物，gitignore）
- `docs/technical-manual.pdf`（二进制产物，gitignore）

如果只想快速检查 Typst 语法：

```bash
typst compile docs/technical-manual.typ /tmp/agent-guardian-technical-manual.pdf
```

== 维护规则

- 文档中的路径必须能在当前仓库找到。
- API 端点以 `src/engine/server.py` 为准。
- 设计决策以 `docs/superpowers/specs/2026-06-29-agent-guardian-design.md` v1.3 为准。
- 模块接口以 `docs/superpowers/specs/2026-06-29-framework-spec.md` v1.0 为准。
- 测试数量容易漂移，除非刚刚重新统计，否则不要写成长期事实。
- Dashboard 前端已实现（10 个 React + TypeScript 组件，WebSocket 实时事件）。
- SLM 审查已实现为 ONNX 嵌入模型语义审查（all-MiniLM-L6-v2），不再标注为占位。
- eBPF、causal-guardian、Frida hook、Dashboard 均已实现，手册描述应以当前代码为准。
