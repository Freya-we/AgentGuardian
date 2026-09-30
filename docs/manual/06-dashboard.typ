= Dashboard 前端

AgentGuardian Dashboard 是一个 React + TypeScript 单页应用，通过 WebSocket 接收审计引擎推送的实时事件，使用 D3.js 进行可视化展示。

== 技术栈

#table(
  columns: (auto, 1fr),
  [*技术*], [*用途*],
  [React 18+], [UI 框架，函数组件 + Hooks。],
  [TypeScript], [类型安全，接口定义。],
  [D3.js], [统计图表：折线图（P95 间隔）、柱状图（工具分布）、饼图（决策分布）。],
  [WebSocket], [实时事件流，审计引擎推送 tool_call / taint_update / ebpf_intercept 事件。],
  [Vite], [构建工具和开发服务器，代理 `/api` 到 FastAPI 后端。],
  [pnpm], [包管理器。],
)

== 组件树

```text
App.tsx
├─ StatusBar.tsx         系统状态指示器（审计引擎、SLM、eBPF 状态）
├─ MetricCard.tsx        关键指标卡片
├─ MiniCharts.tsx        小型趋势图和分布图
├─ CallChainTree.tsx     因果链树形展示
├─ TaintTracker.tsx      污点标签和传播状态
├─ EventStream.tsx       WebSocket 事件流
├─ AlertBanner.tsx       告警通知横幅
└─ ConfigPanel.tsx       task_templates.json 在线编辑
```

== 当前视图

=== 实时监控

默认首页展示 Agent 的当前调用路径、每个节点的决策状态（ALLOW/ASK/BLOCK）、活跃污点标签、实时事件流和高优先级告警。前端通过 Vite 代理访问审计引擎 API。

=== 指标分析

`MiniCharts` 和 `MetricCard` 展示 P95 调用间隔、熵值、污点比率、未知图边计数、工具调用分布和决策分布。当前实现以单页面板形式呈现，未拆独立路由。

=== 配置管理

`ConfigPanel` 管理 `config/task_templates.json`，支持读取、编辑和通过 `PUT /api/v1/config/task-templates` 保存。保存成功后审计引擎热重载配置并广播 `config_reloaded` 事件。

== WebSocket 事件

`useWebSocket.ts` Hook 管理 WebSocket 连接，自动重连，解析核心事件类型：

#table(
  columns: (auto, 1fr),
  [*事件类型*], [*payload*],
  [`tool_call`], [`{session_id, tool_name, decision, causal_id, taint_tags, reason, timestamp}`],
  [`taint_update`], [`{session_id, source_type, active_tags, timestamp}`],
  [`ebpf_intercept`], [`{pid, syscall, causal_id_valid, action, reason, timestamp}`],
  [`stats_update`], [`{session_id, snapshot}`],
  [`config_reloaded`], [`{templates_loaded, changes}`],
)

== 与后端的交互

前端不直接调用 `/api/v1/causal-id/sign`（该端点由 Frida bridge 调用）。Dashboard 仅消费：
- `GET /api/v1/sessions/{id}/stats` — 获取统计快照
- `GET /api/v1/sessions/{id}/graph` — 获取调用路径
- `GET /api/v1/config/task-templates` — 读取模板配置
- `PUT /api/v1/config/task-templates` — 保存模板配置并热重载
- `GET /health` — 系统健康状态
- `WS /ws/events` — 实时事件流

== 开发模式

```bash
cd src/dashboard
pnpm install
pnpm dev
```

Vite 开发服务器监听 `127.0.0.1:5173`，`/api` 代理到 `127.0.0.1:8000`。
