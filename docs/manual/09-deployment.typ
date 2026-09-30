= 部署与运维

== 开发环境

```bash
# 1. 克隆仓库
cd AgentGuardian

# 2. 安装依赖
uv sync

# 3. 启动 审计引擎（开发模式）
make dev
# 等价于: uv run uvicorn src.engine.server:app --reload --host 0.0.0.0 --port 8000

# 4. 运行测试
make test
# 等价于: uv run pytest tests/ -v --cov=src/engine --cov-report=term-missing

# 5. 编译技术手册
make docs
```

== 生产部署

=== 审计引擎

```bash
# 生成主密钥（仅首次部署）
mkdir -p /etc/agent-guardian
openssl rand -hex 32 > /etc/agent-guardian/master.key
chmod 600 /etc/agent-guardian/master.key

# 启动引擎
uv run uvicorn src.engine.server:app --host 0.0.0.0 --port 8000 --workers 4
```

注意：生产模式必须存在 `/etc/agent-guardian/master.key`（最少 32 字节）。开发模式自动生成临时密钥，不能用于生产。

=== eBPF 内核监控 + causal-guardian（已实现）

```bash
# 编译 eBPF 探针（7 探针，单文件 execve_monitor.bpf.c）
cd src/ebpf
make

# 编译 causal-guardian
cd src/causal_guardian
make

# 启动 causal-guardian（需要 CAP_BPF + root）
sudo ./causal-guardian \
  --socket /var/run/causal-guardian.sock \
  --bpf-obj ../ebpf/execve_monitor.bpf.o
```

=== Dashboard（已实现）

```bash
cd src/dashboard
pnpm install
pnpm build    # 产出 dist/ 静态文件
```

静态文件可由 `src/dashboard/nginx.conf` 对应的 nginx 镜像提供，也可通过外部 nginx 反向代理到审计引擎 API。

== 目录权限

#table(
  columns: (auto, auto, 1fr),
  [*路径*], [*权限*], [*说明*],
  [`/etc/agent-guardian/master.key`], [0600], [主密钥，仅 root 可读写。],
  [`/var/run/causal-guardian.sock`], [0600], [Unix Socket，仅 root 可访问。],
  [`config/task_templates.json`], [0644], [任务模板配置，可通过 API 热重载。],
)

== 健康检查

```bash
curl http://localhost:8000/health
# {"status": "ok", "slm_available": false, "review_backend": "rule_engine", "rule_engine_available": true}
```

`slm_available` 指示 SLM 审查是否可用。当 ONNX 模型文件（`~/.cache/agent-guardian/model.onnx`）不存在时返回 `false`，审计引擎降级为中性分数处理。

== 监控

- 审计引擎日志：FastAPI 应用日志输出到 stdout/stderr
- WebSocket 事件：通过 Dashboard 实时查看
- eBPF 告警：通过 perf buffer → causal-guardian → WebSocket → Dashboard
- 统计指标：通过 `GET /api/v1/sessions/{id}/stats` 查询

== 故障处理

#table(
  columns: (auto, 1fr),
  [*故障*], [*处理*],
  [主密钥文件缺失], [开发模式自动生成临时密钥并打印警告。生产模式 startup 失败，应用退出。],
  [Frida 100ms 超时], [降级为 UNVERIFIED，Agent 继续运行，eBPF 走白名单兜底 (flags & 0x01)。],
  [causal-guardian 不可用], [Frida bridge 降级，所有 CausalID 标记为 UNVERIFIED。Agent 继续运行。],
  [BPF Map 满 (4096 条)], [LRU 自动淘汰最久未使用的条目。MSG_REGISTER 返回状态码 1。],
  [Config 热重载失败], [保持当前模板不变，返回错误信息。不中断运行中的 Agent。],
)
