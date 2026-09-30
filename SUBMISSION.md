# AgentGuardian 参赛压缩包交付说明

本文档用于长城杯产品赛提交前自检，目标是保证评委或队友解压后可以按同一条路径完成安装、演示和验证。

## 推荐压缩包内容

保留：

- `README.md`
- `SUBMISSION.md`
- `Makefile`
- `pyproject.toml`
- `uv.lock`
- `Dockerfile`
- `docker-compose.yml`
- `config/`
- `docs/`
- `scripts/`
- `src/`
- `tests/`

排除：

- `.git/`
- `.venv/`
- `.pytest_cache/`
- `.idea/`
- `.agents/`
- `.codex/`
- `src/dashboard/node_modules/`
- `src/dashboard/dist/`
- `src/dashboard/test-results/`
- `src/dashboard/playwright-report/`
- `tests/__pycache__/`
- `src/**/__pycache__/`
- 旧的或重复的压缩包文件，例如历史 `.tar.gz` 或 `.zip` 文件

## 解压后环境要求

- Linux 5.8+
- Python 3.11+
- `uv`
- Node.js 20+
- `pnpm`
- 可选：Docker、libbpf/eBPF 构建工具、Frida

eBPF 探针和 causal-guardian 需要 root 权限；普通审计引擎、Dashboard 和 HTTP/WebSocket 演示不需要 root。

## 标准验证路径

在项目根目录执行：

```bash
uv sync
cd src/dashboard && pnpm install && cd ../..
```

验证后端单元测试：

```bash
uv run pytest tests/ -q --ignore=tests/integration
```

验证三类攻击场景集成测试：

```bash
uv run pytest tests/integration/test_e2e_chain.py -q
```

验证一键演示链路：

```bash
./scripts/demo_e2e.sh
```

生成 Dashboard 高危阻断告警：

```bash
./scripts/demo_alert.sh
```

验证 Dashboard 构建：

```bash
cd src/dashboard && pnpm build
```

验证技术手册构建：

```bash
bash docs/manual/build-typst.sh
```

## 演示启动路径

终端 1：

```bash
make dev
```

终端 2：

```bash
cd src/dashboard
pnpm dev
```

浏览器访问：

```text
http://127.0.0.1:5173
```

另开终端触发演示事件：

```bash
./scripts/demo_e2e.sh --session-id demo-final
```

生成可视化高危阻断告警：

```bash
./scripts/demo_alert.sh judge-demo
```

执行后刷新 `http://127.0.0.1:5173`，Dashboard 会通过历史事件接口回放最近阻断告警。

## 当前已验证结果

最近一次本地验证结果：

- `uv run pytest tests/ -q --ignore=tests/integration`: 154 passed
- `uv run pytest tests/integration/test_e2e_chain.py -q`: 8 passed
- `./scripts/demo_e2e.sh`: 9 passed, 0 failed
- `./scripts/demo_alert.sh`: generated blocking alert
- `cd src/dashboard && pnpm build`: passed
- `bash docs/manual/build-typst.sh`: generated `docs/technical-manual.pdf`, 34 pages

## 打包命令示例

在项目父目录执行：

```bash
zip -r AgentGuardian-submission.zip AgentGuardian \
  -x 'AgentGuardian/.git/*' \
  -x 'AgentGuardian/.venv/*' \
  -x 'AgentGuardian/.pytest_cache/*' \
  -x 'AgentGuardian/.idea/*' \
  -x 'AgentGuardian/.agents/*' \
  -x 'AgentGuardian/.codex/*' \
  -x 'AgentGuardian/src/dashboard/node_modules/*' \
  -x 'AgentGuardian/src/dashboard/dist/*' \
  -x 'AgentGuardian/src/dashboard/test-results/*' \
  -x 'AgentGuardian/src/dashboard/playwright-report/*' \
  -x 'AgentGuardian/**/__pycache__/*' \
  -x 'AgentGuardian/*.tar.gz' \
  -x 'AgentGuardian/*.zip'
```
