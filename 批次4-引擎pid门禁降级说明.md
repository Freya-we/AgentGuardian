# 批次 4：引擎侧 pid 门禁降级为可选

> 执行日期：2026-10-26
> 基线：`AgentGuardian-fixed-20261027.zip`（批次 2+3）
> 结论：把引擎侧的 `/proc` 存活校验从"默认强制"降级为"显式可选"，并修掉它打挂的 6 个测试。

---

## 一、问题：批次 3 在 Linux 上有 6 个真实回归

批次 3 的说明写的是 `uv run pytest tests -q --ignore=tests/integration` → **182 passed**，
但那是在 Windows 上跑的。在 Linux（WSL Ubuntu-24.04）上实测：

```
178 passed, 6 failed, 4 skipped
```

失败清单：

| 用例 | 报错 |
|---|---|
| `test_sign_request_broadcasts_tool_call` | `assert 'block' == 'ask'` |
| `test_db_query_ddl_blocked` | `assert 'DDL' in 'pid 101 不存在，拒绝签发'` |
| `test_db_query_select_allowed` | 同上 |
| `test_db_query_dcl_blocked` | 同上 |
| `test_db_query_comment_bypass_blocked` | 同上 |
| `test_session_sweep_cleans_all_containers` | `last_call_ns == {}`（被门禁提前返回，连带） |

**根因**：批次 3 新增的 `_pid_exists()` 在 Linux 上生效，而测试里用的是合成 pid
（123/321/101/102/103/104/201）→ `/proc/<pid>` 不存在 → 一律 block。
Windows 上 `/proc` 目录都不存在 → 校验被跳过 → 所以那边一直绿。

**验证方式**：把出问题的 6 个用例里的 pid 换成 `os.getpid()`，6 个全部通过。

---

## 二、为什么是"降级"而不是"修好"

批次 3 的注释写的是：

> 引擎与 Agent 跨 PID 命名空间部署时 /proc 看不到对方，同样按跳过处理

但**代码识别不了这种情况**——它只判断 `/proc` 目录是否存在。于是：

| 部署形态 | `/proc/<pid>` 的实际结果 | 后果 |
|---|---|---|
| 同命名空间 | 正确指向目标进程 | 可用 |
| 跨命名空间，pid 不存在 | 不存在 | **误杀**合法请求 |
| 跨命名空间，pid 恰好撞上别的进程 | 存在但是别人 | **误放**（更糟：给人虚假安全感） |

也就是说，这道门在容器化部署（Docker / k8s / WSL）里既不可靠、又做不到它声称的"跳过"。

而**真正的 pid 权威本来就在 causal-guardian**：它对照 root 维护的 `monitored_tgid`
（key 是目标命名空间内的 tgid，即批次 1 的 P0-6 修复），不在名单内一律拒绝写票据
（`status=3`）。这道门是强制且可信的，引擎侧再做一次 `/proc` 检查既重复又不可靠。

---

## 三、改动

### `src/engine/server.py`

| 点 | 处理 |
|---|---|
| `pid <= 0` | **保留**。与命名空间无关，永远成立（非法 pid 直接拒） |
| `_pid_exists()` | 保留函数，但新增 `_pid_gate_enabled()` 开关，**默认关闭** |
| 调用点 | `if _pid_gate_enabled() and not _pid_exists(req.pid):` |
| 开关 | 环境变量 `AGENT_GUARDIAN_PID_GATE=1`（`true`/`yes` 亦可） |

`_pid_exists()` 与 `_pid_gate_enabled()` 的 docstring 都改成了**如实描述**：
默认不做校验、以及跨命名空间时两种失效方式，不再写"会自动跳过"。

### `tests/test_server_events.py`

| 改动 | 说明 |
|---|---|
| 6 个"借 pid 走流程"的用例 | `pid=<合成值>` → `pid=os.getpid()` |
| `test_sign_rejects_nonexistent_pid` | 显式 `monkeypatch.setenv("AGENT_GUARDIAN_PID_GATE", "1")`，继续验证开关打开时的行为 |
| 新增 `test_pid_gate_disabled_by_default` | 即使 `_pid_exists` 返回 False，默认也不得因此拦截 |

---

## 四、验证

### Linux（WSL Ubuntu-24.04，Python 3.12.3）

```
185 passed, 4 skipped, 0 failed
```

（改前 178 passed / 6 failed；净增 1 条新用例）

### Windows 开发机

```
tests/test_server_events.py: 18 passed
```

（另有 2 个 error 是本机沙箱不允许创建 `pytest` 的 tmp_path 目录，与代码无关）

### C 侧

本批次未改动任何 C/C++ 代码（只动 `server.py` 与测试）。
批次 2+3 的 C 侧此前已实测：BPF 探针与 `causal-guardian` 均编译通过，
协议结构体尺寸 `msg_register=177` / `msg_ns_update=17` / `msg_key_update=65` 与
Python 侧 `struct.pack` 完全一致，且 HMAC payload 跨语言逐字节一致。

---

## 五、部署提示

- **默认行为**：引擎不再因 `/proc/<pid>` 不存在而拒签，pid 门禁由 causal-guardian 全权负责；
- **需要引擎侧兜底时**（例如单机同命名空间演示）：`export AGENT_GUARDIAN_PID_GATE=1`；
- 打开后请确认引擎与 Agent 在同一 PID 命名空间，否则会出现上面那两种失效方式。

---

## 六、附加修复：限流桶的跨文件污染（10 个"全量跑才挂"的用例）

### 现象

批次 4 改完 pid 门禁后，`pytest tests --ignore=tests/integration` 全绿；
但**不排除 integration** 跑全量时，`test_server_events.py` 又挂 10 个，报错统一是：

```
decision == "block"，reason == "请求频率超限，请稍后重试"
```

单跑其中任何一个用例却通过 —— 典型的跨文件状态污染。

### 根因

- `server._rate_buckets` 是模块级单例，限流键是**调用方身份**；开发模式无令牌时身份
  统一为 `"dev"`，配额 60 令牌/分钟；
- `tests/integration/test_e2e_chain.py` **没有平台 skip**（TestClient + Flask 跨平台），
  它会按三种攻击场景真打几十个 `sign` 请求；
- pytest 按目录字母序先跑 `integration/`，`"dev"` 桶被烧光，后面的
  `test_server_events.py` 里所有走 sign 路径的用例全部被挡成 `block`。

> 自省：这个耦合是批次 1 把限流键从 `session_id` 改成"调用方身份"时引入的
> —— 改之前每个 session 一个桶，测试之间天然隔离；改之后所有测试共用一个桶。

### 修法

新增 `tests/conftest.py`，用 autouse 夹具在每个用例前后清空限流桶：

```python
@pytest.fixture(autouse=True)
def _isolate_rate_limit_buckets():
    server._rate_buckets.clear()
    yield
    server._rate_buckets.clear()
```

这是测试隔离问题，不是限流逻辑的问题 —— 生产环境"一个令牌一个桶"是预期行为。

### 验证

| 场景 | 改前 | 改后 |
|---|---|---|
| Windows 全量（含 integration） | 10 failed / 162 passed | **0 failed / 172 passed** |
| Linux 全量（仅跳过需 root 的 `test_ebpf_chain`） | — | **194 passed / 7 skipped / 0 failed** |
| Linux CI 口径（`--ignore=tests/integration`） | 185 passed | **185 passed / 4 skipped** |
| `test_e2e_chain.py` 单跑 | — | 8 passed（确认它真的在打 sign 请求） |

### 生产侧提醒

限流按"令牌"计数意味着**同一个令牌下的所有 Agent 共享 60 次/分钟**。
多 Agent 部署时用 `AGENT_GUARDIAN_RATE_LIMIT` 调高，或按 Agent 拆发令牌。

