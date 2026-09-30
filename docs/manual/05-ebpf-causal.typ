= eBPF 内核监控 + causal-guardian

eBPF 内核监控组件由 eBPF 内核探针和宿主机守护进程 causal-guardian 组成。eBPF 探针在内核态拦截系统调用并验证 CausalID，causal-guardian 是唯一有权写入 BPF Map 的进程。

== 架构

```text
容器内                         宿主机
───────                        ──────
Frida bridge.py ──Unix Socket──> causal-guardian (CAP_BPF)
KeyManager ──────Unix Socket──>  MSG_KEY_UPDATE → session_key
                                      |
                                      | 写入 BPF Map
                                      v
                               ┌──────────────────┐
                               │    BPF Maps      │
                               │  causal_chain     │
                               │  session_key      │
                               │  exec_whitelist   │
                               │  alert_events     │
                               └──────┬───────────┘
                                      |
                                      | 查表验证
                                      v
                               eBPF 探针 (内核态)
                               ┌──────────────────┐
                               │  sys_enter_execve │
                               │  sys_exit_execve  │
                               │  sys_enter_openat │
                               │  sys_enter_connect│
                               │  sys_enter_chmod  │
                               │  sys_enter_fchmod │
                               │  sys_enter_sendto │
                               └──────────────────┘
```

== 权限死锁问题

核心问题：Frida 运行在容器内，没有 CAP_BPF 写入 BPF Map；但如果给容器 CAP_BPF，攻击者就能卸载 eBPF 程序。

解决方案：宿主机上的 causal-guardian 守护进程是唯一有 CAP_BPF 的进程。Frida 通过 Unix Socket 将 CausalID 发送给它，由它写入 BPF Map。容器内进程无特权。

== BPF Maps

=== causal_chain

#table(
  columns: (auto, auto, 1fr),
  [*字段*], [*类型*], [*说明*],
  [`pid_tgid`], [u64], [进程 PID+TID 组合键。],
  [`causal_id`], [[u8; 32]], [审计引擎签发的 32 字节 CausalID。],
  [`timestamp`], [u64], [注册时间戳。5 秒 TTL 自动清理。],
  [`validated`], [u8], [是否已验证（1 = 已验证，0 = 未验证）。],
  [`flags`], [u8], [bit0: UNVERIFIED 标记 (CAUSAL_FLAG_UNVERIFIED = 0x01)。所有 7 个探针在 validated=1 时先检查 flags & 0x01。],
)

最大条目：4096。LRU 淘汰策略。

=== session_key

#table(
  columns: (auto, auto, 1fr),
  [*字段*], [*类型*], [*说明*],
  [`active_key`], [[u8; 32]], [当前签发用密钥（30s 内有效）。],
  [`grace_key`], [[u8; 32]], [上一轮密钥（60s 内仅验签）。],
)

causal-guardian 每 30 秒接收 KeyManager 的轮换结果并更新此 Map。

=== monitored_tgid

#table(
  columns: (auto, auto, 1fr),
  [*字段*], [*类型*], [*说明*],
  [`tgid`], [u64], [线程组 ID（`pid_tgid >> 32`），即宿主视角的进程 PID。],
  [`监控标记`], [u8], [1 = 该进程受 eBPF 监控。],
)

仅注册在此 Map 中的进程会被 eBPF 探针拦截。不在集合中的进程不受影响，避免了全系统性能开销。最大 64 条目，Hash 类型。

=== exec_whitelist

白名单路径（如 `/usr/bin/`、`/usr/lib/`、`/bin/` 等标准系统路径前缀），最多 16 条。当 CausalID 为 `UNVERIFIED_` 时，匹配白名单前缀的路径才放行。

白名单匹配使用展开 if 链实现（`match_whitelist()` 函数），逐个字符比较路径前缀，完全避免循环结构以通过 eBPF verifier 检查：

=== alert_events (perf buffer)

推送告警事件到用户态，格式：
```text
{pid: u32, tgid: u32, syscall: u32, causal_id: [u8; 32], reason: [u8; 64]}
```

== eBPF 探针

所有 7 个探针位于同一个文件 `execve_monitor.bpf.c` 中，共享 `causal_chain.h` 中定义的数据结构。

=== execve_monitor.bpf.c — 7 探针总览

#table(
  columns: (auto, auto, 1fr),
  [*探针*], [*SEC 名称*], [*职责*],
  [`sys_enter_execve`], [`tracepoint/syscalls/sys_enter_execve`], [进程创建入口。验证 CausalID，Unix Socket 写入 BPF Map。],
  [`sys_exit_execve`], [`tracepoint/syscalls/sys_exit_execve`], [进程创建出口。execve 成功（ret==0）时删除 causal_chain 条目，失败时保留。],
  [`sys_enter_openat`], [`tracepoint/syscalls/sys_enter_openat`], [文件打开入口。检查 O_WRONLY/O_RDWR/O_CREAT 写模式，读操作不拦截。],
  [`sys_enter_connect`], [`tracepoint/syscalls/sys_enter_connect`], [网络连接入口。提取目标 IP 和端口，拦截未经授权的出站连接。],
  [`sys_enter_chmod`], [`tracepoint/syscalls/sys_enter_chmod`], [文件权限修改入口。仅拦截添加 +x 执行权限的操作（mode & S_IXUSR/S_IXGRP/S_IXOTH）。],
  [`sys_enter_fchmod`], [`tracepoint/syscalls/sys_enter_fchmod`], [文件描述符权限修改入口。与 chmod 同样的 +x 检测逻辑。],
  [`sys_enter_sendto`], [`tracepoint/syscalls/sys_enter_sendto`], [UDP 数据发送入口。检查 AF_INET/AF_INET6 地址族，目标地址为 NULL 时保守拦截。],
)

=== 通用处理流程

每个探针遵循相同的验证流水线：

```text
1. bpf_get_current_pid_tgid() 获取 pid_tgid
2. tgid = pid_tgid >> 32; 查 monitored_tgid Map:
   不在集合中 → 直接放行（不拦截非 Agent 进程）
3. bpf_map_lookup_elem(&causal_chain, &pid_tgid) 查表
4. 条目不存在 → UNVERIFIED 路径
5. 条目存在且 validated=1:
   a. 检查 flags & CAUSAL_FLAG_UNVERIFIED (0x01)
   b. 若 flags 含 UNVERIFIED → 走 exec_whitelist 兜底
   c. 若 flags 不含 UNVERIFIED → 验证通过，放行
6. 条目存在但 TTL 过期 → 同"条目不存在"处理
7. UNVERIFIED 路径: match_whitelist(filename) 展开 if 链匹配
   匹配 → 放行；不匹配 → bpf_perf_event_output() 推送告警 + SIGKILL
```

=== chmod / fchmod 探针

这两个探针只拦截添加执行权限的操作：

```c
// 仅当添加 +x 时才触发拦截
if (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
    // 检查 CausalID
}
```

移除执行权限（chmod -x）或修改其他权限位不触发拦截，减少误报。

=== sendto 探针

UDP 数据包发送拦截：

- 检查 `family == AF_INET || family == AF_INET6`，忽略 Unix Socket 等其他地址族
- 目标地址 `dest_addr == NULL` 时保守拦截（可能是错误调用或恶意行为）
- 通过 CausalID 验证的 `sendto` 调用放行，未验证的拦截

=== UNVERIFIED 白名单兜底

所有 7 个探针共享 `exec_whitelist` BPF Map（HASH，16 条）和展开 if 链 `match_whitelist()`。当 `flags & 0x01` 时，探针调用 `match_whitelist(filename)` 逐字符比较路径前缀（`/usr/bin/`、`/usr/lib/`、`/bin/`、`/sbin/` 等标准系统路径），完全避免循环结构以通过 eBPF verifier。

=== causal_chain.h

共享头文件，定义 BPF Map 结构体（`causal_entry`、`session_keys`、`alert_event`）和 Unix Socket 消息协议。供所有 7 个探针和 causal-guardian 使用。

=== loader.c

用户态加载器，使用 libbpf skeleton 加载。职责：
1. 打开 BPF 对象文件（`execve_monitor.bpf.o`）
2. 创建和固定 BPF Maps
3. 加载和附加 7 个探针程序
4. 设置 perf buffer 读取回调（`alert_events` → 告警处理）
5. 信号处理（SIGINT/SIGTERM → 分离探针 + 删除固定 Map）

== causal-guardian 守护进程

`src/causal_guardian/main.c`（已实现）：

=== 核心职责

1. Unix Socket 服务端：监听 `/var/run/causal-guardian.sock`
2. 处理 MSG_REGISTER（0x01）：
   a. 从 `session_key` BPF Map 读取 active/grace 密钥
   b. 重建 HMAC payload `{pid}|{tool_name}|{timestamp_ns}|{ttl_ns}`
   c. 使用 `HMAC(EVP_sha256())` + `CRYPTO_memcmp()` 常量时间验签
   d. 先使用 active key 验证，失败后尝试 grace key
   e. 验签通过 → 写入 `causal_chain` Map；失败 → 返回 status=2（hmac_fail）
3. 处理 MSG_KEY_UPDATE（0x02）：更新 `session_key` Map
4. 打开 `alert_events` perf buffer，注册回调 `handle_alert_event()`
   → eBPF 告警事件 → 格式化为 JSON → 通过原始 TCP POST 到 `localhost:8000/api/v1/ebpf/intercept`（审计引擎接收并 WebSocket 广播）
5. 定期清理：每 5 秒扫描过期 `causal_chain` 条目
6. 信号处理：SIGINT/SIGTERM 时清理并退出

=== MSG_KEY_UPDATE 流程

```text
审计引擎 KeyManager.rotate() (30s 间隔)
  |
  |-- 派生新 session_key (active + grace)
  |-- 通过 Unix Socket 发送 MSG_KEY_UPDATE
  |     {u8 type=0x02, u8[32] active_key, u8[32] grace_key}
  |
  |-- causal-guardian 接收并写入 BPF Map session_key[0]
  |     eBPF 探针在下一次系统调用时使用新 key 验签
  |
  |-- 失败处理
        Socket 写入失败 → 打印警告，下次 rotate() 重试
        BPF Map 更新失败 → 断开连接并重试
```

=== Socket 协议

```text
所有消息小端序，1 字节对齐。最大消息大小 128 字节。

MSG_REGISTER (0x01):
  请求: {u8 type; u64 pid; u8[32] causal_id; u64 timestamp_ns; u8[64] tool_name}
  响应: {u8 type; u8 status}  // 0=成功, 1=Map已满, 2=HMAC验签失败

  causal-guardian 使用 tool_name 重建 HMAC payload 并与 causal_id 验签。
  只有验签通过后才写入 BPF Map，防止伪造 CausalID。

MSG_KEY_UPDATE (0x02):
  请求: {u8 type; u8[32] active_key; u8[32] grace_key}
  响应: {u8 type; u8 status}  // 0=成功
```

=== PID 命名空间

容器内 Frida 通过 `/proc/self/status` 的 `NSpid` 字段获取宿主机 PID，causal-guardian 使用宿主机 PID 作为 `causal_chain` Map 的键。不使用 `SO_PEERCRED`（Unix Socket 对端凭证），因为 `/proc` 信息更可靠，且不依赖 socket 实现细节。

=== CausalID 删除时机

两阶段设计：
1. `sys_enter_execve`：验证 CausalID 是否存在且有效
2. `sys_exit_execve`：execve 成功（返回值 == 0）时才删除 CausalID

这样处理 execve 失败（如文件不存在、权限不足）的场景：CausalID 保留在 Map 中，Agent 重试时无需重新签名。

== 安全边界

- causal-guardian 是唯一有 CAP_BPF 的进程
- Unix Socket 权限：`0600`，仅 root 和同组可访问
- Socket 不接受远程连接（AF_UNIX 仅本地）
- BPF Map 只能被 causal-guardian 写入，eBPF 探针只读
- exec_whitelist 作为 UNVERIFIED 的兜底白名单
- 7 个探针覆盖主要攻击面：进程创建、文件写入、网络连接、权限提升、UDP 外传
- chmod/fchmod 仅拦截 +x 操作，不拦截权限缩减操作（减少误报）
