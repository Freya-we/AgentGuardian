// src/ebpf/execve_monitor.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "causal_chain.h"

#ifndef __NR_execve
#define __NR_execve 59  // x86_64
#endif

char LICENSE[] SEC("license") = "GPL";

/* ── BPF Maps ── */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CAUSAL_CHAIN_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct causal_entry);
} causal_chain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u8[SESSION_KEY_SIZE]);
} session_key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, EXEC_WHITELIST_MAX);
    __type(key, __u8[EXEC_WHITELIST_PATH_LEN]);
    __type(value, __u8[32]);
} exec_whitelist SEC(".maps");

/* 受监控的进程 TGID 集合 — 只有在此集合中的进程才受 eBPF 拦截 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);   // tgid (pid_tgid >> 32)
    __type(value, __u8);  // 1 = 监控中
} monitored_tgid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} alert_events SEC(".maps");

/* ── 白名单 BPF Map 精确查表 ── */
static __always_inline int match_whitelist(const char *filename) {
    __u8 key[EXEC_WHITELIST_PATH_LEN] = {0};
    long len = bpf_probe_read_user_str(key, sizeof(key), filename);
    if (len <= 0)
        return 0;

    if (bpf_map_lookup_elem(&exec_whitelist, key))
        return 1;
    return 0;
}

/* ── sys_enter_execve ── */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    /* TGID 过滤: 仅拦截受监控的 Agent 进程 */
    __u64 tgid = pid_tgid >> 32;
    __u8 *mon = bpf_map_lookup_elem(&monitored_tgid, &tgid);
    if (!mon)
        return 0;

    struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
            bpf_map_delete_elem(&causal_chain, &pid_tgid);
            goto check_whitelist;
        }
        if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
            goto check_whitelist;
        if (!entry->validated)
            goto check_whitelist;
        return 0;
    }

check_whitelist:
    {
        const char *filename = (const char *)ctx->args[0];
        if (match_whitelist(filename))
            return 0;

        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_execve;
        evt.reason = ALERT_NO_CAUSAL_ID;
        bpf_probe_read_user_str(evt.path_or_ip, sizeof(evt.path_or_ip), filename);

        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        bpf_send_signal(9);  // SIGKILL
        return 0;
    }
}

/* ── sys_exit_execve ── */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (ctx->ret == 0) {
        bpf_map_delete_elem(&causal_chain, &pid_tgid);
    }
    return 0;
}

/* ── open flags ── */
#ifndef O_WRONLY
#define O_WRONLY   01
#endif
#ifndef O_RDWR
#define O_RDWR     02
#endif
#ifndef O_CREAT
#define O_CREAT    0100
#endif
#ifndef O_APPEND
#define O_APPEND   02000
#endif
#ifndef O_TRUNC
#define O_TRUNC    01000
#endif

/* ── AF 常量 ── */
#ifndef AF_UNIX
#define AF_UNIX   1
#endif
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

#ifndef __NR_openat
#define __NR_openat  257
#endif
#ifndef __NR_connect
#define __NR_connect  42
#endif

/* ── sys_enter_openat ── */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    /* args: dfd, filename, flags, mode */
    int flags = (int)ctx->args[2];

    int write_flags = O_WRONLY | O_RDWR | O_CREAT | O_APPEND | O_TRUNC;
    if ((flags & write_flags) == 0)
        return 0;  // 纯读操作放行

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 tgid = pid_tgid >> 32;
    __u8 *mon = bpf_map_lookup_elem(&monitored_tgid, &tgid);
    if (!mon)
        return 0;

    struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
            bpf_map_delete_elem(&causal_chain, &pid_tgid);
            goto openat_alert;
        }
        if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
            goto openat_unverified_alert;
        if (!entry->validated)
            goto openat_alert;
        return 0;
    }

openat_alert:
    {
        const char *filename = (const char *)ctx->args[1];
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_openat;
        evt.reason = ALERT_NO_CAUSAL_ID;
        bpf_probe_read_user_str(evt.path_or_ip, sizeof(evt.path_or_ip), filename);

        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        bpf_send_signal(9);  // SIGKILL
        return 0;
    }

openat_unverified_alert:
    {
        const char *filename = (const char *)ctx->args[1];
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_openat;
        evt.reason = ALERT_UNVERIFIED_BLOCK;
        bpf_probe_read_user_str(evt.path_or_ip, sizeof(evt.path_or_ip), filename);
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }
}

/* ── sys_enter_connect ── */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    unsigned short sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family == AF_UNIX)
        return 0;  // 本地 Socket 放行

    if (sa_family != AF_INET && sa_family != AF_INET6)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 __tgid = pid_tgid >> 32;
    __u8 *_m = bpf_map_lookup_elem(&monitored_tgid, &__tgid);
    if (!_m)
        return 0;

    struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
            bpf_map_delete_elem(&causal_chain, &pid_tgid);
            goto connect_alert;
        }
        if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
            goto connect_unverified_alert;
        if (!entry->validated)
            goto connect_alert;
        return 0;
    }

connect_alert:
    {
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_connect;
        evt.reason = ALERT_NO_CAUSAL_ID;

        if (sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            __be32 ip;
            __be16 port;
            bpf_probe_read_user(&ip, sizeof(ip), &sin->sin_addr.s_addr);
            bpf_probe_read_user(&port, sizeof(port), &sin->sin_port);
            __u8 *b = (__u8 *)&ip;
            __u16 p = __builtin_bswap16(port);

            int pos = 0;
            for (int i = 0; i < 4; i++) {
                __u8 v = b[i];
                if (v >= 100) { evt.path_or_ip[pos++] = '0' + v / 100; v %= 100; }
                if (v >= 10)  { evt.path_or_ip[pos++] = '0' + v / 10;  v %= 10; }
                evt.path_or_ip[pos++] = '0' + v;
                evt.path_or_ip[pos++] = (i < 3) ? '.' : ':';
            }
            evt.path_or_ip[pos++] = '0' + (p / 10000); p %= 10000;
            evt.path_or_ip[pos++] = '0' + (p / 1000);  p %= 1000;
            evt.path_or_ip[pos++] = '0' + (p / 100);   p %= 100;
            evt.path_or_ip[pos++] = '0' + (p / 10);
            evt.path_or_ip[pos++] = '0' + (p % 10);
        } else {
            /* AF_INET6 */
            bpf_probe_read_user(evt.path_or_ip, 40, addr);
        }

        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        bpf_send_signal(9);  // SIGKILL
        return 0;
    }

connect_unverified_alert:
    {
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_connect;
        evt.reason = ALERT_UNVERIFIED_BLOCK;
        // 复用 connect_alert 的 IP:port 格式化逻辑
        if (sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            __be32 ip;
            __be16 port;
            bpf_probe_read_user(&ip, sizeof(ip), &sin->sin_addr.s_addr);
            bpf_probe_read_user(&port, sizeof(port), &sin->sin_port);
            __u8 *b = (__u8 *)&ip;
            __u16 p = __builtin_bswap16(port);
            int pos = 0;
            for (int i = 0; i < 4; i++) {
                __u8 v = b[i];
                if (v >= 100) { evt.path_or_ip[pos++] = '0' + v / 100; v %= 100; }
                if (v >= 10)  { evt.path_or_ip[pos++] = '0' + v / 10;  v %= 10; }
                evt.path_or_ip[pos++] = '0' + v;
                evt.path_or_ip[pos++] = (i < 3) ? '.' : ':';
            }
            evt.path_or_ip[pos++] = '0' + (p / 10000); p %= 10000;
            evt.path_or_ip[pos++] = '0' + (p / 1000);  p %= 1000;
            evt.path_or_ip[pos++] = '0' + (p / 100);   p %= 100;
            evt.path_or_ip[pos++] = '0' + (p / 10);
            evt.path_or_ip[pos++] = '0' + (p % 10);
        } else {
            bpf_probe_read_user(evt.path_or_ip, 40, addr);
        }
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }
}

/* ── chmod 权限位 ── */
#define S_IXUSR  0100
#define S_IXGRP  0010
#define S_IXOTH  0001
#define S_IXANY  (S_IXUSR | S_IXGRP | S_IXOTH)

/* ── sys_enter_chmod ── */
SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    int mode = (int)ctx->args[1];

    /* 仅拦截添加执行权限的操作 */
    if ((mode & S_IXANY) == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 tgid = pid_tgid >> 32;
    __u8 *mon = bpf_map_lookup_elem(&monitored_tgid, &tgid);
    if (!mon)
        return 0;

    struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
            bpf_map_delete_elem(&causal_chain, &pid_tgid);
            goto chmod_alert;
        }
        if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
            goto chmod_unverified_alert;
        if (!entry->validated)
            goto chmod_alert;
        return 0;
    }

chmod_alert:
    {
        const char *filename = (const char *)ctx->args[0];
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_chmod;
        evt.reason = ALERT_NO_CAUSAL_ID;
        bpf_probe_read_user_str(evt.path_or_ip, sizeof(evt.path_or_ip), filename);
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }

chmod_unverified_alert:
    {
        const char *filename = (const char *)ctx->args[0];
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_chmod;
        evt.reason = ALERT_UNVERIFIED_BLOCK;
        bpf_probe_read_user_str(evt.path_or_ip, sizeof(evt.path_or_ip), filename);
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }
}

/* ── sys_enter_fchmod ── */
SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    int mode = (int)ctx->args[1];

    if ((mode & S_IXANY) == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u64 tgid = pid_tgid >> 32;
    __u8 *mon = bpf_map_lookup_elem(&monitored_tgid, &tgid);
    if (!mon)
        return 0;

    struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
            bpf_map_delete_elem(&causal_chain, &pid_tgid);
            goto fchmod_alert;
        }
        if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
            goto fchmod_unverified_alert;
        if (!entry->validated)
            goto fchmod_alert;
        return 0;
    }

fchmod_alert:
    {
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_fchmod;
        evt.reason = ALERT_NO_CAUSAL_ID;
        int fd_val = (int)ctx->args[0];
        evt.path_or_ip[0] = 'f'; evt.path_or_ip[1] = 'd';
        // 简单写 fd 数字，最多处理 3 位
        if (fd_val >= 100) { evt.path_or_ip[2] = '0' + fd_val / 100; fd_val %= 100; }
        else { evt.path_or_ip[2] = '0' + fd_val / 10; }
        evt.path_or_ip[3] = '0' + (fd_val / 10);
        evt.path_or_ip[4] = '0' + (fd_val % 10);
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }

fchmod_unverified_alert:
    {
        struct alert_event evt = {0};
        evt.pid = pid_tgid >> 32;
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.syscall_nr = __NR_fchmod;
        evt.reason = ALERT_UNVERIFIED_BLOCK;
        int fd_val = (int)ctx->args[0];
        evt.path_or_ip[0] = 'f'; evt.path_or_ip[1] = 'd';
        // 简单写 fd 数字，最多处理 3 位
        if (fd_val >= 100) { evt.path_or_ip[2] = '0' + fd_val / 100; fd_val %= 100; }
        else { evt.path_or_ip[2] = '0' + fd_val / 10; }
        evt.path_or_ip[3] = '0' + (fd_val / 10);
        evt.path_or_ip[4] = '0' + (fd_val % 10);
        bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        bpf_send_signal(9);
        return 0;
    }
}

/* ── sys_enter_sendto ── */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *addr = (struct sockaddr *)ctx->args[4];

    /* dest_addr 为 NULL: 已 connect 的 socket，无法安全确定目标 → 阻断 */
    if (!addr)
        goto sendto_block;

    unsigned short sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family == AF_UNIX)
        return 0;

    if (sa_family != AF_INET && sa_family != AF_INET6)
        return 0;

sendto_block:
    {
        __u64 pid_tgid = bpf_get_current_pid_tgid();

        __u64 tgid = pid_tgid >> 32;
        __u8 *mon = bpf_map_lookup_elem(&monitored_tgid, &tgid);
        if (!mon)
            return 0;

        struct causal_entry *entry = bpf_map_lookup_elem(&causal_chain, &pid_tgid);

        if (entry) {
            __u64 now = bpf_ktime_get_ns();
            if (now - entry->timestamp_ns > CAUSAL_ID_TTL_NS) {
                bpf_map_delete_elem(&causal_chain, &pid_tgid);
                goto sendto_alert;
            }
            if (entry->flags & CAUSAL_FLAG_UNVERIFIED)
                goto sendto_unverified_alert;
            if (!entry->validated)
                goto sendto_alert;
            return 0;
        }

sendto_alert:
        {
            struct alert_event evt = {0};
            evt.pid = pid_tgid >> 32;
            evt.timestamp_ns = bpf_ktime_get_ns();
            evt.syscall_nr = __NR_sendto;
            evt.reason = ALERT_NO_CAUSAL_ID;

            if (addr && sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr;
                __be32 ip;
                __be16 port;
                bpf_probe_read_user(&ip, sizeof(ip), &sin->sin_addr.s_addr);
                bpf_probe_read_user(&port, sizeof(port), &sin->sin_port);
                __u8 *b = (__u8 *)&ip;
                __u16 p = __builtin_bswap16(port);

                int pos = 0;
                for (int i = 0; i < 4; i++) {
                    __u8 v = b[i];
                    if (v >= 100) { evt.path_or_ip[pos++] = '0' + v / 100; v %= 100; }
                    if (v >= 10)  { evt.path_or_ip[pos++] = '0' + v / 10;  v %= 10; }
                    evt.path_or_ip[pos++] = '0' + v;
                    evt.path_or_ip[pos++] = (i < 3) ? '.' : ':';
                }
                evt.path_or_ip[pos++] = '0' + (p / 10000); p %= 10000;
                evt.path_or_ip[pos++] = '0' + (p / 1000);  p %= 1000;
                evt.path_or_ip[pos++] = '0' + (p / 100);   p %= 100;
                evt.path_or_ip[pos++] = '0' + (p / 10);
                evt.path_or_ip[pos++] = '0' + (p % 10);
            }
            bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            bpf_send_signal(9);
            return 0;
        }

sendto_unverified_alert:
        {
            struct alert_event evt = {0};
            evt.pid = pid_tgid >> 32;
            evt.timestamp_ns = bpf_ktime_get_ns();
            evt.syscall_nr = __NR_sendto;
            evt.reason = ALERT_UNVERIFIED_BLOCK;

            if (addr && sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr;
                __be32 ip;
                __be16 port;
                bpf_probe_read_user(&ip, sizeof(ip), &sin->sin_addr.s_addr);
                bpf_probe_read_user(&port, sizeof(port), &sin->sin_port);
                __u8 *b = (__u8 *)&ip;
                __u16 p = __builtin_bswap16(port);

                int pos = 0;
                for (int i = 0; i < 4; i++) {
                    __u8 v = b[i];
                    if (v >= 100) { evt.path_or_ip[pos++] = '0' + v / 100; v %= 100; }
                    if (v >= 10)  { evt.path_or_ip[pos++] = '0' + v / 10;  v %= 10; }
                    evt.path_or_ip[pos++] = '0' + v;
                    evt.path_or_ip[pos++] = (i < 3) ? '.' : ':';
                }
                evt.path_or_ip[pos++] = '0' + (p / 10000); p %= 10000;
                evt.path_or_ip[pos++] = '0' + (p / 1000);  p %= 1000;
                evt.path_or_ip[pos++] = '0' + (p / 100);   p %= 100;
                evt.path_or_ip[pos++] = '0' + (p / 10);
                evt.path_or_ip[pos++] = '0' + (p % 10);
            }
            bpf_perf_event_output(ctx, &alert_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            bpf_send_signal(9);
            return 0;
        }
    }
}
