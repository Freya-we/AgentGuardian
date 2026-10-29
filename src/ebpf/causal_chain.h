// src/ebpf/causal_chain.h
#pragma once
// BPF 编译时 vmlinux.h 已提供所有类型，避免 stdint.h 冲突
#ifndef __VMLINUX_H__
#include <stdint.h>
#endif

/* ── BPF Map 容量常量 ── */
#define CAUSAL_CHAIN_MAX_ENTRIES 4096
#define CAUSAL_ID_TTL_NS        5000000000ULL  // 5 秒
#define EXEC_WHITELIST_MAX      64
#define EXEC_WHITELIST_PATH_LEN 64
#define SESSION_KEY_SIZE        32

/* ── Syscall 号 ── */
#ifndef __NR_chmod
#define __NR_chmod   90
#endif
#ifndef __NR_fchmod
#define __NR_fchmod  91
#endif
#ifndef __NR_sendto
#define __NR_sendto  44
#endif

/* ── Unix Socket 协议 ── */
#define SOCKET_PATH    "/var/run/causal-guardian.sock"
#define MSG_REGISTER   0x01
#define MSG_KEY_UPDATE 0x02
#define MSG_NS_UPDATE  0x03   /* 推送 /proc 挂载点 dev/ino，用于命名空间 pid 换算 */

/* ── alert_event 拦截原因 ── */
#define ALERT_NO_CAUSAL_ID     0
#define ALERT_HMAC_FAIL        1
#define ALERT_UNVERIFIED_BLOCK 2
#define CAUSAL_FLAG_UNVERIFIED 0x01

#pragma pack(1)

/* ── BPF Map: causal_chain (key: u64 pid_tgid) ── */
struct causal_entry {
    uint8_t  causal_id[32];   // HMAC-SHA256 或 UNVERIFIED_ 标记
    uint64_t timestamp_ns;     // 写入时间 (bpf_ktime_get_ns)
    uint8_t  validated;        // 0=待验证, 1=sys_enter 验签通过
    uint8_t  flags;            // bit0: UNVERIFIED 标记
    uint8_t  padding[6];
};

/* ── BPF Map: exec_whitelist (key: 64-byte path, value: 32-byte SHA256) ── */
struct exec_whitelist_entry {
    uint8_t  sha256[32];   // 期望的 SHA256 哈希值
};

/* ── perf buffer: alert_events ── */
struct alert_event {
    uint64_t pid;
    uint64_t timestamp_ns;
    uint32_t syscall_nr;
    uint8_t  reason;            // ALERT_NO_CAUSAL_ID / ALERT_HMAC_FAIL / ALERT_UNVERIFIED_BLOCK
    uint8_t  path_or_ip[128];
};

/* ── Unix Socket 消息 ── */
struct msg_register {
    uint8_t  type;            // 0x01
    uint64_t pid;             // 本命名空间 pid（必须在 monitored_tgid 中，见 guardian handle_register）
    uint8_t  causal_id[32];   // HMAC-SHA256 签名后的 CausalID
    uint64_t timestamp_ns;    // 引擎签名时的单调时钟值，必须原样回传
    uint8_t  tool_name[64];   // 工具名，HMAC payload 重建所需
    uint8_t  params_hash[64]; // sha256(params) hex —— 票据绑定参数指纹 (P1-2)
};

struct msg_key_update {
    uint8_t  type;            // 0x02
    uint8_t  active_key[32];
    uint8_t  grace_key[32];   // 全 0 表示无旧 Key
};

/* ── 命名空间标识：/proc 挂载点的 dev + ino ── */
struct ns_id {
    uint64_t dev;
    uint64_t ino;
};

struct msg_ns_update {
    uint8_t  type;   /* 0x03 */
    uint64_t dev;
    uint64_t ino;
};

struct msg_ack {
    uint8_t  type;            // 0x01
    uint8_t  status;          // 0=ok, 1=map_write_fail, 2=验签失败/无效请求, 3=pid 不在监控名单
};

#pragma pack()
