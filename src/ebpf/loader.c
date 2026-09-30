// src/ebpf/loader.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execve_monitor.skel.h"
#include "causal_chain.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define MAP_PIN_DIR "/sys/fs/bpf/agent_guardian"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) { running = 0; }

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct alert_event *evt = data;
    fprintf(stderr,
            "[ALERT] pid=%llu syscall=%u reason=%u path=%s\n",
            (unsigned long long)evt->pid,
            evt->syscall_nr, evt->reason, evt->path_or_ip);
}

#define CONF_PATH "/etc/agent-guardian/exec_whitelist.conf"
#define CONF_LINE_MAX 512

static int compute_sha256(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); fclose(f); return -1;
    }
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx); fclose(f); return -1;
        }
    }
    fclose(f);

    unsigned int len = 32;
    if (EVP_DigestFinal_ex(ctx, out, &len) != 1) {
        EVP_MD_CTX_free(ctx); return -1;
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static int init_whitelist(struct execve_monitor_bpf *skel) {
    FILE *conf = fopen(CONF_PATH, "r");
    if (!conf) {
        fprintf(stderr, "白名单配置文件 %s 不存在，所有非 CausalID 的 execve 将被阻断\n", CONF_PATH);
        return 0;
    }

    char line[CONF_LINE_MAX];
    int line_no = 0;
    int loaded = 0, skipped = 0;

    while (fgets(line, sizeof(line), conf)) {
        line_no++;

        // 跳过注释和空行
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        if (*start == '#' || *start == '\n' || *start == '\0')
            continue;

        // 解析: <sha256 hex>  <path>
        char sha_hex[65] = {0};
        char file_path[EXEC_WHITELIST_PATH_LEN * 2] = {0};
        if (sscanf(start, "%64s %127[^\n]", sha_hex, file_path) != 2) {
            fprintf(stderr, "WARNING: %s:%d: 格式错误\n", CONF_PATH, line_no);
            skipped++;
            continue;
        }

        // 去掉 Windows 换行符 \r (防止路径末尾带 \r 导致 stat 失败)
        size_t fp_len = strlen(file_path);
        while (fp_len > 0 && file_path[fp_len - 1] == '\r')
            file_path[--fp_len] = '\0';

        // 验证路径存在且为普通文件
        struct stat st;
        if (stat(file_path, &st) != 0) {
            fprintf(stderr, "WARNING: %s:%d: 文件不存在: %s\n", CONF_PATH, line_no, file_path);
            skipped++;
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "WARNING: %s:%d: 不是普通文件: %s\n", CONF_PATH, line_no, file_path);
            skipped++;
            continue;
        }

        // 计算实际 SHA256
        uint8_t actual_sha[32] = {0};
        if (compute_sha256(file_path, actual_sha) != 0) {
            fprintf(stderr, "WARNING: %s:%d: 无法计算哈希: %s\n", CONF_PATH, line_no, file_path);
            skipped++;
            continue;
        }

        // 与期望哈希比较 (常量时间，防时序侧信道)
        uint8_t expected_sha[32] = {0};
        if (hex_to_bytes(sha_hex, expected_sha, 32) != 0) {
            fprintf(stderr, "WARNING: %s:%d: 无效 SHA256 hex: %s\n", CONF_PATH, line_no, sha_hex);
            skipped++;
            continue;
        }

        if (CRYPTO_memcmp(expected_sha, actual_sha, 32) != 0) {
            char actual_hex[65];
            for (int i = 0; i < 32; i++)
                sprintf(actual_hex + i * 2, "%02x", actual_sha[i]);
            fprintf(stderr, "WARNING: %s:%d: 哈希不匹配 %s (期望 %s, 实际 %s)\n",
                    CONF_PATH, line_no, file_path, sha_hex, actual_hex);
            skipped++;
            continue;
        }

        // 写入 BPF Map: key = 64 字节路径 (末尾补零), value = SHA256
        uint8_t key[EXEC_WHITELIST_PATH_LEN] = {0};
        size_t path_len = strnlen(file_path, EXEC_WHITELIST_PATH_LEN);
        if (path_len >= EXEC_WHITELIST_PATH_LEN) {
            fprintf(stderr, "WARNING: %s:%d: 路径过长 (最大 %d): %s\n",
                    CONF_PATH, line_no, EXEC_WHITELIST_PATH_LEN - 1, file_path);
            skipped++;
            continue;
        }
        memcpy(key, file_path, path_len);

        int ret = bpf_map__update_elem(skel->maps.exec_whitelist,
                                        key, sizeof(key),
                                        actual_sha, sizeof(actual_sha),
                                        BPF_ANY);
        if (ret) {
            fprintf(stderr, "WARNING: 写入 BPF Map 失败 (%s): %s\n",
                    file_path, strerror(-ret));
            skipped++;
        } else {
            loaded++;
        }
    }

    fclose(conf);
    printf("exec_whitelist: 已加载 %d 条, 跳过 %d 条\n", loaded, skipped);
    return 0;
}

int main(int argc, char **argv) {
    struct execve_monitor_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err = 0;
    long monitor_pid = 0;

    /* 0. 解析参数 */
    if (argc > 1 && strcmp(argv[1], "-p") == 0 && argc > 2) {
        monitor_pid = atol(argv[2]);
    }

    /* 1. 设置 libbpf 日志 */
    libbpf_set_print(libbpf_print_fn);

    /* 2. 注册信号处理 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 3. 提升内存锁限制 */
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Warning: setrlimit(RLIMIT_MEMLOCK) 失败: %s\n",
                strerror(errno));
    }

    /* 4. 打开 + 加载 + 附加 */
    skel = execve_monitor_bpf__open();
    if (!skel) { fprintf(stderr, "未能打开 BPF skeleton\n"); return 1; }

    err = execve_monitor_bpf__load(skel);
    if (err) { fprintf(stderr, "未能加载 BPF skeleton: %d\n", err); goto cleanup; }

    err = execve_monitor_bpf__attach(skel);
    if (err) { fprintf(stderr, "未能附加 BPF skeleton: %d\n", err); goto cleanup; }

    /* 5. 固定 Map (供 causal-guardian 打开) */
    mkdir(MAP_PIN_DIR, 0755);
    bpf_map__pin(skel->maps.causal_chain, MAP_PIN_DIR "/causal_chain");
    bpf_map__pin(skel->maps.session_key, MAP_PIN_DIR "/session_key");
    bpf_map__pin(skel->maps.exec_whitelist, MAP_PIN_DIR "/exec_whitelist");
    bpf_map__pin(skel->maps.monitored_tgid, MAP_PIN_DIR "/monitored_tgid");
    chmod(MAP_PIN_DIR "/monitored_tgid", 0666);
    bpf_map__pin(skel->maps.alert_events, MAP_PIN_DIR "/alert_events");

    /* 6. 初始化白名单 */
    init_whitelist(skel);

    /* 6b. 注册监控 PID (如有 -p 参数) */
    if (monitor_pid > 0) {
        __u64 tgid = (__u64)monitor_pid;
        __u8 val = 1;
        int ret = bpf_map__update_elem(skel->maps.monitored_tgid,
                                        &tgid, sizeof(tgid),
                                        &val, sizeof(val), BPF_ANY);
        if (ret)
            fprintf(stderr, "无法注册监控 PID %ld: %s\n", monitor_pid, strerror(-ret));
        else
            printf("已注册监控 TGID: %ld\n", monitor_pid);
    }

    /* 7. 设置 perf buffer */
    pb = perf_buffer__new(bpf_map__fd(skel->maps.alert_events), 64,
                          handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "警告: 未能创建 perf buffer (无 CONFIG_DEBUG_FS?)\n");
        /* 非致命，继续运行 */
    }

    printf("eBPF execve 探针已加载, Map 固定于 %s\n", MAP_PIN_DIR);

    /* 8. 主循环 */
    while (running) {
        if (pb) perf_buffer__poll(pb, 300);
        else usleep(300000);
    }

    printf("\n正在清理...\n");

cleanup:
    perf_buffer__free(pb);
    /* 解除 Map 固定 */
    bpf_map__unpin(skel->maps.causal_chain, MAP_PIN_DIR "/causal_chain");
    bpf_map__unpin(skel->maps.session_key, MAP_PIN_DIR "/session_key");
    bpf_map__unpin(skel->maps.exec_whitelist, MAP_PIN_DIR "/exec_whitelist");
    bpf_map__unpin(skel->maps.monitored_tgid, MAP_PIN_DIR "/monitored_tgid");
    bpf_map__unpin(skel->maps.alert_events, MAP_PIN_DIR "/alert_events");
    execve_monitor_bpf__destroy(skel);
    return err ? 1 : 0;
}
