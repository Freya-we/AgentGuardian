// src/causal_guardian/main.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "../ebpf/causal_chain.h"

#define MAP_PIN_DIR    "/sys/fs/bpf/agent_guardian"
#define MAX_CLIENTS    16

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig) { running = 0; }

static int open_bpf_map(const char *name, int *fd) {
    char path[256];
    snprintf(path, sizeof(path), MAP_PIN_DIR "/%s", name);
    *fd = bpf_obj_get(path);
    if (*fd < 0) {
        fprintf(stderr, "未能打开 BPF Map %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int handle_register(int causal_chain_fd, int session_key_fd,
                           struct msg_register *req, struct msg_ack *ack) {
    ack->type = MSG_REGISTER;

    /* ── 读取 session keys ── */
    __u32 key_active = 0, key_grace = 1;
    uint8_t active_key[32] = {0}, grace_key[32] = {0};
    int has_active = (bpf_map_lookup_elem(session_key_fd, &key_active, active_key) == 0);
    int has_grace  = (bpf_map_lookup_elem(session_key_fd, &key_grace, grace_key) == 0);

    if (!has_active) {
        ack->status = 2;
        fprintf(stderr, "HMAC 验签失败: session_key 未初始化\n");
        return -1;
    }

    /* ── 重建 payload: pid|tool_name|timestamp_ns|ttl_ns ── */
    char payload[256];
    int plen = snprintf(payload, sizeof(payload), "%llu|%s|%llu|%llu",
                        (unsigned long long)req->pid, req->tool_name,
                        (unsigned long long)req->timestamp_ns,
                        (unsigned long long)CAUSAL_ID_TTL_NS);
    if (plen < 0 || plen >= (int)sizeof(payload)) {
        ack->status = 2;
        return -1;
    }

    /* ── HMAC-SHA256 验签 (active key → grace key) ── */
    int hmac_ok = 0;
    uint8_t computed[32];
    unsigned int len = 32;
    HMAC(EVP_sha256(), active_key, 32,
         (uint8_t *)payload, (size_t)plen, computed, &len);
    hmac_ok = (CRYPTO_memcmp(computed, req->causal_id, 32) == 0);

    if (!hmac_ok && has_grace) {
        /* 检查 grace key 是否全零 (未设定) */
        int zero = 1;
        for (int i = 0; i < 32; i++) { if (grace_key[i]) { zero = 0; break; } }
        if (!zero) {
            HMAC(EVP_sha256(), grace_key, 32,
                 (uint8_t *)payload, (size_t)plen, computed, &len);
            hmac_ok = (CRYPTO_memcmp(computed, req->causal_id, 32) == 0);
        }
    }

    if (!hmac_ok) {
        ack->status = 2;
        fprintf(stderr, "HMAC 验签失败 (pid=%llu)\n",
                (unsigned long long)req->pid);
        return -1;
    }

    /* ── 验签通过，写入 BPF Map ── */
    struct causal_entry entry = {0};
    memcpy(entry.causal_id, req->causal_id, 32);
    entry.timestamp_ns = req->timestamp_ns;
    entry.validated = 1;
    entry.flags = 0;

    __u64 mkey = req->pid;
    int ret = bpf_map_update_elem(causal_chain_fd, &mkey, &entry, BPF_ANY);
    ack->status = (ret == 0) ? 0 : 1;
    if (ret)
        fprintf(stderr, "MSG_REGISTER 写入 Map 失败 (pid=%llu): %s\n",
                (unsigned long long)req->pid, strerror(-ret));
    return ret;
}

static int handle_key_update(int session_key_fd, struct msg_key_update *req,
                             struct msg_ack *ack) {
    __u32 key_active = 0;
    __u32 key_grace  = 1;
    int ret1 = bpf_map_update_elem(session_key_fd, &key_active,
                                   req->active_key, BPF_ANY);
    int ret2 = bpf_map_update_elem(session_key_fd, &key_grace,
                                   req->grace_key, BPF_ANY);

    ack->type = MSG_KEY_UPDATE;
    ack->status = (ret1 == 0 && ret2 == 0) ? 0 : 1;
    if (ret1 || ret2)
        fprintf(stderr, "MSG_KEY_UPDATE 写入 Map 失败\n");
    return (ret1 || ret2) ? -1 : 0;
}

static int check_peer_cred(int fd) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        fprintf(stderr, "SO_PEERCRED 获取失败: %s\n", strerror(errno));
        return -1;
    }
    /* 仅允许 root 或与 guardian 同 UID 的进程 */
    if (cred.uid != 0 && cred.uid != getuid()) {
        fprintf(stderr, "拒绝连接: pid=%d uid=%d (非授权调用方)\n",
                cred.pid, cred.uid);
        return -1;
    }
    return 0;
}

#define AUDIT_ENGINE_HOST          "127.0.0.1"
#define AUDIT_ENGINE_PORT          8000
#define ALERT_JSON_MAX   1024
#define HTTP_REQ_MAX     1536

/* ── syscall 编号 → 名称 ── */
static const char *syscall_name(uint32_t nr) {
    switch (nr) {
        case 59:  return "execve";
        case 257: return "openat";
        case 42:  return "connect";
        case 90:  return "chmod";
        case 91:  return "fchmod";
        case 44:  return "sendto";
        default:  return "unknown";
    }
}

static const char *alert_reason_name(uint8_t reason) {
    switch (reason) {
        case 0: return "no_causal_id";
        case 1: return "hmac_fail";
        case 2: return "unverified_blocked";
        default: return "unknown";
    }
}

/* ── 原始 TCP HTTP POST 到审计引擎 ── */
static void forward_to_l3(const char *json_body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(AUDIT_ENGINE_PORT);
    addr.sin_addr.s_addr = inet_addr(AUDIT_ENGINE_HOST);

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return;
    }

    size_t body_len = strlen(json_body);
    char req[HTTP_REQ_MAX];
    int req_len = snprintf(req, sizeof(req),
        "POST /api/v1/ebpf/intercept HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        AUDIT_ENGINE_HOST, AUDIT_ENGINE_PORT, body_len, json_body);

    if (req_len > 0 && req_len < (int)sizeof(req))
        send(sock, req, (size_t)req_len, MSG_NOSIGNAL);
    close(sock);
}

/* ── perf buffer 回调: 格式化 + 转发到审计引擎 ── */
static void handle_alert_event(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx; (void)cpu; (void)size;
    struct alert_event *evt = data;

    char json[ALERT_JSON_MAX];
    int n = snprintf(json, sizeof(json),
        "{"
        "\"pid\":%llu,"
        "\"syscall\":\"%s\","
        "\"causal_id_valid\":%s,"
        "\"action\":\"block\","
        "\"reason\":\"%s\","
        "\"timestamp\":%llu"
        "}",
        (unsigned long long)evt->pid,
        syscall_name(evt->syscall_nr),
        evt->reason == ALERT_NO_CAUSAL_ID ? "false" : "true",
        alert_reason_name(evt->reason),
        (unsigned long long)evt->timestamp_ns);

    if (n > 0 && n < (int)sizeof(json)) {
        fprintf(stderr, "[ALERT] %s\n", json);
        forward_to_l3(json);
    }
}

/* ── 打开 alert_events perf buffer ── */
static struct perf_buffer *open_alert_pb(void) {
    char path[256];
    snprintf(path, sizeof(path), MAP_PIN_DIR "/alert_events");
    int map_fd = bpf_obj_get(path);
    if (map_fd < 0) {
        fprintf(stderr, "无法打开 alert_events map (内核探针可能未加载): %s\n",
                strerror(errno));
        return NULL;
    }
    struct perf_buffer *pb = perf_buffer__new(map_fd, 64,
                                              handle_alert_event, NULL, NULL, NULL);
    close(map_fd);
    if (!pb)
        fprintf(stderr, "perf_buffer__new 失败\n");
    else
        printf("alert_events perf buffer 已就绪\n");
    return pb;
}

static int process_client(int fd, int causal_chain_fd, int session_key_fd) {
    uint8_t buf[128] = {0};
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0) return -1;

    uint8_t type = buf[0];
    struct msg_ack ack = {0};

    if (type == MSG_REGISTER && n >= (ssize_t)sizeof(struct msg_register)) {
        handle_register(causal_chain_fd, session_key_fd,
                        (struct msg_register *)buf, &ack);
    } else if (type == MSG_KEY_UPDATE &&
               n >= (ssize_t)sizeof(struct msg_key_update)) {
        handle_key_update(session_key_fd, (struct msg_key_update *)buf, &ack);
    } else {
        ack.type = type;
        ack.status = 2;  // 无效请求
        fprintf(stderr, "收到无效请求 type=0x%02x len=%zd\n", type, n);
    }

    send(fd, &ack, sizeof(ack), MSG_DONTWAIT);
    return 0;
}

int main(int argc, char **argv) {
    int listen_fd = -1, causal_chain_fd = -1, session_key_fd = -1;
    struct sockaddr_un addr;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 1. 打开已固定的 BPF Maps */
    if (open_bpf_map("causal_chain", &causal_chain_fd)) return 1;
    if (open_bpf_map("session_key", &session_key_fd)) return 1;
    printf("BPF Map 已打开: %s/causal_chain, session_key\n", MAP_PIN_DIR);

    /* 1b. 打开 perf buffer (alert_events → 审计引擎转发) */
    struct perf_buffer *alert_pb = open_alert_pb();

    /* 2. 创建 Unix Socket */
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    unlink(SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    chmod(SOCKET_PATH, 0600);
    if (listen(listen_fd, MAX_CLIENTS) < 0) { perror("listen"); return 1; }

    printf("causal-guardian 已启动, 监听 %s\n", SOCKET_PATH);

    /* 3. poll 主循环 */
    struct pollfd fds[MAX_CLIENTS + 1];
    memset(fds, 0, sizeof(fds));
    fds[0].fd = listen_fd;
    fds[0].events = POLLIN;
    int nfds = 1;

    while (running) {
        /* perf buffer 非阻塞轮询 (与审计引擎断连不影响主循环) */
        if (alert_pb) perf_buffer__poll(alert_pb, 0);

        int ret = poll(fds, nfds, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }

        if (fds[0].revents & POLLIN) {
            int client = accept(listen_fd, NULL, NULL);
            if (client >= 0 && nfds < MAX_CLIENTS + 1) {
                if (check_peer_cred(client) < 0) {
                    close(client);
                    continue;
                }
                fds[nfds].fd = client;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        for (int i = 1; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                int rc = process_client(fds[i].fd, causal_chain_fd, session_key_fd);
                if (rc < 0) {
                    close(fds[i].fd);
                    fds[i] = fds[nfds - 1];
                    nfds--;
                    i--;
                }
            }
        }
    }

    printf("\n正在清理...\n");
    if (alert_pb) perf_buffer__free(alert_pb);
    close(listen_fd);
    unlink(SOCKET_PATH);
    return 0;
}
