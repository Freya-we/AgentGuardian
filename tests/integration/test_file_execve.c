// tests/integration/test_file_execve.c
// 测试文件操作和网络操作是否被 eBPF 拦截
// 编译: gcc -o tests/integration/test_file_execve tests/integration/test_file_execve.c -lbpf
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <bpf/bpf.h>

static void register_self(void) {
    __u64 tgid = (__u64)getpid();
    __u8 val = 1;
    int fd = bpf_obj_get("/sys/fs/bpf/agent_guardian/monitored_tgid");
    if (fd >= 0) {
        bpf_map_update_elem(fd, &tgid, &val, BPF_ANY);
        close(fd);
    }
}

static void test_open_read(const char *path) {
    printf("OPEN_READ: %s\n", path);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        printf("RESULT: ALLOWED (fd=%d)\n", fd);
        close(fd);
    } else {
        printf("RESULT: BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

static void test_open_write(const char *path) {
    printf("OPEN_WRITE: %s\n", path);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        printf("RESULT: ALLOWED (fd=%d)\n", fd);
        close(fd);
        unlink(path);
    } else {
        printf("RESULT: BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
    }
}

static void test_connect(const char *ip, int port) {
    printf("CONNECT: %s:%d\n", ip, port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("RESULT: SOCKET_FAILED (errno=%d: %s)\n", errno, strerror(errno));
        return;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) {
        printf("RESULT: ALLOWED\n");
        close(fd);
    } else {
        printf("RESULT: BLOCKED (errno=%d: %s)\n", errno, strerror(errno));
        close(fd);
    }
}

/* chmod +x: 应被阻断 (无 CausalID) */
static int test_chmod_add_exec(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) { perror("chmod setup open"); return 1; }
    close(fd);
    if (chmod(path, 0755) != 0) {
        perror("chmod");
        return 1;
    }
    printf("CHMOD_ALLOWED pid=%d\n", getpid());
    unlink(path);
    return 0;
}

/* chmod 644 (无执行位): 应放行。文件必须提前创建，避免 open(O_CREAT) 触发 eBPF 写拦截 */
static int test_chmod_no_exec(const char *path) {
    if (chmod(path, 0644) != 0) {
        perror("chmod");
        return 1;
    }
    printf("CHMOD_NOEXEC_ALLOWED pid=%d\n", getpid());
    return 0;
}

/* sendto AF_INET: 应被阻断 (无 CausalID) */
static int test_sendto_inet(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("sendto socket"); return 1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr);

    sendto(fd, "test", 4, 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("SENDTO_ALLOWED pid=%d\n", getpid());
    close(fd);
    return 0;
}

/* sendto AF_UNIX: 应放行 */
static int test_sendto_unix(const char *sock_path) {
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) { perror("sendto socket"); return 1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    sendto(fd, "test", 4, 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("SENDTO_UNIX_ALLOWED pid=%d\n", getpid());
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    register_self();
    printf("TEST_FILE_PID=%d\n", getpid());

    if (argc < 2) {
        fprintf(stderr, "用法: %s <action> [args...]\n", argv[0]);
        fprintf(stderr, "  read   <path>              测试读文件\n");
        fprintf(stderr, "  write  <path>              测试写文件\n");
        fprintf(stderr, "  connect <ip> <port>        测试网络连接\n");
        fprintf(stderr, "  test_chmod_add_exec <path> 测试 chmod +x\n");
        fprintf(stderr, "  test_chmod_no_exec <path>  测试 chmod 644\n");
        fprintf(stderr, "  test_sendto_inet            测试 sendto AF_INET\n");
        fprintf(stderr, "  test_sendto_unix <path>    测试 sendto AF_UNIX\n");
        return 2;
    }

    if (strcmp(argv[1], "read") == 0 && argc >= 3) {
        test_open_read(argv[2]);
    } else if (strcmp(argv[1], "write") == 0 && argc >= 3) {
        test_open_write(argv[2]);
    } else if (strcmp(argv[1], "connect") == 0 && argc >= 4) {
        test_connect(argv[2], atoi(argv[3]));
    } else if (strcmp(argv[1], "test_chmod_add_exec") == 0) {
        return test_chmod_add_exec(argv[2]);
    } else if (strcmp(argv[1], "test_chmod_no_exec") == 0) {
        return test_chmod_no_exec(argv[2]);
    } else if (strcmp(argv[1], "test_sendto_inet") == 0) {
        return test_sendto_inet();
    } else if (strcmp(argv[1], "test_sendto_unix") == 0) {
        return test_sendto_unix(argv[2]);
    } else {
        fprintf(stderr, "未知操作: %s\n", argv[1]);
        return 2;
    }

    return 0;
}
