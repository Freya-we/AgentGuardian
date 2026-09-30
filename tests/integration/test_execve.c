// tests/integration/test_execve.c
// 编译: gcc -o tests/integration/test_execve tests/integration/test_execve.c -lbpf
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
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

int main(int argc, char **argv) {
    register_self();

    if (argc < 2) {
        fprintf(stderr, "用法: %s <executable> [args...]\n", argv[0]);
        fprintf(stderr, "退出码: 0=execve成功, -9=被SIGKILL杀死, 1=execve失败, 2=用法错误\n");
        return 2;
    }

    printf("TEST_EXECVE_PID=%d\n", getpid());

    execv(argv[1], &argv[1]);

    fprintf(stderr, "EXECVE_FAILED: %s (errno=%d: %s)\n", argv[1], errno, strerror(errno));
    return 1;
}
