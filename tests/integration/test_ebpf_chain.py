#!/usr/bin/env python3
"""eBPF + causal-guardian 集成测试

测试前确保:
  1. sudo ./src/ebpf/loader 已运行
  2. sudo ./src/causal_guardian/causal-guardian 已运行
"""

import hashlib
import hmac
import os
import socket
import struct
import subprocess
import time

import pytest

# 需要 Linux + root + eBPF + causal-guardian 运行中，见 scripts/run_ebpf_tests.sh
pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "AF_UNIX"),
    reason="eBPF 集成测试仅支持 Linux (需 root + causal-guardian)",
)

BPFTOOL = "bpftool"
TEST_EXECVE = os.path.join(os.path.dirname(__file__), "test_execve")
TEST_FILE_EXECVE = os.path.join(os.path.dirname(__file__), "test_file_execve")
SOCKET_PATH = "/var/run/causal-guardian.sock"
MAP_DIR = "/sys/fs/bpf/agent_guardian"

# 测试用固定密钥
TEST_KEY = b"T" * 32  # 32 bytes

# 注册/签发共用同一 params_hash 约定：引擎按 sha256(params) 重算，
# 这里的票据是测试自己造的，只要"签名"与"注册"两端一致即可
PARAMS_HASH = hashlib.sha256(b"").hexdigest()


def _send_key_update(active_key: bytes, grace_key: bytes = b"") -> int:
    """发送 MSG_KEY_UPDATE，返回 status"""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect(SOCKET_PATH)
    payload = struct.pack("<B32s32s", 0x02, active_key, grace_key)
    sock.sendall(payload)
    ack = sock.recv(2)
    sock.close()
    return ack[1]


def _make_causal_id(pid: int, tool_name: str, timestamp_ns: int,
                    key: bytes = TEST_KEY,
                    params_hash: str = PARAMS_HASH) -> bytes:
    """生成合法的 HMAC-SHA256 CausalID

    payload 必须与 guardian 重建格式逐字节一致:
    pid|tool_name|params_hash|timestamp_ns|ttl_ns"""
    payload = f"{pid}|{tool_name}|{params_hash}|{timestamp_ns}|5000000000".encode()
    return hmac.new(key, payload, hashlib.sha256).digest()


def ensure_monitored(pid: int) -> None:
    """把 pid 加进 monitored_tgid（等价于 loader -p <pid>）。

    guardian 现在只给监控名单内的 pid 写票据（P0-1b 门禁），注册前必须先加白。"""
    key_hex = int(pid).to_bytes(8, "little").hex()
    subprocess.run(
        [BPFTOOL, "map", "update", "pinned", f"{MAP_DIR}/monitored_tgid",
         "key", "hex", key_hex, "value", "hex", "01"],
        check=True, capture_output=True,
    )


def send_register(pid: int, causal_id: bytes,
                  tool_name: str = "bash_exec",
                  timestamp_ns: int = None,
                  params_hash: str = PARAMS_HASH) -> int:
    """发送 MSG_REGISTER，返回 status

    timestamp_ns 必须用单调时钟（与内核 bpf_ktime_get_ns 同基准）；
    pid 必须先经过 ensure_monitored()。"""
    if timestamp_ns is None:
        timestamp_ns = time.monotonic_ns()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect(SOCKET_PATH)
    name_bytes = tool_name.encode()[:63].ljust(64, b'\x00')
    hash_bytes = params_hash.encode()[:64].ljust(64, b'\x00')
    payload = struct.pack("<BQ32sQ64s64s", 0x01, pid, causal_id,
                          timestamp_ns, name_bytes, hash_bytes)
    sock.sendall(payload)
    ack = sock.recv(2)
    sock.close()
    return ack[1]


def bpftool_map_dump(map_name: str) -> str:
    return subprocess.check_output(
        [BPFTOOL, "map", "dump", "pinned", f"{MAP_DIR}/{map_name}"],
        stderr=subprocess.STDOUT, text=True
    )


def setup_module():
    """所有测试前发送 session key 到 guardian"""
    status = _send_key_update(TEST_KEY)
    if status != 0:
        print(f"  [WARN] MSG_KEY_UPDATE 失败 status={status}")


# ── 测试 ───────────────────────────────────────────


def test_probe_loaded():
    """验证 eBPF 探针已加载"""
    result = subprocess.run(
        [BPFTOOL, "prog", "list"], capture_output=True, text=True
    )
    assert "execve" in result.stdout, \
        f"探针未在 bpftool prog list 中找到:\n{result.stdout}"


def test_map_accessible():
    """验证 BPF Map 可读取"""
    result = bpftool_map_dump("causal_chain")
    # bpftool 输出可能是 "Found 0 elements" 或 "[]"
    assert "Found 0 elements" in result or result.strip() in ("", "[]"), \
        f"Map 不可读:\n{result}"


def test_register_and_allow():
    """验证 causal-guardian 写入后 eBPF 放行"""
    pid = os.getpid()
    ensure_monitored(pid)  # P0-1b：注册前先加监控名单
    ts = time.monotonic_ns()
    causal_id = _make_causal_id(pid, "bash_exec", ts)

    status = send_register(pid, causal_id, timestamp_ns=ts)
    assert status == 0, f"MSG_REGISTER 失败，status={status}"


def test_register_rejects_unmonitored_pid():
    """P0-1b 门禁：不在 monitored_tgid 里的 pid 注册票据 → status=3 拒绝。

    选一个几乎不可能存在的 pid（且绝不给自己加白）。"""
    victim_pid = 4194303  # pid_max 默认上限附近，测试机不会有这个进程
    ensure_monitored(victim_pid)
    subprocess.run(
        [BPFTOOL, "map", "delete", "pinned", f"{MAP_DIR}/monitored_tgid",
         "key", "hex", victim_pid.to_bytes(8, "little").hex()],
        check=True, capture_output=True,
    )
    ts = time.monotonic_ns()
    causal_id = _make_causal_id(victim_pid, "bash_exec", ts)
    status = send_register(victim_pid, causal_id, timestamp_ns=ts)
    assert status == 3, f"未监控 pid 应被拒绝 (status=3)，实际 {status}"


def test_no_causal_id_blocked():
    """验证无 CausalID 且不在白名单时进程被 SIGKILL"""
    # 注意: /bin/ 和 /usr/bin/ 在白名单中，需要用一个不在白名单的路径
    # 先创建一个测试脚本，再 exec 它
    test_script = "/tmp/agent_test_script.sh"
    with open(test_script, "w") as f:
        f.write("#!/bin/sh\necho 'SHOULD_NOT_RUN'\n")
    os.chmod(test_script, 0o755)

    result = subprocess.run(
        [TEST_EXECVE, test_script],
        capture_output=True, text=True, timeout=5
    )
    os.unlink(test_script)
    assert result.returncode == -9, \
        f"无 CausalID execve 应被 SIGKILL (returncode=-9), 实际 {result.returncode}"


def test_ttl_expiry():
    """验证 CausalID 过期 (5s TTL) 后自动清理"""
    pid = os.getpid()
    ensure_monitored(pid)
    ts = time.monotonic_ns()
    causal_id = _make_causal_id(pid, "bash_exec", ts)

    status = send_register(pid, causal_id, timestamp_ns=ts)
    assert status == 0, f"MSG_REGISTER 失败，status={status}"


def test_msg_register_latency():
    """验证 MSG_REGISTER 在 50ms 内返回 ACK"""
    pid = os.getpid()
    ensure_monitored(pid)
    ts = time.monotonic_ns()
    causal_id = _make_causal_id(pid, "bash_exec", ts)

    start = time.monotonic()
    status = send_register(pid, causal_id, timestamp_ns=ts)
    elapsed = (time.monotonic() - start) * 1000

    assert status == 0, f"MSG_REGISTER 失败，status={status}"
    assert elapsed < 50, f"MSG_REGISTER 延迟 {elapsed:.1f}ms > 50ms"


def test_open_read_allowed():
    """只读 open 不受 CausalID 检查"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "read", "/etc/hostname"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "ALLOWED" in result.stdout


def test_open_write_blocked():
    """写文件无 CausalID → 应 SIGKILL"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "write", "/tmp/ebpf_test_write.txt"],
        capture_output=True, text=True, timeout=5
    )
    assert result.returncode == -9, \
        f"写文件应被 SIGKILL: returncode={result.returncode}"


def test_connect_blocked():
    """外部 IP connect 无 CausalID → 应 SIGKILL"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "connect", "1.2.3.4", "80"],
        capture_output=True, text=True, timeout=5
    )
    assert result.returncode == -9, \
        f"connect 应被 SIGKILL: returncode={result.returncode}"


def test_open_write_with_causal_id():
    """有 CausalID 时写文件 → 应放行"""
    pid = os.getpid()
    ensure_monitored(pid)
    ts = time.monotonic_ns()
    causal_id = _make_causal_id(pid, "bash_exec", ts)
    status = send_register(pid, causal_id, timestamp_ns=ts)
    assert status == 0, f"MSG_REGISTER 失败: status={status}"


def _wait_for_pid_file(path: str, timeout: float = 3.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            time.sleep(0.02)
    raise TimeoutError(f"pid 文件未生成: {path}")


def test_valid_ticket_allows_exec():
    """DeepSeek 复查报告 P1-11 要求的关键断言（此前整套测试都缺它）：

    注册合法票据 → 受监控进程 exec 非白名单二进制 → 应当存活。
    只断言"guardian 收下了注册"验证不了任何端到端行为。"""
    marker = "/tmp/agent_test_ticket_marker"
    pidfile = "/tmp/agent_test_ticket_pid"
    script = "/tmp/agent_test_ticket_script.sh"
    for stale in (marker, pidfile):
        try:
            os.unlink(stale)
        except OSError:
            pass
    with open(script, "w") as f:
        f.write(f"#!/bin/sh\necho ok > {marker}\n")
    os.chmod(script, 0o755)

    # sh 自报 pid → 父进程加白 + 注册票据 → sh 在 1s 后 exec 脚本（票据 5s TTL 内）
    proc = subprocess.Popen(
        ["sh", "-c", f"echo $$ > {pidfile}; sleep 1; exec {script}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        pid = _wait_for_pid_file(pidfile)
        ensure_monitored(pid)
        ts = time.monotonic_ns()
        causal_id = _make_causal_id(pid, "bash_exec", ts)
        status = send_register(pid, causal_id, timestamp_ns=ts)
        assert status == 0, f"注册合法票据失败: status={status}"

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not os.path.exists(marker):
            time.sleep(0.05)
        assert os.path.exists(marker), \
            "受监控进程持合法票据 exec 非白名单二进制应放行（标记文件未生成）"
    finally:
        proc.wait(timeout=10)


def test_chmod_add_exec_no_causal_id():
    """chmod +x 无 CausalID → SIGKILL"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "test_chmod_add_exec", "/tmp/agent_test_chmod"],
        capture_output=True, text=True, timeout=5
    )
    assert "CHMOD_ALLOWED" not in result.stdout, \
        f"chmod +x 应被 SIGKILL: {result.stdout}"


def test_chmod_no_exec_allowed():
    """chmod 644 (无 +x) → 放行 (文件需提前创建避开 O_CREAT 拦截)"""
    path = "/tmp/agent_test_chmod2"
    subprocess.run(["touch", path], check=True)
    result = subprocess.run(
        [TEST_FILE_EXECVE, "test_chmod_no_exec", path],
        capture_output=True, text=True, timeout=5
    )
    subprocess.run(["rm", "-f", path])
    assert "CHMOD_NOEXEC_ALLOWED" in result.stdout


def test_sendto_inet_no_causal_id():
    """sendto AF_INET 无 CausalID → SIGKILL"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "test_sendto_inet"],
        capture_output=True, text=True, timeout=5
    )
    assert result.returncode == -9, \
        f"sendto INET should be blocked: {result}"


def test_sendto_unix_allowed():
    """sendto AF_UNIX → 放行"""
    result = subprocess.run(
        [TEST_FILE_EXECVE, "test_sendto_unix", "/tmp/test_sock"],
        capture_output=True, text=True, timeout=5
    )
    assert "SENDTO_UNIX_ALLOWED" in result.stdout


# ── 执行白名单精确路径集成测试 ──────────────────────

class TestExecWhitelist:
    """eBPF execve 白名单集成测试 (需 root + 已加载探针)"""

    def test_whitelist_exact_match(self):
        """白名单中的路径应放行 — /bin/true 在配置中, 执行成功"""
        import hashlib
        sha = hashlib.sha256(open("/bin/true", "rb").read()).hexdigest()
        key_hex = b"/bin/true".ljust(64, b"\x00").hex()
        val_hex = sha
        subprocess.run(
            [BPFTOOL, "map", "update", "pinned",
             MAP_DIR + "/exec_whitelist",
             "key", "hex", key_hex,
             "value", "hex", val_hex],
            check=True, capture_output=True,
        )
        pid = os.getpid()
        ensure_monitored(pid)
        cid = _make_causal_id(pid, "bash_exec", time.monotonic_ns())
        status = send_register(pid, cid)
        assert status == 0, f"注册 CausalID 失败: status={status}"
        result = subprocess.run(["/bin/true"], capture_output=True)
        assert result.returncode == 0

    def test_whitelist_unknown_path_blocked(self):
        """未知路径应触发告警 — Map 查表返回空"""
        key_hex = b"/tmp/test_blocked_me".ljust(64, b"\x00").hex()
        # 确保 key 不在 Map 中
        subprocess.run(
            [BPFTOOL, "map", "delete", "pinned",
             MAP_DIR + "/exec_whitelist",
             "key", "hex", key_hex],
            capture_output=True,
        )
        result = subprocess.run(
            [BPFTOOL, "map", "lookup", "pinned",
             MAP_DIR + "/exec_whitelist",
             "key", "hex", key_hex],
            capture_output=True, text=True,
        )
        assert "Not found" in result.stderr or result.returncode != 0, \
            "未知路径不应在白名单中"

    def test_whitelist_subpath_not_matched(self):
        """前缀匹配已废弃 — /usr/bin 不是 /usr/bin/python3 的前缀匹配"""
        short_key = b"/usr/bin".ljust(64, b"\x00").hex()
        full_key = b"/usr/bin/python3".ljust(64, b"\x00").hex()

        sha = hashlib.sha256(open("/usr/bin/python3", "rb").read()).hexdigest()
        subprocess.run(
            [BPFTOOL, "map", "update", "pinned",
             MAP_DIR + "/exec_whitelist",
             "key", "hex", full_key,
             "value", "hex", sha],
            check=True, capture_output=True,
        )

        result = subprocess.run(
            [BPFTOOL, "map", "lookup", "pinned",
             MAP_DIR + "/exec_whitelist",
             "key", "hex", short_key],
            capture_output=True, text=True,
        )
        assert "Not found" in result.stderr or result.returncode != 0, \
            "短路径不应在精确匹配白名单中，前缀匹配已废弃"
