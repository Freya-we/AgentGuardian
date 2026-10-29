"""L1（eBPF 内核链）契约测试 — 防止已修复的四处断点回归。

不需要 root / Linux / 内核：前四条静态检查源码里"两侧必须一致"的约定，
最后一条用真实的 HmacSigner 证明"时间戳必须原样回传"不是可选项。

对应的问题（见 复现_key不一致/README.md）：
  断点①  引擎签名的时间戳没随票下发，bridge 自己重新取 → HMAC 必失败
  断点②  内核用 pid_tgid 查表、守护用纯 PID 写表 → 查表必 MISS
  断点③  写入墙上时钟、比较单调时钟 → 票一写就"过期"
  断点④  启动时不推送初始 session key → 前 30 秒验签用的是全零 key
"""

import hashlib
import pathlib
import time

from src.engine.hmac_signer import HmacSigner

ROOT = pathlib.Path(__file__).resolve().parents[1]
BPF_SRC = ROOT / "src" / "ebpf" / "execve_monitor.bpf.c"
SERVER_SRC = ROOT / "src" / "engine" / "server.py"
BRIDGE_SRC = ROOT / "src" / "frida" / "bridge.py"
KEYMGR_SRC = ROOT / "src" / "engine" / "key_manager.py"
GUARDIAN_SRC = ROOT / "src" / "causal_guardian" / "main.c"


def test_ebpf_uses_process_level_key():
    """断点②：内核侧必须用 tgid 作 causal_chain 的 key，与守护写入的纯 PID 对齐"""
    src = BPF_SRC.read_text(encoding="utf-8")
    assert "bpf_get_current_pid_tgid()" in src
    assert "__u64 key = ns_tgid();" in src, "缺少进程级 key 的声明"
    assert "&causal_chain, &key" in src, "查表未使用进程级 key"
    assert "&pid_tgid" not in src, "仍有以 pid_tgid 作 key 的查表/删除，必然 MISS"


def test_ebpf_avoids_signed_division():
    """BPF 不支持有符号除法/取模（clang: unsupported signed division）。

    修复前 fchmod 分支用 `int fd_val` 做 /100、/10、%10，导致整个 BPF 程序
    在 Linux 上根本编译不出来 —— 也就是说这层从来没被真正构建过。
    """
    src = BPF_SRC.read_text(encoding="utf-8")
    assert "int fd_val = (int)ctx->args[0];" not in src, "fd 仍用有符号 int，BPF 无法编译"
    assert "unsigned int fd_val = (unsigned int)ctx->args[0];" in src


def test_server_signs_with_monotonic_clock():
    """断点③：签名时间戳必须是单调时钟，与 bpf_ktime_get_ns() 同基准"""
    src = SERVER_SRC.read_text(encoding="utf-8")
    assert "now_ns = time.monotonic_ns()" in src
    assert "now_ns = time.time_ns()" not in src, "签名仍用墙上时钟，票据会被判为已过期"


def test_sign_response_carries_timestamp():
    """断点①：引擎必须把签名用的时间戳一并返回"""
    src = SERVER_SRC.read_text(encoding="utf-8")
    assert "timestamp_ns: int | None = None" in src, "SignResponse 缺少 timestamp_ns"
    assert "timestamp_ns=now_ns" in src, "签发响应未带上时间戳"


def test_bridge_echoes_engine_timestamp():
    """断点①：bridge 不得自己取时间戳，必须原样回传"""
    src = BRIDGE_SRC.read_text(encoding="utf-8")
    assert "causal_id, timestamp_ns, name_bytes" in src, "注册消息未使用引擎给的时间戳"
    assert "causal_id, time.time_ns()" not in src, "bridge 仍在自己取墙上时钟"


def test_key_manager_can_push_initial_keys():
    """断点④：KeyManager 必须提供"启动即推送"的入口"""
    src = KEYMGR_SRC.read_text(encoding="utf-8")
    assert "def push_current(self) -> bool:" in src
    server_src = SERVER_SRC.read_text(encoding="utf-8")
    assert "push_current()" in server_src, "服务启动时没有推送初始 session key"


def test_hmac_payload_requires_exact_timestamp():
    """行为验证：时间戳差 1ns，验签即失败 —— 所以"原样回传"是硬要求"""
    signer = HmacSigner()
    key = b"k" * 32
    ts = time.monotonic_ns()
    causal_id = signer.sign(key, 1234, "read_file", ts)

    assert signer.verify(key, causal_id, 1234, "read_file", ts) is True
    assert signer.verify(key, causal_id, 1234, "read_file", ts + 1) is False
    assert signer.verify(key, causal_id, 1234, "read_file", ts - 1) is False

def test_ebpf_is_namespace_aware():
    """P0-6：容器/WSL 里 init 命名空间 pid 与本地 pid 不同（实测差 688）。

    必须用 bpf_get_ns_current_pid_tgid() 把 pid 换算到目标命名空间，
    否则 monitored_tgid / causal_chain 的 key 永远查不到。
    """
    src = BPF_SRC.read_text(encoding="utf-8")
    assert "bpf_get_ns_current_pid_tgid" in src, "未做命名空间换算"
    assert "ns_id_map" in src, "缺少 /proc dev/ino 的 map"
    assert "__u64 key = ns_tgid();" in src, "key 未走命名空间换算"
    # 回退分支仍然保留，保证未配置时行为不变
    assert "return bpf_get_current_pid_tgid() >> 32;" in src


def test_bridge_pushes_namespace_id():
    """P0-6：bridge 必须把 /proc 的 dev/ino 推给 guardian"""
    src = BRIDGE_SRC.read_text(encoding="utf-8")
    assert "_send_ns_update" in src
    assert '0x03' in src and 'st_dev' in src and 'st_ino' in src
    assert 'os.stat("/proc/self/ns/pid")' in src, "dev/ino 必须取 pid 命名空间的 nsfs inode"
    # 不能再靠 NSpid 的列号猜 pid（旧实现 parts[2] 就是那个 bug）
    assert "return int(parts[2])" not in src, "仍在用 NSpid 列号猜 pid"
    assert "return os.getpid()" in src, "应直接返回本命名空间 pid"


def test_hmac_binds_params_hash():
    """P1-2：票据必须绑定参数指纹 —— 同一 pid/tool/timestamp、
    不同 params_hash 的票据不能互换，堵住"换内容重放"的口子。"""
    signer = HmacSigner()
    key = b"k" * 32
    ts = time.monotonic_ns()
    h_benign = hashlib.sha256(b"SELECT 1").hexdigest()
    h_evil = hashlib.sha256(b"DROP TABLE users").hexdigest()
    causal_id = signer.sign(key, 1234, "db_query", ts, params_hash=h_benign)

    assert signer.verify(key, causal_id, 1234, "db_query", ts, params_hash=h_benign)
    assert not signer.verify(key, causal_id, 1234, "db_query", ts, params_hash=h_evil)
    assert not signer.verify(key, causal_id, 1234, "db_query", ts)


def test_server_signs_with_own_params_hash():
    """P1-2：引擎必须自行重算 sha256(params)，不得信任请求体里的 params_hash。

    否则攻击者可以提交"干净"的 params 通过内容审查、却附带恶意内容的
    hash 换票，审查就被整体绕过了。"""
    src = SERVER_SRC.read_text(encoding="utf-8")
    assert 'hashlib.sha256(req.params.encode("utf-8")).hexdigest()' in src, \
        "引擎未自行重算 params_hash"
    assert "params_hash=params_hash" in src, "签名调用未绑定参数指纹"
    handler = src[src.index("async def handle_sign_request"):]
    handler = handler[:handler.index("\n@app.", 1)]
    assert "req.params_hash" not in handler, "签名路径仍在消费请求体的 params_hash"


def test_bridge_registers_params_hash():
    """P1-2：注册消息必须携带与签名一致的 params_hash（协议两端同格式）"""
    src = BRIDGE_SRC.read_text(encoding="utf-8")
    assert '"<BQ32sQ64s64s"' in src, "注册消息未带 params_hash 字段"
    assert "hashlib.sha256(params.encode()).hexdigest()" in src, \
        "bridge 未按 sha256(params) 计算注册用指纹"
    # guardian 侧 payload 重建必须含 5 个字段（pid|tool|hash|ts|ttl）
    gsrc = GUARDIAN_SRC.read_text(encoding="utf-8")
    assert '"%llu|%s|%s|%llu|%llu"' in gsrc, "guardian 重建 payload 未含 params_hash"


def test_guardian_rejects_unmonitored_pid():
    """P0-1b：guardian 只给 monitored_tgid（root 维护，0600）内的 pid 写票据，
    持 token 的调用方不能再给任意 pid 铺票。"""
    gsrc = GUARDIAN_SRC.read_text(encoding="utf-8")
    assert 'open_bpf_map("monitored_tgid"' in gsrc, "guardian 未打开监控名单 map"
    assert "ack->status = 3" in gsrc, "缺少 pid_not_monitored 拒绝码"
    assert "bpf_map_lookup_elem(monitored_fd" in gsrc, "注册路径未查监控名单"


def test_server_validates_pid():
    """P0-1b：签名端点必须拒绝非法/不存在的 pid"""
    src = SERVER_SRC.read_text(encoding="utf-8")
    assert "if req.pid <= 0:" in src
    assert "_pid_exists(req.pid)" in src, "签名路径未做 pid 存在性检查"

