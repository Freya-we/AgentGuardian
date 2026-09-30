#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$PROJECT_DIR/src/ebpf"
GUARDIAN_DIR="$PROJECT_DIR/src/causal_guardian"
MAP_DIR="/sys/fs/bpf/agent_guardian"
SOCKET_PATH="/var/run/causal-guardian.sock"
LOADER_LOG="/tmp/ebpf-loader-$$.log"
GUARDIAN_LOG="/tmp/ebpf-guardian-$$.log"
LOADER_PID=""
GUARDIAN_PID=""

cleanup() {
    info "清理..."
    [ -n "$GUARDIAN_PID" ] && sudo kill "$GUARDIAN_PID" 2>/dev/null || true
    [ -n "$LOADER_PID" ] && sudo kill "$LOADER_PID" 2>/dev/null || true
    sleep 1
    sudo rm -f "$SOCKET_PATH"
    sudo rm -rf "$MAP_DIR"
    rm -f "$LOADER_LOG" "$GUARDIAN_LOG"
}
trap cleanup EXIT

# ── 前置检查 ──

echo "=== eBPF 集成测试环境检查 ==="
echo ""

if [ "$(uname -s)" != "Linux" ]; then
    error "需要 Linux 系统"
fi

KVER=$(uname -r | cut -d. -f1,2)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 8 ]; }; then
    error "内核版本 $KVER < 5.8，不支持 BPF CO-RE"
fi
info "内核版本: $KVER"

if ! command -v bpftool &>/dev/null; then
    error "bpftool 未安装"
fi
info "bpftool: $(which bpftool)"

if ! command -v clang &>/dev/null; then
    error "clang 未安装 (编译 BPF 需要)"
fi
info "clang: $(which clang)"

if ! mountpoint -q /sys/kernel/debug 2>/dev/null; then
    warn "debugfs 未挂载，尝试挂载..."
    sudo mount -t debugfs none /sys/kernel/debug || error "无法挂载 debugfs"
fi
info "debugfs: 已挂载"

if ! sudo -n true 2>/dev/null; then
    error "当前用户无 sudo 权限（需要加载 BPF 探针）"
fi
info "sudo: OK"

# CAP_BPF 检查 (Linux 5.8+ 加载 BPF 需要)
if capsh --has-p=CAP_BPF 2>/dev/null || capsh --has-p=CAP_SYS_ADMIN 2>/dev/null; then
    info "BPF capability: OK"
elif [ "$(id -u)" -eq 0 ]; then
    info "以 root 运行"
else
    warn "缺少 CAP_BPF/CAP_SYS_ADMIN capability，loader 可能加载失败"
    warn "运行: sudo setcap cap_bpf,cap_sys_admin=ep $EBPF_DIR/loader"
fi

# ── 编译 ──

info "编译 eBPF 探针..."
make -C "$EBPF_DIR" clean >/dev/null 2>&1 || true
make -C "$EBPF_DIR" || error "eBPF 探针编译失败"

info "编译 causal-guardian..."
make -C "$GUARDIAN_DIR" clean >/dev/null 2>&1 || true
make -C "$GUARDIAN_DIR" || error "causal-guardian 编译失败"

info "编译测试二进制..."
gcc -o "$PROJECT_DIR/tests/integration/test_execve" \
    "$PROJECT_DIR/tests/integration/test_execve.c" -lbpf \
    || error "test_execve 编译失败"
gcc -o "$PROJECT_DIR/tests/integration/test_file_execve" \
    "$PROJECT_DIR/tests/integration/test_file_execve.c" -lbpf \
    || error "test_file_execve 编译失败"

# ── 加载探针 ──

info "加载 eBPF 探针 (测试二进制自注册 TGID)..."
sudo "$EBPF_DIR/loader" 2>"$LOADER_LOG" &
LOADER_PID=$!
sleep 2

if ! kill -0 "$LOADER_PID" 2>/dev/null; then
    echo "--- loader stderr ---"
    cat "$LOADER_LOG" 2>/dev/null || true
    echo "--- dmesg (最后 20 行) ---"
    sudo dmesg | tail -20
    error "loader 进程已退出，诊断信息如上"
fi

if [ ! -d "$MAP_DIR" ]; then
    error "BPF Map 目录 $MAP_DIR 未创建，loader 可能加载失败"
fi
info "BPF Maps 已固定到 $MAP_DIR"

# ── 启动 causal-guardian ──

info "启动 causal-guardian..."
sudo "$GUARDIAN_DIR/causal-guardian" 2>"$GUARDIAN_LOG" &
GUARDIAN_PID=$!
sleep 1

if ! kill -0 "$GUARDIAN_PID" 2>/dev/null; then
    echo "--- guardian stderr ---"
    cat "$GUARDIAN_LOG" 2>/dev/null || true
    error "causal-guardian 进程已退出"
fi

echo "--- guardian stdout (启动信息) ---"
cat "$GUARDIAN_LOG" 2>/dev/null | head -5 || true

# 等待 socket 就绪
for i in $(seq 1 10); do
    if [ -S "$SOCKET_PATH" ]; then
        break
    fi
    sleep 0.3
done
if [ ! -S "$SOCKET_PATH" ]; then
    error "causal-guardian socket $SOCKET_PATH 未创建"
fi
info "causal-guardian 就绪"

# ── 运行集成测试 (测试二进制已自注册 TGID) ──

info "运行集成测试..."
echo ""

cd "$PROJECT_DIR"
uv run pytest tests/integration/test_ebpf_chain.py -v --tb=long
TEST_EXIT=$?

echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
    info "全部 eBPF 集成测试通过"
else
    echo ""
    warn "集成测试失败 (exit=$TEST_EXIT)"
    warn "常见原因:"
    warn "  1. eBPF 探针未正确加载 → 查看 sudo dmesg | tail -30"
    warn "  2. causal-guardian socket 权限问题 → ls -la $SOCKET_PATH"
    warn "  3. BPF Map 固定路径不存在 → ls $MAP_DIR/"
    warn "  4. 测试二进制缺少 CAP_BPF → getcap tests/integration/test_execve"
    echo ""
    echo "--- causal-guardian 日志 ---"
    cat "$GUARDIAN_LOG" 2>/dev/null || echo "(无)"
    echo "--- loader 日志 ---"
    cat "$LOADER_LOG" 2>/dev/null || echo "(无)"
    exit 1
fi
