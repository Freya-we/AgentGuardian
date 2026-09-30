#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== AgentGuardian E2E 验证 ==="
echo ""

ENGINE_PID=""

cleanup() {
    if [ -n "$ENGINE_PID" ]; then
        kill "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_for_engine() {
    local max_wait="${1:-30}"
    local elapsed=0
    until curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; do
        if [ "$elapsed" -ge "$max_wait" ]; then
            echo "审计引擎 启动超时 (${max_wait}s)" >&2
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

# 检查 审计引擎
if ! curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo "审计引擎 未运行，启动中..."
    cd "$PROJECT_DIR"
    uv run uvicorn src.engine.server:app --host 0.0.0.0 --port 8000 &
    ENGINE_PID=$!
    wait_for_engine 30
fi

echo "审计引擎: OK"

# 跑 E2E
cd "$PROJECT_DIR"
uv run python scripts/demo_e2e.py "$@"
