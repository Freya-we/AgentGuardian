#!/usr/bin/env bash
# scripts/setup_gadget.sh — 一键部署 Frida Gadget
set -euo pipefail

FRIDA_VERSION="${FRIDA_VERSION:-16.5.9}"
GADGET_DIR="${GADGET_DIR:-/etc/agent-guardian/frida}"
GADGET_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-linux-x86_64.so.xz"

echo "=== AgentGuardian Frida Gadget 部署 ==="
echo "Frida 版本: ${FRIDA_VERSION}"
echo "目标目录:   ${GADGET_DIR}"
echo ""

# 1. 创建目录
sudo mkdir -p "${GADGET_DIR}"

# 2. 下载 frida-gadget.so (如不存在)
if [ ! -f "${GADGET_DIR}/frida-gadget.so" ]; then
    echo "[1/4] 下载 frida-gadget.so ..."
    TMP_XZ=$(mktemp --suffix=.so.xz)
    curl -fSL "${GADGET_URL}" -o "${TMP_XZ}"
    unxz "${TMP_XZ}"
    sudo mv "${TMP_XZ%.xz}" "${GADGET_DIR}/frida-gadget.so"
    sudo chmod 644 "${GADGET_DIR}/frida-gadget.so"
    echo "  完成: ${GADGET_DIR}/frida-gadget.so"
else
    echo "[1/4] frida-gadget.so 已存在，跳过下载"
fi

# 3. 生成 PSK
echo "[2/4] 生成预共享密钥 ..."
if [ ! -f "${GADGET_DIR}/psk" ]; then
    python3 -c "import secrets; print(secrets.token_hex(16))" | sudo tee "${GADGET_DIR}/psk" > /dev/null
    sudo chmod 600 "${GADGET_DIR}/psk"
    echo "  完成: ${GADGET_DIR}/psk"
else
    echo "  PSK 已存在，跳过"
fi

PSK=$(sudo cat "${GADGET_DIR}/psk")

# 4. 复制 Hook 脚本
echo "[3/4] 复制 Hook 脚本 ..."
sudo cp "$(dirname "$0")/../src/frida/lowlevel_hooks.js" "${GADGET_DIR}/hooks.js"
sudo chmod 644 "${GADGET_DIR}/hooks.js"
echo "  完成: ${GADGET_DIR}/hooks.js"

# 5. 生成 Gadget 配置
echo "[4/4] 生成 Gadget 配置 ..."
sudo tee "${GADGET_DIR}/frida-gadget.config.json" > /dev/null <<CONF
{
  "interaction": {
    "type": "connect",
    "address": "127.0.0.1:27042",
    "on_port_conflict": "fail",
    "on_load": "wait"
  },
  "script": {
    "type": "file",
    "path": "${GADGET_DIR}/hooks.js",
    "parameters": {
      "psk": "${PSK}"
    }
  }
}
CONF
sudo chmod 644 "${GADGET_DIR}/frida-gadget.config.json"
echo "  完成: ${GADGET_DIR}/frida-gadget.config.json"

echo ""
echo "=== 部署完成 ==="
echo ""
echo "使用方法:"
echo "  export LD_PRELOAD=${GADGET_DIR}/frida-gadget.so"
echo "  python your_agent.py"
echo ""
echo "或 Dockerfile:"
echo "  ENV LD_PRELOAD=${GADGET_DIR}/frida-gadget.so"
echo "  COPY frida-gadget.so frida-gadget.config.json hooks.js psk ${GADGET_DIR}/"
