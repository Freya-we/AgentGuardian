# src/frida/bridge.py
import hashlib
import json
import os
import secrets
import select
import socket
import struct
import threading
import time

import httpx

try:
    import frida
except ImportError:  # frida 为可选依赖，仅真实插桩时需要；GadgetBridge 纯 TCP 模式不依赖
    frida = None

RUNTIME_PYTHON = "python"
RUNTIME_NODE = "node"


class FridaBridge:
    """Frida ↔ 审计引擎 ↔ causal-guardian 通信桥"""

    def __init__(self, audit_engine_url: str = "http://localhost:8000",
                 runtime: str = RUNTIME_PYTHON):
        self.audit_engine_url = audit_engine_url
        self.runtime = runtime
        self.host_pid = self._get_host_pid()
        self.session_id = os.environ.get("AGENT_SESSION_ID", "default")
        self.sock = None
        self._input_messages = ""
        self._system_prompt = ""
        self._last_http_call = None
        self._script = None

    # ── PID ──────────────────────────────────────────

    def _get_host_pid(self) -> int:
        """从 /proc/self/status 获取宿主机视角 PID（NSpid 第二列）"""
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("NSpid:"):
                        parts = line.split()
                        if len(parts) >= 3:
                            return int(parts[2])  # 宿主机 PID
                        return int(parts[1])      # 无 namespace，即自身 PID
        except Exception:
            pass
        return os.getpid()

    # ── 审计引擎通信 ─────────────────────────────────

    async def request_causal_id(self, tool_name: str, params: str,
                                input_messages: str) -> dict:
        """调审计引擎签名端点"""
        params_hash = hashlib.sha256(params.encode()).hexdigest()
        async with httpx.AsyncClient(timeout=0.1) as client:  # 100ms 硬超时
            try:
                resp = await client.post(
                    f"{self.audit_engine_url}/api/v1/causal-id/sign",
                    json={
                        "pid": self.host_pid,
                        "tool_name": tool_name,
                        "params_hash": params_hash,
                        "params": params,
                        "input_messages": input_messages,
                        "session_id": self.session_id,
                    },
                )
                return resp.json()
            except httpx.TimeoutException:
                return {"causal_id": None, "decision": "allow",
                        "reason": "timeout", "mode": "ask"}

    # ── Unix Socket ──────────────────────────────────

    def _connect_socket(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(0.05)  # 50ms
        self.sock.connect("/var/run/causal-guardian.sock")

    def _send_causal_id(self, causal_id: bytes, tool_name: str) -> bool:
        """向 causal-guardian 注册 CausalID，返回是否成功"""
        if self.sock is None:
            try:
                self._connect_socket()
            except Exception:
                return False
        name_bytes = tool_name.encode()[:63].ljust(64, b'\x00')
        msg = struct.pack("<BQ32sQ64s", 0x01, self.host_pid,
                          causal_id, time.time_ns(), name_bytes)
        try:
            self.sock.sendall(msg)
            ack = self.sock.recv(2)
            return ack[1] == 0  # status=0 表示成功
        except Exception:
            self.sock = None
            return False

    # ── 消息处理 ─────────────────────────────────────

    def on_message(self, message: dict, data: bytes) -> None:
        """Frida JS send() 回调"""
        msg_type = message.get("type", "")

        if msg_type == "context":
            self._input_messages = message.get("input_messages", "")

        elif msg_type == "tool_call":
            # 工具级 Hook 不阻塞，仅记录
            pass

        elif msg_type == "system_prompt":
            self._system_prompt = message.get("content", "")

        elif msg_type == "http_outbound":
            method = message.get("method", "")
            url = message.get("url", "")
            self._last_http_call = {"method": method, "url": url}

        elif msg_type == "blocking_request":
            # JS Hook 发起的同步阻塞请求 → 等待审计引擎响应后返回决策
            import asyncio
            tool_name = message.get("tool_name", "unknown")
            params = message.get("params", "")
            input_msgs = message.get("input_messages", self._input_messages)

            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(
                    self.request_causal_id(tool_name, params, input_msgs)
                )
                loop.close()
            except Exception:
                result = {"causal_id": None, "decision": "allow",
                          "reason": "bridge_error", "mode": "ask"}

            causal_id_str = None
            if result["decision"] == "allow" and result.get("causal_id"):
                causal_id_raw = bytes.fromhex(result["causal_id"])
                if self._send_causal_id(causal_id_raw, tool_name):
                    causal_id_str = result["causal_id"]
                else:
                    causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)
            else:
                causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)

            self._script.post({
                "type": "causal_id_response",
                "request_id": message["request_id"],
                "causal_id": causal_id_str,
                "decision": result.get("decision", "allow"),
                "reason": result.get("reason", ""),
            })

        elif msg_type == "request_causal_id":
            import asyncio
            tool_name = message.get("tool_name", "unknown")
            params = message.get("params", "")
            input_msgs = message.get("input_messages", self._input_messages)

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self.request_causal_id(tool_name, params, input_msgs)
            )

            causal_id_str = None
            if result["decision"] == "allow" and result.get("causal_id"):
                causal_id_raw = bytes.fromhex(result["causal_id"])
                if self._send_causal_id(causal_id_raw, tool_name):
                    causal_id_str = result["causal_id"]
                else:
                    causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)
            else:
                causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)

            self._script.post({
                "type": "causal_id_response",
                "request_id": message["request_id"],
                "causal_id": causal_id_str,
            })

    # ── 脚本加载 ─────────────────────────────────────

    def _load_scripts(self, session: "frida.core.Session") -> list:
        """根据 runtime 加载对应的 Frida JS 脚本"""
        scripts = []
        if self.runtime == RUNTIME_PYTHON:
            with open("src/frida/langchain_hooks.js") as f:
                scripts.append(session.create_script(f.read()))
            with open("src/frida/lowlevel_hooks.js") as f:
                scripts.append(session.create_script(f.read()))
        elif self.runtime == RUNTIME_NODE:
            with open("src/frida/node_lowlevel.js") as f:
                scripts.append(session.create_script(f.read()))
        else:
            raise ValueError(f"Unknown runtime: {self.runtime}")
        return scripts


# ── TCP Gadget 通信 ────────────────────────────────────

GADGET_HOST = "127.0.0.1"
GADGET_PORT = 27042
PSK_PATH = "/etc/agent-guardian/frida/psk"
AUTH_TIMEOUT = 3.0  # 秒


def _load_psk() -> str:
    """读取预共享密钥"""
    try:
        with open(PSK_PATH) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def _recv_msg(sock: socket.socket, timeout: float | None = None) -> dict | None:
    """接收一条长度前缀的 JSON 消息"""
    if timeout is not None:
        ready = select.select([sock], [], [], timeout)
        if not ready[0]:
            return None
    try:
        raw = sock.recv(4)
    except (TimeoutError, ConnectionError):
        return None
    if len(raw) < 4:
        return None
    length = struct.unpack(">I", raw)[0]
    if length > 65536:  # 64KB 上限，防畸形数据
        return None
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
        except (TimeoutError, ConnectionError):
            return None
        if not chunk:
            return None
        data += chunk
    return json.loads(data)


def _send_msg(sock: socket.socket, msg: dict) -> bool:
    """发送一条长度前缀的 JSON 消息"""
    try:
        payload = json.dumps(msg, ensure_ascii=False).encode()
        header = struct.pack(">I", len(payload))
        sock.sendall(header + payload)
        return True
    except (OSError, ConnectionError):
        return False


def _send_causal_id_unix(causal_id: bytes, tool_name: str, pid: int) -> bool:
    """向 causal-guardian 注册 CausalID"""
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        sock.connect("/var/run/causal-guardian.sock")
        name_bytes = tool_name.encode()[:63].ljust(64, b'\x00')
        msg = struct.pack("<BQ32sQ64s", 0x01, pid,
                          causal_id, time.time_ns(), name_bytes)
        sock.sendall(msg)
        ack = sock.recv(2)
        return ack[1] == 0
    except Exception:
        return False
    finally:
        if sock:
            sock.close()


async def _http_sign_request(audit_url: str, pid: int, tool_name: str,
                              params_hash: str, params: str,
                              input_messages: str, session_id: str) -> dict:
    """HTTP POST 到审计引擎签名端点"""
    import httpx
    async with httpx.AsyncClient(timeout=0.1) as client:
        try:
            resp = await client.post(
                f"{audit_url}/api/v1/causal-id/sign",
                json={
                    "pid": pid,
                    "tool_name": tool_name,
                    "params_hash": params_hash,
                    "params": params,
                    "input_messages": input_messages,
                    "session_id": session_id,
                },
            )
            return resp.json()
        except httpx.TimeoutException:
            return {"causal_id": None, "decision": "allow",
                    "reason": "timeout", "mode": "ask"}


def handle_client(sock: socket.socket, audit_url: str) -> None:
    """处理单个 Gadget 连接: PSK 认证 → 消息循环"""
    expected_psk = _load_psk()
    client_pid = 0

    # 阶段 1: PSK 认证
    auth_msg = _recv_msg(sock, timeout=AUTH_TIMEOUT)
    if auth_msg is None:
        print("[GadgetBridge] 认证超时，断开连接")
        sock.close()
        return

    if auth_msg.get("type") != "auth":
        print(f"[GadgetBridge] 首条消息非 auth，断开: {auth_msg.get('type')}")
        sock.close()
        return

    if expected_psk and auth_msg.get("psk") != expected_psk:
        print("[GadgetBridge] PSK 不匹配，断开连接")
        _send_msg(sock, {"type": "auth_result", "status": "rejected"})
        sock.close()
        return

    # PSK 验证通过
    client_pid = auth_msg.get("pid", 0)
    _send_msg(sock, {"type": "auth_result", "status": "ok"})
    print(f"[GadgetBridge] client 已认证, pid={client_pid}")

    # 阶段 2: 消息循环
    import asyncio
    import hashlib
    import os
    import secrets

    audit_session = os.environ.get("AGENT_SESSION_ID", "default")

    try:
        while True:
            msg = _recv_msg(sock, timeout=30.0)
            if msg is None:
                break

            msg_type = msg.get("type", "")

            if msg_type in ("blocking_request", "request_causal_id"):
                tool_name = msg.get("tool_name", "unknown")
                params = msg.get("params", "")
                input_msgs = msg.get("input_messages", "")

                params_hash = hashlib.sha256(params.encode()).hexdigest()
                try:
                    loop = asyncio.new_event_loop()
                    resp = loop.run_until_complete(
                        _http_sign_request(audit_url, client_pid, tool_name,
                                          params_hash, params, input_msgs, audit_session)
                    )
                    loop.close()
                except Exception as e:
                    resp = {"causal_id": None, "decision": "allow",
                            "reason": f"bridge_error: {e}", "mode": "ask"}

                causal_id_str = None
                if resp.get("decision") == "allow" and resp.get("causal_id"):
                    causal_id_raw = bytes.fromhex(resp["causal_id"])
                    if _send_causal_id_unix(causal_id_raw, tool_name, client_pid):
                        causal_id_str = resp["causal_id"]
                    else:
                        causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)
                else:
                    causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)

                _send_msg(sock, {
                    "type": "causal_id_response",
                    "request_id": msg.get("request_id", ""),
                    "causal_id": causal_id_str,
                    "decision": resp.get("decision", "allow"),
                    "reason": resp.get("reason", ""),
                })

    except Exception as e:
        print(f"[GadgetBridge] 消息循环异常: {e}")
    finally:
        sock.close()
        print(f"[GadgetBridge] client pid={client_pid} 已断开")


class GadgetBridge:
    """Frida Gadget TCP server — 监听 Gadget 连接并转发审计请求"""

    def __init__(self, audit_engine_url: str = "http://localhost:8000"):
        self.audit_engine_url = audit_engine_url
        self._running = False
        self._server = None

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((GADGET_HOST, GADGET_PORT))
        self._server.listen(16)
        self._server.settimeout(1.0)
        self._running = True
        psk = _load_psk()
        print(f"[GadgetBridge] 监听 {GADGET_HOST}:{GADGET_PORT}, "
              f"PSK={'已设置' if psk else '未设置(开发模式)'}")
        while self._running:
            try:
                client, addr = self._server.accept()
                print(f"[GadgetBridge] 新连接: {addr}")
                t = threading.Thread(
                    target=handle_client,
                    args=(client, self.audit_engine_url),
                    daemon=True,
                )
                t.start()
            except TimeoutError:
                continue
            except Exception as e:
                if self._running:
                    print(f"[GadgetBridge] accept 异常: {e}")
                break

    def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()


if __name__ == "__main__":
    bridge = GadgetBridge()
    bridge.start()
