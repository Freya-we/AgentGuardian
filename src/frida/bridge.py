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

# 引擎 API 令牌：与 server.py 的 _load_api_token() 同源
ENGINE_TOKEN_PATH = "/etc/agent-guardian/engine.token"
# 签名请求超时。修复前是 100ms 硬超时且超时按 allow 处理（P1-9），
# 现改为可配置 + 超时 fail-closed。
_ENGINE_TIMEOUT_S = float(os.environ.get("AGENT_GUARDIAN_SIGN_TIMEOUT", "0.3"))


def _load_engine_token() -> str:
    token = os.environ.get("AGENT_GUARDIAN_TOKEN", "").strip()
    if token:
        return token
    try:
        with open(ENGINE_TOKEN_PATH, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


class FridaBridge:
    """Frida ↔ 审计引擎 ↔ causal-guardian 通信桥"""

    def __init__(self, audit_engine_url: str = "http://localhost:8000",
                 runtime: str = RUNTIME_PYTHON):
        self.audit_engine_url = audit_engine_url
        self.runtime = runtime
        self.host_pid = self._get_host_pid()
        self.session_id = os.environ.get("AGENT_SESSION_ID", "default")
        self.sock = None
        self._ns_sent = False
        self._input_messages = ""
        self._system_prompt = ""
        self._last_http_call = None
        self._script = None

    # ── PID ──────────────────────────────────────────

    def _get_host_pid(self) -> int:
        """返回**当前命名空间内**的 PID —— 这才是 eBPF 侧换算后能对上的值。

        历史上这里试图从 /proc/self/status 的 NSpid 里取"宿主机 PID"，但：
          · 进程与读取者在同一命名空间时，NSpid 只有一列，取到的仍是本地 PID；
          · 不同命名空间层级下列数不同，parts[2] 的含义不稳定；
          · bpf_get_current_pid_tgid() 返回的永远是 init 命名空间的 PID，
            与这里的猜测必然对不上（WSL 实测恒定相差 688）。

        正确做法见 _send_ns_update()：把 /proc 的 dev/ino 交给内核，
        由 bpf_get_ns_current_pid_tgid() 完成换算。
        """
        return os.getpid()

    # ── 命名空间标识（P0-6）──────────────────────────

    def _send_ns_update(self) -> bool:
        """把 /proc 挂载点的 dev/ino 推给 causal-guardian。

        内核据此用 bpf_get_ns_current_pid_tgid() 换算出"本命名空间内的 pid"，
        与我们发送的 pid 一致。Docker / k8s / WSL 下必需。

        实测（WSL2）：不写 ns_id 或写 /proc 的 dev/ino 时，监控命中率都是 0；
        写 /proc/self/ns/pid 的 dev/ino 后命中（passed=1）。
        """
        try:
            # 注意：必须取 pid 命名空间的 nsfs inode（/proc/self/ns/pid），
            # 而不是 /proc 挂载点本身。实测用 /proc 的 dev/ino 时命中率仍为 0。
            st = os.stat("/proc/self/ns/pid")
        except OSError:
            return False
        try:
            if self.sock is None:
                self._connect_socket()
            self.sock.sendall(struct.pack("<BQQ", 0x03, st.st_dev, st.st_ino))
            ack = self.sock.recv(2)
            return len(ack) == 2 and ack[1] == 0
        except Exception:
            return False

    # ── 审计引擎通信 ─────────────────────────────────

    async def request_causal_id(self, tool_name: str, params: str,
                                input_messages: str) -> dict:
        """调审计引擎签名端点"""
        params_hash = hashlib.sha256(params.encode()).hexdigest()
        headers = {}
        token = _load_engine_token()
        if token:
            headers["X-Guardian-Token"] = token
        async with httpx.AsyncClient(timeout=_ENGINE_TIMEOUT_S) as client:
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
                    headers=headers,
                )
                if resp.status_code != 200:
                    # 401/5xx 不能当成"允许"，否则鉴权失效会被静默吞掉
                    return {"causal_id": None, "decision": "block",
                            "reason": f"engine_http_{resp.status_code}",
                            "mode": "ask"}
                return resp.json()
            except Exception as e:  # 超时/连接失败/解析失败
                # fail-closed：拿不到决策就不放行（原实现返回 allow，P1-9）
                return {"causal_id": None, "decision": "block",
                        "reason": f"engine_unavailable: {type(e).__name__}",
                        "mode": "ask"}

    # ── Unix Socket ──────────────────────────────────

    def _connect_socket(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(0.05)  # 50ms
        self.sock.connect("/var/run/causal-guardian.sock")

    def _send_causal_id(self, causal_id: bytes, tool_name: str,
                        timestamp_ns: int, params_hash: str) -> bool:
        """向 causal-guardian 注册 CausalID，返回是否成功。

        timestamp_ns 必须是引擎签名时用的那个值：guardian 会用
        "pid|tool|params_hash|ts|ttl" 重建 HMAC payload 验签，自己另取时间
        必然失败（P0-1 断点①）；params_hash 必须与签发时 sha256(params)
        一致，否则验签同样失败（P1-2）。
        """
        if self.sock is None:
            try:
                self._connect_socket()
            except Exception:
                return False
        if not self._ns_sent:
            # 首次注册前先把命名空间标识推过去，否则内核算不出本空间的 pid
            self._ns_sent = self._send_ns_update()
        name_bytes = tool_name.encode()[:63].ljust(64, b'\x00')
        hash_bytes = params_hash.encode()[:64].ljust(64, b'\x00')
        msg = struct.pack("<BQ32sQ64s64s", 0x01, self.host_pid,
                          causal_id, timestamp_ns, name_bytes, hash_bytes)
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
            except Exception as e:
                # fail-closed：桥接出错时不能假装"允许"（P1-9）
                result = {"causal_id": None, "decision": "block",
                          "reason": f"bridge_error: {type(e).__name__}",
                          "mode": "ask"}

            causal_id_str = None
            # 注册消息里的 params_hash 必须与引擎签名时的一致（P1-2），
            # 引擎按 sha256(params) 重算，这里用同一个算法。
            register_hash = hashlib.sha256(params.encode()).hexdigest()
            ts_ns = result.get("timestamp_ns")
            if ts_ns is None:
                # 引擎没给时间戳（旧版本/异常）→ 用单调时钟兜底，并明确记录
                ts_ns = time.monotonic_ns()
            if result.get("decision") == "allow" and result.get("causal_id"):
                causal_id_raw = bytes.fromhex(result["causal_id"])
                if self._send_causal_id(causal_id_raw, tool_name, ts_ns, register_hash):
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
            register_hash = hashlib.sha256(params.encode()).hexdigest()
            ts_ns = result.get("timestamp_ns")
            if ts_ns is None:
                # 引擎没给时间戳（旧版本/异常）→ 用单调时钟兜底，并明确记录
                ts_ns = time.monotonic_ns()
            if result.get("decision") == "allow" and result.get("causal_id"):
                causal_id_raw = bytes.fromhex(result["causal_id"])
                if self._send_causal_id(causal_id_raw, tool_name, ts_ns, register_hash):
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


def _send_causal_id_unix(causal_id: bytes, tool_name: str, pid: int,
                         timestamp_ns: int, params_hash: str) -> bool:
    """向 causal-guardian 注册 CausalID

    timestamp_ns / params_hash 必须与引擎签名时的值一致（P0-1 断点① / P1-2）"""
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        sock.connect("/var/run/causal-guardian.sock")
        name_bytes = tool_name.encode()[:63].ljust(64, b'\x00')
        hash_bytes = params_hash.encode()[:64].ljust(64, b'\x00')
        msg = struct.pack("<BQ32sQ64s64s", 0x01, pid,
                          causal_id, timestamp_ns, name_bytes, hash_bytes)
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
    headers = {}
    token = _load_engine_token()
    if token:
        headers["X-Guardian-Token"] = token
    async with httpx.AsyncClient(timeout=_ENGINE_TIMEOUT_S) as client:
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
                headers=headers,
            )
            if resp.status_code != 200:
                return {"causal_id": None, "decision": "block",
                        "reason": f"engine_http_{resp.status_code}", "mode": "ask"}
            return resp.json()
        except Exception as e:
            # fail-closed（P1-9）
            return {"causal_id": None, "decision": "block",
                    "reason": f"engine_unavailable: {type(e).__name__}",
                    "mode": "ask"}


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
                    # fail-closed（P1-9）
                    resp = {"causal_id": None, "decision": "block",
                            "reason": f"bridge_error: {type(e).__name__}",
                            "mode": "ask"}

                causal_id_str = None
                ts_ns = resp.get("timestamp_ns")
                if ts_ns is None:
                    ts_ns = time.monotonic_ns()
                if resp.get("decision") == "allow" and resp.get("causal_id"):
                    causal_id_raw = bytes.fromhex(resp["causal_id"])
                    if _send_causal_id_unix(causal_id_raw, tool_name,
                                            client_pid, ts_ns, params_hash):
                        causal_id_str = resp["causal_id"]
                    else:
                        causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)
                else:
                    causal_id_str = "UNVERIFIED_" + secrets.token_hex(8)

                _send_msg(sock, {
                    "type": "causal_id_response",
                    "request_id": msg.get("request_id", ""),
                    "causal_id": causal_id_str,
                    "decision": resp.get("decision", "block"),
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
