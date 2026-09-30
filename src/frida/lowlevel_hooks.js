// src/frida/lowlevel_hooks.js
// 底层系统调用 Hook，阻塞等待审计引擎 CausalID 决策后放行/阻断

// ── PSK 认证 + PID 上报 (Gadget 模式) ──
(function authHandshake() {
    var PSK = "";
    try {
        // Gadget 模式下 config 对象由 frida-gadget 注入
        if (typeof config !== "undefined" && config && config.parameters) {
            PSK = config.parameters.psk || "";
        }
    } catch(e) {}

    var pid = 0;
    try {
        pid = Process.getCurrentPid();
    } catch(e) {
        pid = 0;
    }

    send({
        type: "auth",
        psk: PSK,
        pid: pid
    });
})();

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

var pendingCallbacks = {};
var BLOCKING_TIMEOUT_MS = 100;  // 硬超时

// ── 全局 recv: 接收 Python bridge 的 causal_id_response ──
recv(function(msg) {
    if (msg.type === "causal_id_response") {
        var cb = pendingCallbacks[msg.request_id];
        if (cb) {
            cb.causal_id = msg.causal_id;
            cb.decision = msg.decision;
            cb.reason = msg.reason;
            cb.resolved = true;
        }
    }
});

// ── 辅助: 发送 blocking_request 并阻塞等待响应 ──
function blockingRequestCausalId(toolName, params) {
    var requestId = generateUUID();
    pendingCallbacks[requestId] = {
        causal_id: null,
        decision: null,
        reason: "",
        resolved: false
    };

    send({
        type: "blocking_request",
        tool_name: toolName,
        params: String(params || "").substring(0, 256),
        request_id: requestId
    });

    // 自旋等待，每次 2ms，最长 100ms
    var start = Date.now();
    while (!pendingCallbacks[requestId].resolved &&
           (Date.now() - start) < BLOCKING_TIMEOUT_MS) {
        Thread.sleep(0.002);
    }

    var result = pendingCallbacks[requestId];
    delete pendingCallbacks[requestId];

    // 超时降级: 放行但打标 UNVERIFIED (eBPF 白名单兜底)
    if (!result.resolved) {
        return { causal_id: "UNVERIFIED_TIMEOUT", decision: "allow",
                 reason: "timeout", resolved: false };
    }
    return result;
}

// ── Hook 1: subprocess.Popen.__init__ ──
try {
    var SubprocessPopen = Python.use("subprocess.Popen");
    SubprocessPopen.$init.implementation = function() {
        var cmd = "";
        try {
            if (arguments.length > 0) cmd = JSON.stringify(arguments[0]);
        } catch(e) { cmd = String(arguments[0] || ""); }

        var result = blockingRequestCausalId("bash_exec", cmd);

        if (result.decision === "block") {
            throw new Error("AgentGuardian BLOCK: " + (result.reason || "策略拒绝"));
        }
        return this.$init.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "subprocess.Popen.__init__", error: e.message});
}

// ── Hook 2: os.system ──
try {
    var OsModule = Python.use("os");
    OsModule.system.implementation = function(command) {
        var result = blockingRequestCausalId("bash_exec", String(command));
        if (result.decision === "block") {
            throw new Error("AgentGuardian BLOCK: " + (result.reason || "策略拒绝"));
        }
        return this.system.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "os.system", error: e.message});
}

// ── Hook 3: os.popen ──
try {
    var OsModule2 = Python.use("os");
    OsModule2.popen.implementation = function(command) {
        var result = blockingRequestCausalId("bash_exec", String(command));
        if (result.decision === "block") {
            throw new Error("AgentGuardian BLOCK: " + (result.reason || "策略拒绝"));
        }
        return this.popen.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "os.popen", error: e.message});
}

// ── Hook 4: requests.request ──
try {
    var requests = Python.use("requests");
    requests.request.implementation = function(method, url) {
        send({
            type: "http_outbound",
            method: String(method),
            url: String(url),
            layer: "requests"
        });
        return this.request.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "requests.request", error: e.message});
}

// ── Hook 5: requests.Session.request ──
try {
    var Session = Python.use("requests.sessions.Session");
    Session.request.implementation = function(method, url) {
        send({
            type: "http_outbound",
            method: String(method),
            url: String(url),
            layer: "requests.session"
        });
        return this.request.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "requests.Session.request", error: e.message});
}

// ── Hook 6: urllib3.HTTPConnectionPool.urlopen ──
try {
    var HTTPConnectionPool = Python.use("urllib3.connectionpool.HTTPConnectionPool");
    HTTPConnectionPool.urlopen.implementation = function(method, url) {
        send({
            type: "http_outbound",
            method: String(method),
            url: String(url),
            layer: "urllib3"
        });
        return this.urlopen.apply(this, arguments);
    };
} catch(e) {
    send({type: "error", hook: "urllib3.HTTPConnectionPool.urlopen", error: e.message});
}

send({type: "ready", hooks_installed: true});
