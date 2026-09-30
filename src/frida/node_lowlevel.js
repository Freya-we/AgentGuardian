// src/frida/node_lowlevel.js
// Frida Hook: Node.js 底层 libuv C 函数 (跨 Node 版本稳定, libuv 1.x ABI)
// 目标: 截获子进程创建 + TCP/UDP 出站

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

var sessionId = generateUUID();
var hooksInstalled = 0;

// ── uv_spawn (子进程创建) ──
// signature: int uv_spawn(uv_loop_t*, uv_process_t*, const uv_process_options_t*)
var uv_spawn = Module.findExportByName(null, "uv_spawn");
if (uv_spawn) {
    Interceptor.attach(uv_spawn, {
        onEnter: function(args) {
            var options = ptr(args[2]);
            if (!options.isNull()) {
                try {
                    // uv_process_options_t: file (char*) is the first field
                    var file_ptr = options.readPointer();
                    if (!file_ptr.isNull()) {
                        var file_path = file_ptr.readCString();
                        send({
                            type: "node_spawn",
                            process: file_path,
                            session_id: sessionId
                        });
                    }
                } catch(e) {}
            }
        }
    });
    hooksInstalled++;
}

// ── uv_tcp_connect (TCP 出站) ──
// signature: int uv_tcp_connect(uv_connect_t*, uv_tcp_t*, const struct sockaddr*)
var uv_tcp_connect = Module.findExportByName(null, "uv_tcp_connect");
if (uv_tcp_connect) {
    Interceptor.attach(uv_tcp_connect, {
        onEnter: function(args) {
            var addr = ptr(args[2]);
            if (!addr.isNull()) {
                var family = addr.readU16();
                if (family === 2) {  // AF_INET
                    send({
                        type: "node_tcp_connect",
                        family: family,
                        session_id: sessionId
                    });
                }
            }
        }
    });
    hooksInstalled++;
}

// ── uv_udp_send (UDP 出站) ──
// signature: int uv_udp_send(uv_udp_send_t*, uv_udp_t*, const uv_buf_t[], unsigned int, const struct sockaddr*, uv_udp_send_cb)
var uv_udp_send = Module.findExportByName(null, "uv_udp_send");
if (uv_udp_send) {
    Interceptor.attach(uv_udp_send, {
        onEnter: function(args) {
            var addr = ptr(args[4]);  // 5th arg: sockaddr*
            if (!addr.isNull()) {
                var family = addr.readU16();
                if (family === 2) {  // AF_INET
                    send({
                        type: "node_udp_send",
                        family: family,
                        session_id: sessionId
                    });
                }
            }
        }
    });
    hooksInstalled++;
}

send({type: "ready", session_id: sessionId, runtime: "node", hooks_installed: hooksInstalled});
