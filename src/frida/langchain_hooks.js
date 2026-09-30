// src/frida/langchain_hooks.js
// LangChain Agent 高层 Hook：截获决策循环和工具调用

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

var sessionId = generateUUID();
var hooksInstalled = false;

// ── Hook 1: AgentExecutor._take_next_step ──
try {
    var AgentExecutor = Python.use("langchain.agents.AgentExecutor");
    AgentExecutor._take_next_step.implementation = function() {
        var inputMsgs = "";
        try {
            if (this.input) {
                inputMsgs = JSON.stringify(this.input);
            }
        } catch(e) {
            inputMsgs = String(this.input);
        }
        send({
            type: "context",
            input_messages: inputMsgs,
            session_id: sessionId,
            agent_class: this.$className || "AgentExecutor"
        });
        return this._take_next_step.apply(this, arguments);
    };
    hooksInstalled = true;
} catch(e) {
    send({type: "error", hook: "AgentExecutor._take_next_step", error: e.message});
}

// ── Hook 2: BaseTool._run ──
try {
    var BaseTool = Python.use("langchain.tools.BaseTool");
    BaseTool._run.implementation = function(tool_input) {
        var toolName = "";
        var paramsStr = "";
        try {
            toolName = this.name || "";
            paramsStr = JSON.stringify(tool_input);
        } catch(e) {
            toolName = String(this.name);
            paramsStr = String(tool_input);
        }
        send({
            type: "tool_call",
            tool_name: toolName,
            params: paramsStr,
            session_id: sessionId
        });
        return this._run.apply(this, arguments);
    };
    hooksInstalled = true;
} catch(e) {
    send({type: "error", hook: "BaseTool._run", error: e.message});
}

// ── Hook 3: BaseTool._arun (异步工具调用) ──
try {
    BaseTool._arun.implementation = function(tool_input) {
        var toolName = "";
        var paramsStr = "";
        try {
            toolName = this.name || "";
            paramsStr = JSON.stringify(tool_input);
        } catch(e) {
            toolName = String(this.name);
            paramsStr = String(tool_input);
        }
        send({
            type: "tool_call",
            tool_name: toolName,
            params: paramsStr,
            session_id: sessionId
        });
        return this._arun.apply(this, arguments);
    };
    hooksInstalled = true;
} catch(e) {
    send({type: "error", hook: "BaseTool._arun", error: e.message});
}

// ── Hook 4: ChatOpenAI._generate -- 截获 System Prompt ──
try {
    var ChatOpenAI = Python.use("langchain_openai.ChatOpenAI");
    ChatOpenAI._generate.implementation = function(messages) {
        var systemPrompt = "";
        try {
            for (var i = 0; i < messages.length; i++) {
                if (messages[i].type === "system") {
                    systemPrompt = messages[i].content;
                    break;
                }
            }
        } catch(e) {}
        if (systemPrompt) {
            send({
                type: "system_prompt",
                content: systemPrompt,
                session_id: sessionId
            });
        }
        return this._generate.apply(this, arguments);
    };
    hooksInstalled = true;
} catch(e) {
    send({type: "error", hook: "ChatOpenAI._generate", error: e.message});
}

send({type: "ready", session_id: sessionId, hooks_installed: hooksInstalled});
