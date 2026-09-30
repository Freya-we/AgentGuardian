// src/frida/openclaw_plugin.ts
// OpenClaw 内置插件：通过 Hook API → HTTP → 审计引擎 bridge 发送上下文
// 安装: 复制到 ~/.openclaw/plugins/agent-guardian/index.ts

const AUDIT_ENGINE_BRIDGE_URL = "http://localhost:8000";

interface ToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  ctx: {
    sessionKey: string;
    sessionId: string;
    agentId: string;
    runId: string;
  };
}

interface AgentRunEvent {
  prompt: string;
  ctx: {
    sessionKey: string;
    sessionId: string;
    agentId: string;
  };
}

interface OpenClawAPI {
  on: (event: string, handler: (event: any) => Promise<void>) => void;
}

export default function plugin(api: OpenClawAPI): void {
  // Hook 1: 工具调用前 — 发送上下文到审计引擎
  api.on("before_tool_call", async (event: ToolCallEvent) => {
    try {
      await fetch(`${AUDIT_ENGINE_BRIDGE_URL}/api/v1/frida/context`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "tool_call",
          tool_name: event.toolName,
          params: JSON.stringify(event.params),
          session_id: event.ctx.sessionId,
          agent_id: event.ctx.agentId,
        }),
      });
    } catch {
      // fail-open: hook 错误不阻塞 agent
    }
  });

  // Hook 2: Agent 执行前 — 发送 System Prompt
  api.on("before_agent_run", async (event: AgentRunEvent) => {
    try {
      await fetch(`${AUDIT_ENGINE_BRIDGE_URL}/api/v1/frida/system-prompt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_prompt: event.prompt || "",
          session_id: event.ctx.sessionId,
        }),
      });
    } catch {
      // fail-open
    }
  });
}
