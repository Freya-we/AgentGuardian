import type { StatsSnapshot, TimedEvent, ToolNode } from "./types";

export function buildToolNodes(events: TimedEvent[]): ToolNode[] {
  return events
    .flatMap((event): ToolNode[] => {
      if (event.type === "causal_id_issued") {
        return [
          {
            id: event.id,
            session_id: event.session_id,
            tool_name: event.tool_name,
            decision: "allow",
            tags: [],
            pid: event.pid,
            timestamp: event.received_at,
          },
        ];
      }
      if (event.type === "tool_blocked") {
        return [
          {
            id: event.id,
            session_id: event.session_id,
            tool_name: event.tool_name,
            decision: "block",
            reason: event.reason,
            tags: event.tags,
            timestamp: event.received_at,
          },
        ];
      }
      if (event.type === "rule_alert") {
        return [
          {
            id: event.id,
            session_id: event.session_id,
            tool_name: event.tool_name,
            decision: "block",
            reason: event.reason,
            tags: [`risk:${event.risk_score.toFixed(2)}`],
            timestamp: event.received_at,
          },
        ];
      }
      if (event.type === "tool_call") {
        return [
          {
            id: event.id,
            session_id: event.session_id,
            tool_name: event.tool_name,
            decision: event.decision,
            reason: event.reason,
            tags: event.taint_tags,
            causal_id: event.causal_id,
            pid: event.pid,
            timestamp: event.timestamp ?? event.received_at,
          },
        ];
      }
      return [];
    })
    .reverse();
}

export function latestStats(events: TimedEvent[]): StatsSnapshot | undefined {
  return events.find((event) => event.type === "stats_update")?.snapshot;
}

export function activeSession(events: TimedEvent[]): string {
  const event = events.find(
    (candidate) =>
      "session_id" in candidate && typeof candidate.session_id === "string",
  );
  return event && "session_id" in event ? event.session_id : "default";
}

export function decisionCounts(nodes: ToolNode[]) {
  return {
    allow: nodes.filter((node) => node.decision === "allow").length,
    ask: nodes.filter((node) => node.decision === "ask").length,
    block: nodes.filter((node) => node.decision === "block").length,
  };
}
