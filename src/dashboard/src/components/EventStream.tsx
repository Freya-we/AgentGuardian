import { Terminal } from "lucide-react";
import { PanelTitle } from "./CallChainTree";
import type { TimedEvent } from "../types";

export function EventStream({ events }: { events: TimedEvent[] }) {
  return (
    <section className="panel event-stream">
      <PanelTitle title="事件流" detail={`${events.length} retained`} />
      <div className="log-table" role="table">
        {events.length === 0 ? (
          <div className="empty-state">Waiting for /ws/events</div>
        ) : (
          events.slice(0, 32).map((event) => (
            <div className="log-row" key={event.id} role="row">
              <Terminal aria-hidden="true" />
              <time>
                {new Date(event.received_at).toLocaleTimeString("zh-CN", {
                  hour12: false,
                })}
              </time>
              <strong>{event.type}</strong>
              <span>{summarize(event)}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function summarize(event: TimedEvent) {
  if (event.type === "tool_call") {
    const causal = event.causal_id ? ` cid=${event.causal_id.slice(0, 12)}` : "";
    const tags = event.taint_tags.length ? ` tags=${event.taint_tags.join("|")}` : "";
    return `${event.decision} ${event.tool_name} / ${event.session_id}${causal}${tags}`;
  }
  if ("tool_name" in event) {
    return `${event.tool_name}${"session_id" in event ? ` / ${event.session_id}` : ""}`;
  }
  if (event.type === "stats_update") {
    return `p95=${event.snapshot.interval_p95_ms.toFixed(1)}ms taint=${(
      event.snapshot.taint_ratio * 100
    ).toFixed(0)}%`;
  }
  if (event.type === "config_reloaded") {
    return `${event.templates_loaded} templates`;
  }
  if (event.type === "ebpf_intercept") {
    return `${event.syscall} ${event.action} cid_valid=${event.causal_id_valid} ${event.reason}`;
  }
  return "telemetry";
}
