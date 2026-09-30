import { AlertTriangle } from "lucide-react";
import type { TimedEvent } from "../types";

export function AlertBanner({ events }: { events: TimedEvent[] }) {
  const alert = events.find(isAlertEvent);

  if (!alert) {
    return (
      <section className="alert-banner quiet">
        <AlertTriangle aria-hidden="true" />
        <span>当前没有高优先级阻断告警</span>
      </section>
    );
  }

  const { label, reason } = describeAlert(alert);

  return (
    <section className="alert-banner hot">
      <AlertTriangle aria-hidden="true" />
      <strong>{label}</strong>
      <span>{reason || "策略要求人工确认"}</span>
    </section>
  );
}

function isAlertEvent(event: TimedEvent) {
  if (event.type === "tool_blocked" || event.type === "rule_alert") return true;
  if (event.type === "ebpf_intercept") {
    return !event.causal_id_valid || event.action === "block";
  }
  if (event.type === "tool_call") {
    const tainted = event.taint_tags.length > 0;
    const writeSend = ["send_email", "write_file", "http_post", "upload"].includes(
      event.tool_name,
    );
    return event.decision === "block" || (tainted && writeSend);
  }
  return false;
}

function describeAlert(event: TimedEvent) {
  if (event.type === "rule_alert") {
    return {
      label: `规则引擎 ${event.tool_name}`,
      reason: `risk=${event.risk_score.toFixed(2)} ${event.reason}`,
    };
  }
  if (event.type === "tool_blocked") {
    return { label: event.tool_name, reason: event.reason };
  }
  if (event.type === "ebpf_intercept") {
    return {
      label: `eBPF ${event.syscall}`,
      reason: event.causal_id_valid
        ? event.reason
        : `causal_id invalid: ${event.reason}`,
    };
  }
  if (event.type === "tool_call") {
    return {
      label: event.tool_name,
      reason:
        event.reason ||
        `tainted ${event.taint_tags.join(", ")} requires review`,
    };
  }
  return { label: "alert", reason: "" };
}
