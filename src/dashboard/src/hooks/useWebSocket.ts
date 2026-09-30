import { useEffect, useMemo, useRef, useState } from "react";
import type { DashboardEvent, TimedEvent } from "../types";

type ConnectionState = "connecting" | "open" | "closed";

export function useWebSocket(
  path = "/ws/events",
  initialEvents: DashboardEvent[] = [],
) {
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("connecting");
  const [events, setEvents] = useState<TimedEvent[]>([]);
  const retryRef = useRef<number>();

  const url = useMemo(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}${path}`;
  }, [path]);

  useEffect(() => {
    setEvents((previous) =>
      mergeEvents(
        initialEvents.map((event) => toTimedEvent(event)),
        previous,
      ),
    );
  }, [initialEvents]);

  useEffect(() => {
    let ws: WebSocket | undefined;
    let shouldReconnect = true;

    const connect = () => {
      setConnectionState("connecting");
      ws = new WebSocket(url);

      ws.onopen = () => {
        setConnectionState("open");
        ws?.send("dashboard-ready");
      };

      ws.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as DashboardEvent;
          setEvents((previous) => mergeEvents([toTimedEvent(event)], previous));
        } catch {
          // Ignore malformed telemetry frames.
        }
      };

      ws.onclose = () => {
        setConnectionState("closed");
        if (shouldReconnect) {
          retryRef.current = window.setTimeout(connect, 1500);
        }
      };

      ws.onerror = () => ws?.close();
    };

    connect();

    return () => {
      shouldReconnect = false;
      window.clearTimeout(retryRef.current);
      ws?.close();
    };
  }, [url]);

  return { connectionState, events };
}

function toTimedEvent(event: DashboardEvent): TimedEvent {
  return {
    ...event,
    id: eventIdentity(event),
    received_at:
      "received_at" in event && typeof event.received_at === "number"
        ? event.received_at
        : Date.now(),
  };
}

function mergeEvents(incoming: TimedEvent[], previous: TimedEvent[]) {
  const seen = new Set<string>();
  return [...incoming, ...previous]
    .filter((event) => {
      const identity = eventIdentity(event);
      if (seen.has(identity)) return false;
      seen.add(identity);
      return true;
    })
    .sort((a, b) => b.received_at - a.received_at)
    .slice(0, 200);
}

function eventIdentity(event: DashboardEvent) {
  const session = "session_id" in event ? event.session_id : "";
  const timestamp = "timestamp" in event ? event.timestamp ?? "" : "";
  const tool = "tool_name" in event ? event.tool_name : "";
  const syscall = "syscall" in event ? event.syscall : "";
  const reason = "reason" in event ? event.reason : "";
  return [
    event.type,
    session,
    tool,
    syscall,
    timestamp,
    reason,
  ].join(":");
}
