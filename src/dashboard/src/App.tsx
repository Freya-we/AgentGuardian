import { useEffect, useMemo, useState } from "react";
import { fetchHealth, fetchRecentEvents, fetchSessionStats } from "./api";
import { activeSession, buildToolNodes, latestStats } from "./eventModel";
import { useWebSocket } from "./hooks/useWebSocket";
import { AlertBanner } from "./components/AlertBanner";
import { CallChainTree } from "./components/CallChainTree";
import { EventStream } from "./components/EventStream";
import { MetricCard } from "./components/MetricCard";
import { MiniCharts } from "./components/MiniCharts";
import { StatusBar } from "./components/StatusBar";
import { TaintTracker } from "./components/TaintTracker";
import { ConfigPanel } from "./components/ConfigPanel";
import type { DashboardEvent, HealthStatus, StatsSnapshot } from "./types";

export function App() {
  const [recentEvents, setRecentEvents] = useState<DashboardEvent[]>([]);
  const { connectionState, events } = useWebSocket("/ws/events", recentEvents);
  const [health, setHealth] = useState<HealthStatus>();
  const [manualStats, setManualStats] = useState<StatsSnapshot>();
  const nodes = useMemo(() => buildToolNodes(events), [events]);
  const sessionId = activeSession(events);
  const stats = latestStats(events) ?? manualStats;

  useEffect(() => {
    fetchHealth().then(setHealth).catch(() => undefined);
    fetchRecentEvents(100).then(setRecentEvents).catch(() => undefined);
    const timer = window.setInterval(() => {
      fetchHealth().then(setHealth).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    fetchSessionStats(sessionId).then(setManualStats).catch(() => undefined);
  }, [sessionId]);

  const blockedCount = nodes.filter((node) => node.decision === "block").length;

  return (
    <main className="app-shell">
      <StatusBar
        health={health}
        wsState={connectionState}
        activeSession={sessionId}
      />
      <AlertBanner events={events} />

      <section className="metrics-grid" aria-label="Runtime metrics">
        <MetricCard
          label="P95 interval"
          value={`${stats?.interval_p95_ms.toFixed(1) ?? "0.0"} ms`}
          tone="neutral"
        />
        <MetricCard
          label="Taint ratio"
          value={`${(((stats?.taint_ratio ?? 0) as number) * 100).toFixed(0)}%`}
          tone={(stats?.taint_ratio ?? 0) > 0.3 ? "warn" : "good"}
        />
        <MetricCard
          label="Unknown graph"
          value={`${stats?.graph_unknown_count ?? 0}`}
          tone={(stats?.graph_unknown_count ?? 0) > 0 ? "warn" : "good"}
        />
        <MetricCard
          label="Blocked calls"
          value={`${blockedCount}`}
          tone={blockedCount > 0 ? "bad" : "good"}
        />
      </section>

      <section className="workspace-grid">
        <CallChainTree nodes={nodes} />
        <TaintTracker nodes={nodes} events={events} />
        <MiniCharts nodes={nodes} stats={stats} />
        <ConfigPanel />
      </section>

      <EventStream events={events} />
    </main>
  );
}
