import type {
  DashboardEvent,
  HealthStatus,
  StatsSnapshot,
  TaskTemplatesConfig,
} from "./types";

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch("/health");
  if (!response.ok) {
    throw new Error("health request failed");
  }
  return response.json();
}

export async function fetchSessionStats(
  sessionId: string,
): Promise<StatsSnapshot> {
  const response = await fetch(`/api/v1/sessions/${sessionId}/stats`);
  if (!response.ok) {
    throw new Error("stats request failed");
  }
  return response.json();
}

export async function fetchSessionGraph(sessionId: string): Promise<{
  path: string[];
}> {
  const response = await fetch(`/api/v1/sessions/${sessionId}/graph`);
  if (!response.ok) {
    throw new Error("graph request failed");
  }
  return response.json();
}

export async function fetchRecentEvents(limit = 100): Promise<DashboardEvent[]> {
  const response = await fetch(`/api/v1/events/recent?limit=${limit}`);
  if (!response.ok) {
    throw new Error("recent events request failed");
  }
  const payload = (await response.json()) as { events: DashboardEvent[] };
  return payload.events;
}

export async function reloadConfig(): Promise<{ templates_loaded: number }> {
  const response = await fetch("/api/v1/config/reload", { method: "POST" });
  if (!response.ok) {
    throw new Error("config reload failed");
  }
  return response.json();
}

export async function fetchTaskTemplatesConfig(): Promise<TaskTemplatesConfig> {
  const response = await fetch("/api/v1/config/task-templates");
  if (!response.ok) {
    throw new Error("config request failed");
  }
  return response.json();
}

export async function saveTaskTemplatesConfig(
  config: TaskTemplatesConfig,
): Promise<{ status: string; templates_loaded: number }> {
  const response = await fetch("/api/v1/config/task-templates", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || "config save failed");
  }
  return response.json();
}
