export type HealthStatus = {
  status: string;
  rule_engine_available: boolean;
};

export type StatsSnapshot = {
  interval_p95_ms: number;
  entropy_current: number;
  taint_ratio: number;
  graph_unknown_count: number;
};

export type TaskTemplateConfig = {
  id: string;
  label: string;
  graph: Record<string, string[]>;
  terminals: string[];
  forbidden_tool_categories: string[];
  require_slm_review: string[];
};

export type TaskTemplatesConfig = {
  templates: TaskTemplateConfig[];
  global_blacklist: string[];
  default_mode: "allow" | "ask" | "block";
};

export type DashboardEvent =
  | {
      type: "causal_id_issued";
      session_id: string;
      tool_name: string;
      pid: number;
    }
  | {
      type: "tool_blocked";
      session_id: string;
      tool_name: string;
      reason: string;
      tags: string[];
    }
  | {
      type: "rule_alert";
      session_id: string;
      tool_name: string;
      risk_score: number;
      reason: string;
    }
  | {
      type: "stats_update";
      session_id: string;
      snapshot: StatsSnapshot;
    }
  | {
      type: "config_reloaded";
      templates_loaded: number;
      changes: Array<{ path: string; kind: string }>;
    }
  | {
      type: "tool_call";
      session_id: string;
      tool_name: string;
      decision: "allow" | "ask" | "block";
      causal_id?: string | null;
      taint_tags: string[];
      reason: string;
      timestamp?: number;
      pid?: number;
    }
  | {
      type: "taint_update";
      session_id: string;
      source_type: string;
      active_tags: string[];
      timestamp?: number;
    }
  | {
      type: "ebpf_intercept";
      pid: number;
      syscall: string;
      causal_id_valid: boolean;
      action: string;
      reason: string;
      timestamp?: number;
    };

export type TimedEvent = DashboardEvent & {
  id: string;
  received_at: number;
};

export type ToolNode = {
  id: string;
  session_id: string;
  tool_name: string;
  decision: "allow" | "ask" | "block";
  reason?: string;
  tags: string[];
  causal_id?: string | null;
  pid?: number;
  timestamp: number;
};
