import { Activity, Cpu, Radio, ShieldCheck } from "lucide-react";
import type { HealthStatus } from "../types";

type Props = {
  health?: HealthStatus;
  wsState: "connecting" | "open" | "closed";
  activeSession: string;
};

export function StatusBar({ health, wsState, activeSession }: Props) {
  return (
    <header className="status-bar">
      <div className="brand">
        <ShieldCheck aria-hidden="true" />
        <div>
          <strong>AgentGuardian</strong>
          <span>Zero-trust runtime monitor</span>
        </div>
      </div>

      <div className="status-cluster">
        <StatusPill
          icon={<Activity aria-hidden="true" />}
          label="审计引擎"
          state={health?.status === "ok" ? "online" : "offline"}
        />
        <StatusPill
          icon={<Cpu aria-hidden="true" />}
          label="规则引擎"
          state={health?.rule_engine_available ? "online" : "standby"}
        />
        <StatusPill
          icon={<Radio aria-hidden="true" />}
          label="Event stream"
          state={wsState === "open" ? "online" : wsState}
        />
        <div className="session-chip" title={activeSession}>
          {activeSession}
        </div>
      </div>
    </header>
  );
}

function StatusPill({
  icon,
  label,
  state,
}: {
  icon: React.ReactNode;
  label: string;
  state: string;
}) {
  return (
    <span className={`status-pill ${state}`}>
      {icon}
      <span>{label}</span>
      <b>{state}</b>
    </span>
  );
}
