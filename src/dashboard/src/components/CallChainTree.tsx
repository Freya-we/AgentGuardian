import { CheckCircle2, CircleHelp, XCircle } from "lucide-react";
import type { ToolNode } from "../types";

const icons = {
  allow: CheckCircle2,
  ask: CircleHelp,
  block: XCircle,
};

export function CallChainTree({ nodes }: { nodes: ToolNode[] }) {
  if (nodes.length === 0) {
    return (
      <section className="panel call-chain">
        <PanelTitle title="因果链" detail="等待工具调用事件" />
        <div className="empty-state">No tool calls yet</div>
      </section>
    );
  }

  return (
    <section className="panel call-chain">
      <PanelTitle title="因果链" detail={`${nodes.length} calls`} />
      <ol className="chain-list">
        {nodes.slice(-14).map((node) => {
          const Icon = icons[node.decision];
          return (
            <li key={node.id} className={node.decision}>
              <span className="chain-rail" />
              <Icon aria-hidden="true" />
              <div>
                <strong>{node.tool_name}</strong>
                <span>{node.session_id}</span>
                {node.reason ? <em>{node.reason}</em> : null}
                {node.causal_id ? (
                  <code title={node.causal_id}>
                    cid:{node.causal_id.slice(0, 16)}
                  </code>
                ) : null}
                {node.tags.length ? (
                  <small>{node.tags.join(" / ")}</small>
                ) : null}
              </div>
              <b>{node.decision}</b>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

export function PanelTitle({
  title,
  detail,
}: {
  title: string;
  detail?: string;
}) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      {detail ? <span>{detail}</span> : null}
    </div>
  );
}
