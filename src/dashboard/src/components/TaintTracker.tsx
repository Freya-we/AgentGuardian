import { Fingerprint } from "lucide-react";
import { PanelTitle } from "./CallChainTree";
import type { TimedEvent, ToolNode } from "../types";

export function TaintTracker({
  nodes,
  events,
}: {
  nodes: ToolNode[];
  events: TimedEvent[];
}) {
  const tags = Array.from(
    new Set(
      nodes.flatMap((node) => node.tags).concat(
        events.flatMap((event) =>
          event.type === "taint_update" ? event.active_tags : [],
        ),
      ),
    ),
  );

  return (
    <section className="panel taint-panel">
      <PanelTitle title="污点追踪" detail={`${tags.length} active tags`} />
      <div className="tag-grid">
        {tags.length ? (
          tags.map((tag) => (
            <span key={tag} className="taint-tag">
              <Fingerprint aria-hidden="true" />
              {tag}
            </span>
          ))
        ) : (
          <div className="empty-state">No taint tags detected</div>
        )}
      </div>
    </section>
  );
}
