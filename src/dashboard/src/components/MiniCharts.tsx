import { useMemo } from "react";
import * as d3 from "d3";
import { PanelTitle } from "./CallChainTree";
import { decisionCounts } from "../eventModel";
import type { StatsSnapshot, ToolNode } from "../types";

export function MiniCharts({
  nodes,
  stats,
}: {
  nodes: ToolNode[];
  stats?: StatsSnapshot;
}) {
  const counts = decisionCounts(nodes);
  const bars = [
    { label: "allow", value: counts.allow },
    { label: "ask", value: counts.ask },
    { label: "block", value: counts.block },
  ];
  const max = Math.max(1, ...bars.map((bar) => bar.value));

  const sparkline = useMemo(() => {
    const values = nodes.slice(-20).map((node, index) => ({
      x: index,
      y: node.decision === "block" ? 100 : node.decision === "ask" ? 60 : 20,
    }));
    if (values.length < 2) return "";
    const x = d3.scaleLinear().domain([0, values.length - 1]).range([0, 220]);
    const y = d3.scaleLinear().domain([0, 100]).range([72, 6]);
    return d3
      .line<(typeof values)[number]>()
      .x((point) => x(point.x))
      .y((point) => y(point.y))
      .curve(d3.curveMonotoneX)(values);
  }, [nodes]);

  return (
    <section className="panel chart-panel">
      <PanelTitle title="统计分析" detail="live summary" />
      <div className="bar-chart">
        {bars.map((bar) => (
          <div key={bar.label} className={`bar-row ${bar.label}`}>
            <span>{bar.label}</span>
            <div>
              <i style={{ width: `${(bar.value / max) * 100}%` }} />
            </div>
            <b>{bar.value}</b>
          </div>
        ))}
      </div>
      <svg className="sparkline" viewBox="0 0 220 80" role="img">
        <title>Recent decision risk line</title>
        <path d={sparkline || "M0 72 L220 72"} />
      </svg>
      <div className="stat-foot">
        <span>P95 {stats?.interval_p95_ms.toFixed(1) ?? "0.0"} ms</span>
        <span>Entropy {stats?.entropy_current.toFixed(2) ?? "0.00"}</span>
      </div>
    </section>
  );
}
