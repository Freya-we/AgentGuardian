type Props = {
  label: string;
  value: string;
  tone?: "neutral" | "good" | "warn" | "bad";
};

export function MetricCard({ label, value, tone = "neutral" }: Props) {
  return (
    <section className={`metric-card ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}
