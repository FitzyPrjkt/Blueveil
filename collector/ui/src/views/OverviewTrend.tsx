import type { TrendDay } from "./overviewAgg";

const W = 640;
const H = 160;
const PAD = 8;

// Stacked-area trend of open findings over 30 days. Hand-rolled SVG (no
// chart dependency): bottom layer = other severities, middle = high,
// top = critical. Adjacent hidden table keeps values accessible.
export function TrendChart({ days }: { days: TrendDay[] }) {
  const max = Math.max(1, ...days.map((d) => d.critical + d.high + d.other));
  const x = (i: number) =>
    PAD + (i / Math.max(1, days.length - 1)) * (W - PAD * 2);
  const y = (v: number) => H - PAD - (v / max) * (H - PAD * 2);
  const layer = (
    pick: (d: TrendDay) => number,
    base: (d: TrendDay) => number,
  ) => {
    const top = days.map((d, i) => `${x(i)},${y(base(d) + pick(d))}`).join(" ");
    const bot = days
      .map((d, i) => `${x(i)},${y(base(d))}`)
      .reverse()
      .join(" ");
    return `M${top} L${bot} Z`;
  };
  const other = (d: TrendDay) => d.other;
  const zero = () => 0;
  const highBase = (d: TrendDay) => d.other;
  const high = (d: TrendDay) => d.high;
  const critBase = (d: TrendDay) => d.other + d.high;
  const crit = (d: TrendDay) => d.critical;
  return (
    <div className="trend-chart">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label="Open findings trend, last 30 days"
        width="100%"
      >
        <title>{`Peak ${max} open findings in the last 30 days`}</title>
        <path d={layer(other, zero)} fill="var(--bv-sev-info)" opacity={0.35} />
        <path
          d={layer(high, highBase)}
          fill="var(--bv-sev-high)"
          opacity={0.55}
        />
        <path
          d={layer(crit, critBase)}
          fill="var(--bv-sev-critical)"
          opacity={0.75}
        />
      </svg>
      <table className="sr-only">
        <caption>Open findings per day</caption>
        <tbody>
          {days.map((d) => (
            <tr key={d.date}>
              <th scope="row">{d.date}</th>
              <td>{d.critical + d.high + d.other}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
