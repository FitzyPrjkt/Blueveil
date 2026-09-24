import type { ReactNode } from "react";

export interface StripStat {
  label: string;
  value: string;
  href?: string;
}

// SummaryStrip: one pattern for every workspace — a one-line "so what"
// statement, 3-5 mini stats (optionally linked), one micro-visual slot.
export function SummaryStrip({
  statement,
  stats,
  viz,
}: {
  statement: string;
  stats: StripStat[];
  viz?: ReactNode;
}) {
  return (
    <section className="strip" aria-label="Summary">
      <p className="strip-statement">{statement}</p>
      <div className="strip-stats">
        {stats.map((s) => (
          <div key={s.label} className="strip-stat">
            {s.href ? (
              <a className="strip-value tabular" href={s.href}>
                {s.value}
              </a>
            ) : (
              <span className="strip-value tabular">{s.value}</span>
            )}
            <span className="strip-label">{s.label}</span>
          </div>
        ))}
        {viz && (
          <div className="micro-viz" aria-hidden="true">
            {viz}
          </div>
        )}
      </div>
    </section>
  );
}
