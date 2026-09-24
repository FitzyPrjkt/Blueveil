import { StatusBadge } from "./StatusBadge";

// Status timeline (M): vertical dots + badges + timestamps for incident
// lifecycle and response chains. Dots: done (green) for passed steps,
// now (blue) for the current step, hollow for the rest.
export interface TimelineStep {
  key: string;
  title: string;
  meta?: string;
  badge?: { text: string; tone: "info" | "warn" | "bad" | "low" | "neutral" };
  state: "done" | "now" | "todo";
}

export function StatusTimeline({ steps }: { steps: TimelineStep[] }) {
  return (
    <ol className="timeline">
      {steps.map((s) => (
        <li key={s.key}>
          <span className={`t-dot ${s.state}`} aria-hidden="true" />
          <div className="t-title">{s.title}</div>
          {s.badge && (
            <div style={{ margin: "2px 0" }}>
              <StatusBadge value={s.badge.text} tone={s.badge.tone} />
            </div>
          )}
          {s.meta && <div className="t-meta">{s.meta}</div>}
        </li>
      ))}
    </ol>
  );
}
