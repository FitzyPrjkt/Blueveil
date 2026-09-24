import { useEffect, useRef, useState } from "react";

// KPI stat card: label + tabular number + caption. Optional delta line and
// optional link wrapper (href) for click-through cards. No trends baked in —
// callers compute delta text. Optional gentle count-up on mount (numbers only).
export function StatCard({
  label,
  value,
  caption,
  animate = false,
  delta,
  deltaTone = "neutral",
  href,
}: {
  label: string;
  value: number | string;
  caption: string;
  animate?: boolean;
  delta?: string;
  deltaTone?: "bad" | "good" | "neutral";
  href?: string;
}) {
  const numeric = typeof value === "number" ? value : null;
  const [shown, setShown] = useState(animate && numeric !== null ? 0 : value);
  const raf = useRef(0);
  useEffect(() => {
    if (!animate || numeric === null) {
      setShown(value);
      return;
    }
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setShown(value);
      return;
    }
    const start = performance.now();
    const dur = 450;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / dur);
      setShown(Math.round(numeric * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [animate, value, numeric]);
  const text =
    typeof shown === "number" ? shown.toLocaleString("en-US") : shown;
  const body = (
    <>
      <div className="stat-label">{label}</div>
      <div className="stat-value tabular">{text}</div>
      {delta && <div className={`stat-delta ${deltaTone}`}>{delta}</div>}
      <div className="stat-caption">{caption}</div>
    </>
  );
  if (href) {
    return (
      <a
        className="stat-card link"
        href={href}
        aria-label={`${label}: ${text}`}
      >
        {body}
      </a>
    );
  }
  return <div className="stat-card">{body}</div>;
}
