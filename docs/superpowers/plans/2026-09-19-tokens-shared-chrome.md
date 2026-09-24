# Design Tokens + Shared Components Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze one visual language (tokens, badges, stat cards, empty states) reused by Overview and all 14 workspaces, with zero backend changes.

**Architecture:** Extend the existing CSS-variable system in `ui/src/tokens.css` (do not invent a second system); add an outline badge variant to distinguish status vocabulary from severity vocabulary; extend `EmptyState` with an optional action (additive prop only); add a `SummaryStrip` + `StatLinkCard` component pair. All UI copy stays English (existing convention).

**Tech Stack:** React 19, TypeScript strict, Vite 7, vitest + @testing-library/react, prettier. No new dependencies.

**Spec:** Conversation spec "Design Token + Summary Strip" (2026-09-19), as corrected below.

## Global Constraints

- No backend, store, contract, or API changes. Read-only UI; no POST/PUT/DELETE.
- No new npm dependencies. No new theme mechanism (`data-theme` + `--bv-*` vars only).
- Copy is English, honest: never "Secure"/"100% safe"; use "Controlled", "No data yet", "Not yet scanned".
- `npm run build` (tsc + vite), `npm test` (vitest run), `npm run format` must all pass after every task.
- Existing severity color semantics are FROZEN (`tokens.css`: critical red, high orange, medium blue, low green, info grey). Do not remap medium/low.

## Spec Corrections (binding, supersede the chat spec)

1. Chat spec said medium=yellow, low=blue. Reality: `tokens.css` already maps medium=blue, low=green. REUSE existing mapping; no churn.
2. Chat spec proposed `ui/src/design/tokens.ts`. Reality: `tokens.css` + `theme.tsx` already exist and work. Do NOT create a parallel token file. Add missing scale tokens (type scale, spacing scale) as CSS vars + classes in `tokens.css`.
3. Chat spec said severity=solid pill, status=outline pill. Reality: severity pills are tinted (`--bv-sev-*-bg` backgrounds) and look fine. Keep them. ADD `.badge.outline` variant (transparent bg, 1px border, muted text) for lifecycle/status strings so the two vocabularies never share one pill.

---

## File Map

- Modify: `ui/src/tokens.css` — add type scale (`--bv-text-display/title/body/caption` + `.display/.title/.body/.caption` classes), spacing scale vars (`--bv-space-1:4px … --bv-space-6:48px`), `.tabular` already exists (keep).
- Modify: `ui/src/components.css` — add `.badge.outline`, `.stat-card.link` (clickable card), `.strip` (summary strip), `.micro-viz` sizes, `.group-head` (drawer section header).
- Modify: `ui/src/components/StatusBadge.tsx` — add `outline?: boolean` prop to `StatusBadge` only (SeverityBadge untouched).
- Modify: `ui/src/components/StatCard.tsx` — add optional `delta?: string`, `deltaTone?: "bad" | "good" | "neutral"`, `href?: string` (renders `<a>` wrapping card when present; keyboard-focusable, no new router).
- Modify: `ui/src/components/States.tsx` — add optional `action?: { label: string; onClick: () => void }` and `secondary?: string` (link-style text, non-navigation hint) to `EmptyState`. Existing 3-prop call sites keep working.
- Create: `ui/src/components/SummaryStrip.tsx` — `SummaryStrip({ statement, stats, viz }: { statement: string; stats: { label: string; value: string; href?: string }[]; viz?: ReactNode })`.
- Test: `ui/src/components/chrome.test.tsx` — new file covering outline badge, linked stat card, empty-state action, summary strip.

---

### Task 1: Token scale + outline badge CSS

**Files:**
- Modify: `ui/src/tokens.css` (append scale block after `.sr-only`, lines ~194-201)
- Modify: `ui/src/components.css` (append after `.badge.neutral`, lines ~466-470)
- Test: none new (visual tokens); gate is full suite green.

**Interfaces:**
- Consumes: existing `--bv-*` vars.
- Produces: `.display` (40px/700, letter-spacing -0.01em), `.title` (20px/600), `.body` (14px/400), `.caption` (12px/500 uppercase, letter-spacing 0.06em, muted); `--bv-space-1..6`; `.badge.outline`; `.stat-card.link` (hover border-strong + cursor pointer, focus-visible outline already global); `.strip` (surface, border, radius-l, padding 24, margin-bottom 32); `.micro-viz` (48px donut slot / 120x32 bar slot); `.group-head` (caption style + bottom border).

- [ ] **Step 1: Append token scale to tokens.css**

```css
/* ---- Type scale (executive layer + workspace polish) ---- */
:root,
[data-theme="light"],
[data-theme="dark"] {
  --bv-space-1: 4px;
  --bv-space-2: 8px;
  --bv-space-3: 16px;
  --bv-space-4: 24px;
  --bv-space-5: 32px;
  --bv-space-6: 48px;
}

.display {
  font-size: 40px;
  font-weight: 700;
  letter-spacing: -0.01em;
  line-height: 1.1;
}

.title {
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.body {
  font-size: 14px;
  font-weight: 400;
}

.caption {
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--bv-muted);
}
```

- [ ] **Step 2: Append component classes to components.css**

```css
/* ---- Outline badge: lifecycle/status vocabulary (never severity) ---- */
.badge.outline {
  color: var(--bv-ink-soft);
  background: transparent;
  border-color: var(--bv-border-strong);
}

/* ---- Linked stat card ---- */
.stat-card.link {
  cursor: pointer;
}
.stat-card.link:hover {
  border-color: var(--bv-border-strong);
}
.stat-card .stat-delta {
  font-size: 12px;
  font-weight: 600;
  margin-top: 2px;
}
.stat-card .stat-delta.bad {
  color: var(--bv-bad);
}
.stat-card .stat-delta.good {
  color: var(--bv-ok);
}
.stat-card .stat-delta.neutral {
  color: var(--bv-muted);
}

/* ---- Summary strip (one pattern, all workspaces) ---- */
.strip {
  background: var(--bv-card);
  border: 1px solid var(--bv-border);
  border-radius: var(--bv-radius-l);
  box-shadow: var(--bv-shadow);
  padding: 16px 24px;
  margin-bottom: 32px;
}
.strip-statement {
  color: var(--bv-ink-soft);
  font-size: 13.5px;
  margin: 0 0 12px;
}
.strip-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 32px;
  align-items: center;
}
.strip-stat {
  display: flex;
  flex-direction: column;
}
.strip-stat .strip-value {
  font-size: 20px;
  font-weight: 600;
}
.strip-stat .strip-label {
  font-size: 12px;
  color: var(--bv-muted);
}
.micro-viz {
  margin-left: auto;
}

/* ---- Drawer section header ---- */
.group-head {
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--bv-muted);
  border-bottom: 1px solid var(--bv-border);
  padding-bottom: 8px;
  margin: 16px 0 8px;
}
```

- [ ] **Step 3: Verify gates**

Run: `npm run format && npm run typecheck` in `collector/ui`
Expected: PASS (CSS-only change; prettier may reformat — accept its output with `format:write` then re-run check)

---

### Task 2: Extend StatusBadge, StatCard, EmptyState (additive props)

**Files:**
- Modify: `ui/src/components/StatusBadge.tsx:44-59` (StatusBadge function)
- Modify: `ui/src/components/StatCard.tsx:1-44` (whole file)
- Modify: `ui/src/components/States.tsx:41-59` (EmptyState function)
- Test: `ui/src/components/chrome.test.tsx` (new)

**Interfaces:**
- Consumes: classes from Task 1.
- Produces: `StatusBadge({value, tone, outline})`; `StatCard({label, value, caption, animate, delta, deltaTone, href})`; `EmptyState({icon, title, description, action, secondary})`; `SummaryStrip` (Task 3).

- [ ] **Step 1: Write the failing test** (`ui/src/components/chrome.test.tsx`)

```tsx
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StatusBadge } from "./StatusBadge";
import { StatCard } from "./StatCard";
import { EmptyState } from "./States";
import { SummaryStrip } from "./SummaryStrip";

afterEach(() => cleanup());

describe("shared chrome", () => {
  it("renders outline status badge without severity colors", () => {
    render(<StatusBadge value="ASSET_STATUS_STALE" tone="info" outline />);
    const el = screen.getByText("STALE");
    expect(el.className).toContain("outline");
    expect(el.className).not.toContain("critical");
  });

  it("renders linked stat card with delta", async () => {
    const user = userEvent.setup();
    render(
      <StatCard
        label="Findings"
        value={12}
        caption="3 critical"
        delta="▲ +2 vs last week"
        deltaTone="bad"
        href="#/findings"
      />,
    );
    expect(screen.getByText("▲ +2 vs last week")).toBeInTheDocument();
    const link = screen.getByRole("link");
    expect(link.getAttribute("href")).toBe("#/findings");
    await user.click(link);
  });

  it("renders empty state with action button", async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    render(
      <EmptyState
        icon="shield"
        title="No assets"
        description="Nothing observed yet."
        action={{ label: "Seed the lab", onClick }}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Seed the lab" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("renders summary strip with statement, stats, and viz", () => {
    render(
      <SummaryStrip
        statement="2 outdated dependencies raise supply-chain risk."
        stats={[
          { label: "Components", value: "8", href: "#/supply-chain" },
          { label: "Policies failing", value: "1" },
        ]}
        viz={<span data-testid="viz">viz</span>}
      />,
    );
    expect(
      screen.getByText("2 outdated dependencies raise supply-chain risk."),
    ).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByTestId("viz")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/components/chrome.test.tsx` in `collector/ui`
Expected: FAIL — `SummaryStrip` (and new props) not defined

- [ ] **Step 3: Minimal implementation**

StatusBadge — add prop, append class:
```tsx
export function StatusBadge({
  value,
  tone,
  outline = false,
}: {
  value: string;
  tone?: "info" | "warn" | "bad" | "low" | "neutral";
  outline?: boolean;
}) {
  return (
    <span className={`badge ${tone ?? "info"}${outline ? " outline" : ""}`}>
      <span className="dot" aria-hidden="true" />
      {shortEnum(value)}
    </span>
  );
}
```

StatCard — add `delta`, `deltaTone`, `href`; wrap in `<a>` when href present:
```tsx
import { useEffect, useRef, useState } from "react";

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
  const text = typeof shown === "number" ? shown.toLocaleString("en-US") : shown;
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
      <a className="stat-card link" href={href} aria-label={`${label}: ${text}`}>
        {body}
      </a>
    );
  }
  return <div className="stat-card">{body}</div>;
}
```

EmptyState — additive optional props:
```tsx
export function EmptyState({
  icon,
  title,
  description,
  action,
  secondary,
}: {
  icon: IconName;
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
  secondary?: string;
}) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        <Icon name={icon} />
      </span>
      <h3 className="empty-title">{title}</h3>
      <p className="empty-desc">{description}</p>
      {action && (
        <button type="button" onClick={action.onClick}>
          {action.label}
        </button>
      )}
      {secondary && <p className="empty-desc">{secondary}</p>}
    </div>
  );
}
```
(`.empty` class already centers content — verify in components.css lines ~688-720; if buttons need spacing add `margin-top: 12px` to `.empty button`. Include that in the components.css append if missing.)

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/components/chrome.test.tsx` then full `npm test` in `collector/ui`
Expected: new file PASS; full suite PASS (existing call sites use old props only)

---

### Task 3: SummaryStrip component

**Files:**
- Create: `ui/src/components/SummaryStrip.tsx`
- Test: covered by `chrome.test.tsx` (Task 2, Step 1 — write it in the same step)

**Interfaces:**
- Consumes: `.strip*` classes from Task 1.
- Produces: `SummaryStrip({statement, stats, viz})` where `stats: { label: string; value: string; href?: string }[]`, `viz?: ReactNode`.

- [ ] **Step 1: Implementation** (test already written in Task 2)

```tsx
import type { ReactNode } from "react";

export interface StripStat {
  label: string;
  value: string;
  href?: string;
}

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
```

- [ ] **Step 2: Run gates**

Run: `npm test && npm run build && npm run format` in `collector/ui`
Expected: all PASS (64 existing + 4 new = 68 tests)

---

## Self-Review

- Spec coverage: token scale ✓ (Task 1), badge vocab split ✓ (Task 1+2), stat card delta/link ✓ (Task 2), empty action ✓ (Task 2), strip ✓ (Task 3). Drawer grouping + per-workspace strip rollout + micro-sweep are NOT in this plan — they belong to a follow-up "batch rollout" plan after Overview lands.
- Placeholders: none — all code blocks complete.
- Type consistency: `StripStat.href` string matches `<a href>` usage in Overview plan; `StatCard.href` string matches hash links (`#/findings?...`).
