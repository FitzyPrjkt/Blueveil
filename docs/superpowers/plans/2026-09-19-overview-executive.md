# Executive Overview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the counts-only Overview with a 5-section executive layer (status strip, 4 linked stat cards, 30-day trend + auto-summary, attention queue, domain rollup) where every number click-throughs to a pre-filtered workspace.

**Architecture:** Frontend-only aggregation over endpoints the app already fetches (`useApiList` + existing contract parsers). Hash routing gains an optional query string (`#/findings?severity=…&status=…`); target views accept initial filter values from the hash (initializer only, no two-way sync). No backend changes, no new dependencies (trend chart is hand-rolled SVG).

**Tech Stack:** React 19, TypeScript strict, Vite 7, vitest + @testing-library/react, prettier. No new dependencies.

**Spec:** Conversation spec "Executive Overview" (2026-09-19), as corrected below. Depends on: tokens/shared-chrome plan (merged first).

## Global Constraints

- No backend, store, contract, or API changes. Read-only UI.
- `npm run build`, `npm test`, `npm run format` pass after every task.
- Copy is English, honest: "Controlled" never "Secure"; "No data yet" / "Not yet scanned" for low-data; every low-data state carries a next action.
- "Open" findings = `ALERT_STATUS_OPEN` or `ALERT_STATUS_ACKNOWLEDGED` (not CLOSED). Document this definition in a comment where used.
- Deterministic output: same data → same overview. No random IDs, no time-of-render wording except relative ages computed from data timestamps (`fmtTime` exists in `views/hooks.ts`).

## Spec Corrections (binding, supersede the chat spec)

1. Chat spec's card 4 ("validation score % + campaign name + next schedule") does not match the backend: `ValidationResult` has `verdict` + `validated_at`, no score; campaigns have `status` + `by_verdict` counts, no schedule. Card 4 shows: latest `validated_at`, total results, count of bad-outcome results (`ALLOWED_AND_NOT_DETECTED`), low-data copy when empty. Link → `#/validation`.
2. Chat spec said asset "lifecycle" field. Reality: `Asset.status?: AssetStatus` (`DISCOVERED|ACTIVE|STALE|RETIRED`) + `first_seen`/`last_seen`. Coverage = ACTIVE / (ACTIVE + STALE); assets with `status === undefined` count as monitored but excluded from the coverage ratio (comment this).
3. Chat spec's trend used `firstSeen`. Reality: `Alert.created_at` (required ISO string). Bucket non-closed alerts by UTC calendar day of `created_at`, last 30 days, stacked critical / high / other.
4. S3 "Assign / Snooze" actions are OUT OF SCOPE (deferred to option-D follow-up). Every attention item carries one action only: `Open` → pre-filtered workspace.

---

## File Map

- Modify: `ui/src/App.tsx` — `viewFromHash()` parses optional `?k=v`; `navigate(v, query?)`; pass `initialSeverity/initialStatus/initialSort` into `Findings`, `initialStatus` into `Assets`. Keep `focusAlertId` behavior untouched.
- Modify: `ui/src/views/Findings.tsx` — accept optional `initialSeverity?: string; initialStatus?: string; initialSort?: "oldest"`; `useState(initial ?? "ALL")`; when `initialSort === "oldest"`, default table sort to `created_at` ascending (check DataTable sort API in `components/DataTable.tsx` before editing).
- Modify: `ui/src/views/Assets.tsx` — accept optional `initialStatus?: string`; `useState(initial ?? "ALL")` (check its existing filter control names first; reuse them).
- Create: `ui/src/views/overviewAgg.ts` — pure aggregation helpers + unit tests (no React): `verdictStatus`, `openAlerts`, `bucketTrend`, `alertAgeDays`, `assetCoverage`, `summarizeTrend`, `pickAttention`.
- Create: `ui/src/views/OverviewTrend.tsx` — `TrendChart({ days }: { days: { date: string; critical: number; high: number; other: number }[] })`, hand-rolled SVG stacked area, `role="img"` + `<title>` + adjacent data table for screen readers.
- Modify: `ui/src/views/Overview.tsx` — rewrite into S0–S4 (keep `useCount`→ replace with `useApiList` + `listOf` from `views/hooks.ts`).
- Modify: `ui/src/components.css` — `.status-strip` (4 tones), `.attention-list` rows, `.group-row` rows, `.trend` container.
- Test: `ui/src/views/overview.test.tsx` (agg unit tests + Overview render tests with `mockApi`).

### Endpoint + parser inventory (exact, verified 2026-09-19)

| Data | Endpoint | Parser | Source |
|---|---|---|---|
| alerts | `/api/v1/alerts` | `parseAlert` | contracts.ts |
| assets | `/api/v1/assets` | `parseAsset` | contracts.ts |
| incidents | `/api/v1/incidents` | `parseIncident` | contracts.ts |
| validation results | `/api/v1/validation-results` | `parseValidationResult` | contracts.ts |
| supply components | `/api/v1/supply-chain/components` | `parseSupplyComponent` | contracts.ts |
| supply policies | `/api/v1/supply-chain/policies` | `parseSupplyPolicy` | contracts.ts |

Policy FAIL detection: executor reads `SupplyChain.tsx` lines ~280-320 to reuse its exact fail predicate (evaluate-result based) — do not invent a new one. If `parseSupplyPolicy` items carry no evaluate result inline, S3 policy slot uses the same derivation the SupplyChain view already renders.

---

### Task 1: Pure aggregation module + tests

**Files:**
- Create: `ui/src/views/overviewAgg.ts`
- Test: `ui/src/views/overview.test.tsx` (part 1: agg tests; render tests added in Task 4)

**Interfaces:**
- Consumes: `Alert`, `Asset`, `ValidationResult`, `Incident`, `SupplyComponent`, `SupplyPolicy` types from `../contracts`.
- Produces: `isOpenStatus(s)`, `openAlerts(alerts)`, `alertAgeDays(a, nowMs)`, `bucketTrend(alerts, nowMs)`, `assetCoverage(assets)`, `summarizeTrend(days, attentionCount)`, `verdictStatus(counts)` returning `"ok" | "attention" | "critical" | "unknown"`, `DomainRow { key, label, status, figure, href }`, `buildDomainRows(input)`, `AttentionItem { key, severity, text, context, href }`, `pickAttention(input, nowMs)`.

Input shape for `buildDomainRows`/`pickAttention`: `{ alerts, assets, incidents, results, components, policies }` with the contract types above.

- [ ] **Step 1: Write failing agg tests** (first half of `overview.test.tsx`)

```tsx
import { describe, expect, it } from "vitest";
import {
  assetCoverage,
  bucketTrend,
  openAlerts,
  pickAttention,
  summarizeTrend,
} from "./overviewAgg";
import type { Alert } from "../contracts";

const NOW = Date.parse("2026-09-19T12:00:00Z");
function alert(
  id: string,
  created_at: string,
  severity: Alert["severity"] = "SEVERITY_HIGH",
  status: Alert["status"] = "ALERT_STATUS_OPEN",
): Alert {
  return {
    id,
    detection_ids: [],
    status,
    severity,
    created_at,
    updated_at: created_at,
    title: `finding ${id}`,
  };
}

describe("overviewAgg", () => {
  it("openAlerts excludes closed findings", () => {
    const all = [
      alert("a", "2026-09-18T00:00:00Z"),
      alert("b", "2026-09-18T00:00:00Z", "SEVERITY_LOW", "ALERT_STATUS_ACKNOWLEDGED"),
      alert("c", "2026-09-18T00:00:00Z", "SEVERITY_LOW", "ALERT_STATUS_CLOSED"),
    ];
    expect(openAlerts(all).map((a) => a.id)).toEqual(["a", "b"]);
  });

  it("bucketTrend stacks 30 days by severity", () => {
    const days = bucketTrend(
      [
        alert("a", "2026-09-19T01:00:00Z", "SEVERITY_CRITICAL"),
        alert("b", "2026-09-10T01:00:00Z", "SEVERITY_HIGH"),
        alert("c", "2026-08-01T01:00:00Z"),
      ],
      NOW,
    );
    expect(days).toHaveLength(30);
    expect(days[29]).toMatchObject({ critical: 1, high: 0, other: 0 });
    expect(days[20]).toMatchObject({ critical: 0, high: 1, other: 0 });
    expect(days.reduce((n, d) => n + d.critical + d.high + d.other, 0)).toBe(2);
  });

  it("assetCoverage counts ACTIVE over ACTIVE+STALE", () => {
    const cov = assetCoverage([
      { id: "1", type: "ASSET_TYPE_HOST", name: "a", status: "ASSET_STATUS_ACTIVE" },
      { id: "2", type: "ASSET_TYPE_HOST", name: "b", status: "ASSET_STATUS_STALE" },
      { id: "3", type: "ASSET_TYPE_HOST", name: "c", status: "ASSET_STATUS_RETIRED" },
      { id: "4", type: "ASSET_TYPE_HOST", name: "d" },
    ]);
    expect(cov).toEqual({ monitored: 4, active: 1, stale: 1, ratio: 0.5 });
  });

  it("pickAttention caps at five with oldest critical first", () => {
    const items = pickAttention(
      {
        alerts: [
          alert("old", "2026-09-01T00:00:00Z", "SEVERITY_CRITICAL"),
          alert("new", "2026-09-18T00:00:00Z", "SEVERITY_CRITICAL"),
        ],
        assets: [],
        incidents: [],
        results: [],
        components: [],
        policies: [],
      },
      NOW,
    );
    expect(items.length).toBeLessThanOrEqual(5);
    expect(items[0].key).toContain("old");
  });

  it("summarizeTrend is honest when empty", () => {
    expect(summarizeTrend([], 0)).toMatch(/not yet enough data/i);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/overview.test.tsx` in `collector/ui`
Expected: FAIL — `overviewAgg` module missing

- [ ] **Step 3: Implement `overviewAgg.ts`**

```ts
import type {
  Alert,
  Asset,
  Incident,
  SupplyComponent,
  SupplyPolicy,
  ValidationResult,
} from "../contracts";

export type DomainStatus = "ok" | "attention" | "critical" | "unknown";

export function isOpenStatus(s: Alert["status"]): boolean {
  // "Open" for executives = OPEN or ACKNOWLEDGED. CLOSED is resolved.
  return s === "ALERT_STATUS_OPEN" || s === "ALERT_STATUS_ACKNOWLEDGED";
}

export function openAlerts(alerts: Alert[]): Alert[] {
  return alerts.filter((a) => isOpenStatus(a.status));
}

export function alertAgeDays(a: Alert, nowMs: number): number {
  const t = Date.parse(a.created_at);
  if (Number.isNaN(t)) return 0;
  return Math.max(0, Math.floor((nowMs - t) / 86_400_000));
}

export interface TrendDay {
  date: string; // YYYY-MM-DD (UTC)
  critical: number;
  high: number;
  other: number;
}

export function bucketTrend(alerts: Alert[], nowMs: number): TrendDay[] {
  const days: TrendDay[] = [];
  const start = new Date(nowMs);
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - 29);
  const index = new Map<string, TrendDay>();
  for (let i = 0; i < 30; i++) {
    const d = new Date(start.getTime() + i * 86_400_000);
    const key = d.toISOString().slice(0, 10);
    const row: TrendDay = { date: key, critical: 0, high: 0, other: 0 };
    days.push(row);
    index.set(key, row);
  }
  for (const a of openAlerts(alerts)) {
    const t = Date.parse(a.created_at);
    if (Number.isNaN(t)) continue;
    const row = index.get(new Date(t).toISOString().slice(0, 10));
    if (!row) continue; // older than 30 days: out of window, not dropped silently (counted in cards)
    if (a.severity === "SEVERITY_CRITICAL") row.critical += 1;
    else if (a.severity === "SEVERITY_HIGH") row.high += 1;
    else row.other += 1;
  }
  return days;
}

export interface Coverage {
  monitored: number;
  active: number;
  stale: number;
  ratio: number | null; // null when ACTIVE+STALE is 0
}

export function assetCoverage(assets: Asset[]): Coverage {
  let active = 0;
  let stale = 0;
  for (const a of assets) {
    if (a.status === "ASSET_STATUS_ACTIVE") active += 1;
    else if (a.status === "ASSET_STATUS_STALE") stale += 1;
  }
  const denom = active + stale;
  return {
    monitored: assets.length,
    active,
    stale,
    ratio: denom === 0 ? null : active / denom,
  };
}

export function summarizeTrend(days: TrendDay[], attentionCount: number): string {
  const total = days.reduce((n, d) => n + d.critical + d.high + d.other, 0);
  if (total === 0)
    return "Not yet enough data for a trend — run a scan or a first validation to see movement.";
  const first7 = days.slice(0, 7).reduce((n, d) => n + d.critical, 0);
  const last7 = days.slice(-7).reduce((n, d) => n + d.critical, 0);
  const tail =
    attentionCount > 0
      ? ` ${attentionCount} item${attentionCount === 1 ? "" : "s"} still need${attentionCount === 1 ? "s" : ""} a decision.`
      : " Nothing is waiting for a decision.";
  if (last7 < first7)
    return `Critical findings are trending down over the last 30 days.${tail}`;
  if (last7 > first7)
    return `Critical findings are trending up over the last 30 days.${tail}`;
  return `Critical findings are flat over the last 30 days.${tail}`;
}

export interface AttentionItem {
  key: string;
  severity: "critical" | "high" | "info";
  text: string;
  context: string;
  href: string;
}

export interface AttentionInput {
  alerts: Alert[];
  assets: Asset[];
  incidents: Incident[];
  results: ValidationResult[];
  components: SupplyComponent[];
  policies: SupplyPolicy[];
}

export function pickAttention(input: AttentionInput, nowMs: number): AttentionItem[] {
  const out: AttentionItem[] = [];
  const open = openAlerts(input.alerts)
    .map((a) => ({ a, age: alertAgeDays(a, nowMs) }))
    .sort((x, y) => y.age - x.age);
  for (const { a, age } of open) {
    if (a.severity === "SEVERITY_CRITICAL" && age > 7 && out.length < 2) {
      out.push({
        key: `alert-${a.id}`,
        severity: "critical",
        text: a.title,
        context: `Critical, open ${age} days`,
        href: `#/findings?severity=SEVERITY_CRITICAL&status=ALERT_STATUS_OPEN`,
      });
    }
  }
  for (const { a, age } of open) {
    if (out.length >= 5) break;
    if (age > 30 && !out.some((i) => i.key === `alert-${a.id}`)) {
      out.push({
        key: `alert-${a.id}`,
        severity: "high",
        text: a.title,
        context: `Open ${age} days — needs a decision`,
        href: `#/findings?status=ALERT_STATUS_OPEN&sort=oldest`,
      });
    }
  }
  return out.slice(0, 5);
}

export interface DomainRow {
  key: string;
  label: string;
  status: DomainStatus;
  figure: string;
  href: string;
}

function statusFor(open: Alert[], kinds: Alert["severity"][]): DomainStatus {
  if (open.some((a) => a.severity === "SEVERITY_CRITICAL")) return "critical";
  if (open.some((a) => kinds.includes(a.severity))) return "attention";
  return "ok";
}

export function buildDomainRows(input: AttentionInput): DomainRow[] {
  const open = openAlerts(input.alerts);
  const activeIncidents = input.incidents.filter(
    (i) => i.status === "INCIDENT_STATUS_OPEN" || i.status === "INCIDENT_STATUS_INVESTIGATING",
  );
  const failingPolicies = input.policies.filter((p) => {
    const r = (p as { last_result?: string }).last_result;
    return r === "FAIL";
  });
  const badResults = input.results.filter(
    (r) => r.verdict === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
  );
  return [
    {
      key: "surface",
      label: "Attack Surface",
      status: open.length === 0 ? "unknown" : statusFor(open, ["SEVERITY_HIGH"]),
      figure: `${open.length} open findings`,
      href: "#/findings?status=ALERT_STATUS_OPEN",
    },
    {
      key: "supply",
      label: "Supply Chain",
      status:
        input.components.length === 0
          ? "unknown"
          : failingPolicies.length > 0
            ? "critical"
            : "ok",
      figure: `${input.components.length} components · ${failingPolicies.length} failing policies`,
      href: "#/supply-chain",
    },
    {
      key: "ops",
      label: "Operations",
      status: activeIncidents.length > 0 ? "attention" : "ok",
      figure: `${activeIncidents.length} active incidents`,
      href: "#/incidents",
    },
    {
      key: "gov",
      label: "Governance & Validation",
      status:
        input.results.length === 0
          ? "unknown"
          : badResults.length > 0
            ? "critical"
            : "ok",
      figure:
        input.results.length === 0
          ? "No validation results yet"
          : `${input.results.length} results · ${badResults.length} undetected`,
      href: "#/validation",
    },
  ];
}
```

NOTE on `last_result`: executor must check `parseSupplyPolicy` output shape in `contracts.ts` (~line 1762) and `SupplyChain.tsx` fail predicate; replace `(p as { last_result?: string }).last_result` with the real field. If policies carry no inline result, derive FAIL by reusing the exact predicate from `SupplyChain.tsx`.

- [ ] **Step 4: Run agg tests**

Run: `npx vitest run src/views/overview.test.tsx` in `collector/ui`
Expected: PASS (5 tests)

---

### Task 2: Hash query routing + initial filters

**Files:**
- Modify: `ui/src/App.tsx:42-70` (`viewFromHash`, `navigate`, hashchange effect) and render block lines ~196-219
- Modify: `ui/src/views/Findings.tsx:106-118` (filter state) — read rest of file first (lines 120-319) to match existing sort mechanism
- Modify: `ui/src/views/Assets.tsx` (filter state — read file first, reuse existing control)
- Test: extend `ui/src/views/overview.test.tsx` with a routing test, OR add `ui/src/views/hashfilter.test.tsx`. Use the latter (isolated).

**Interfaces:**
- Consumes: existing `NAV`, `ViewId`, `navigate`.
- Produces: `viewFromHash(): { view: ViewId; query: URLSearchParams }`; `navigate(v, query?: string)`; `<Findings initialSeverity? initialStatus? initialSort?>`; `<Assets initialStatus?>`.

- [ ] **Step 1: Write failing routing test** (`ui/src/views/hashfilter.test.tsx`)

```tsx
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import { Findings } from "./Findings";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

describe("hash initial filters", () => {
  it("Findings preselects severity from initial props", async () => {
    mockApi({
      "/api/v1/alerts": { data: [alertJson] },
      "/api/v1/detections": { data: [] },
      "/api/v1/telemetry": { data: [] },
    });
    render(<Findings initialSeverity="SEVERITY_CRITICAL" initialStatus="ALL" />);
    await waitFor(() => expect(screen.getByText("Findings")).toBeInTheDocument());
    // Executor: replace "Severity" with the real select label in Findings.tsx.
    const sel = screen.getByLabelText("Severity") as HTMLSelectElement;
    expect(sel.value).toBe("SEVERITY_CRITICAL");
  });
});
```

(Executor: verify fixture path `contracts/fixtures/alert/valid.json` exists — check `contracts/fixtures` dir; use an existing alert fixture. Verify the real severity `<select>` accessible label in Findings.tsx lines 120-319 before finalizing the test.)

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/hashfilter.test.tsx`
Expected: FAIL — `initialSeverity` prop unknown

- [ ] **Step 3: Implement**

App.tsx:
```tsx
function viewAndQuery(): { view: ViewId; query: URLSearchParams } {
  const raw = window.location.hash.replace("#/", "");
  const qi = raw.indexOf("?");
  const v = qi === -1 ? raw : raw.slice(0, qi);
  return {
    view: (NAV.some((n) => n.id === v) ? v : "overview") as ViewId,
    query: new URLSearchParams(qi === -1 ? "" : raw.slice(qi + 1)),
  };
}
```
Keep `viewFromHash()` name/signature if other code uses it — executor greps usages first; simplest is to keep `viewFromHash(): ViewId` and add `hashQuery(): URLSearchParams` beside it. State: `const [query, setQuery] = useState(hashQuery)` updated in the same `hashchange` handler. `navigate(v, q?)` sets `window.location.hash = q ? \`#/${v}?${q}\` : \`#/${v}\``.

Render: `<Findings initialSeverity={query.get("severity") ?? undefined} initialStatus={query.get("status") ?? undefined} initialSort={query.get("sort") ?? undefined} ... />`, `<Assets initialStatus={query.get("status") ?? undefined} />`. Validate values against `SEVERITIES`/`ALERT_STATUSES`/`ASSET_STATUSES` before passing (ignore unknown values → undefined).

Findings.tsx: `useState(initialSeverity ?? "ALL")`, `useState(initialStatus ?? "ALL")`; if `initialSort === "oldest"`, initialize sort state to created-ascending (match DataTable's sort API — read `components/DataTable.tsx` first).

Assets.tsx: same pattern for its status filter.

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/views/hashfilter.test.tsx` then `npm test`
Expected: PASS; existing view tests unaffected (props optional)

---

### Task 3: TrendChart component + CSS

**Files:**
- Create: `ui/src/views/OverviewTrend.tsx`
- Modify: `ui/src/components.css` (append `.status-strip*`, `.attention*`, `.group-row*`, `.trend*` — full block below)
- Test: render test inside `overview.test.tsx` part 2 (Task 4) — chart covered via Overview render.

**Interfaces:**
- Consumes: `TrendDay[]` from `overviewAgg.ts`.
- Produces: `TrendChart({ days })` — SVG 640x160 viewBox, three stacked paths (critical/high/other) using existing `--bv-sev-*` fills at 0.75/0.55/0.35 opacity, axes minimal (30-day window label + max tick), `role="img"`, `<title>`, plus visually-hidden table of values.

- [ ] **Step 1: CSS append** (exact block)

```css
/* ---- Executive overview ---- */
.status-strip {
  display: flex;
  align-items: center;
  gap: 12px;
  border-radius: var(--bv-radius-l);
  padding: 12px 24px;
  margin-bottom: 32px;
  border: 1px solid var(--bv-border);
  background: var(--bv-card);
  font-weight: 600;
}
.status-strip.critical {
  border-color: var(--bv-bad);
}
.status-strip.attention {
  border-color: var(--bv-warn);
}
.status-strip.ok {
  border-color: var(--bv-ok);
}
.status-strip.unknown {
  border-style: dashed;
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.status-strip.critical .status-dot {
  background: var(--bv-bad);
}
.status-strip.attention .status-dot {
  background: var(--bv-warn);
}
.status-strip.ok .status-dot {
  background: var(--bv-ok);
}
.status-strip.unknown .status-dot {
  background: var(--bv-muted);
}

.attention-list {
  list-style: none;
  margin: 0 0 32px;
  padding: 0;
  background: var(--bv-card);
  border: 1px solid var(--bv-border);
  border-radius: var(--bv-radius-l);
}
.attention-list li {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 24px;
  border-bottom: 1px solid var(--bv-border);
}
.attention-list li:last-child {
  border-bottom: none;
}
.attention-text {
  flex: 1;
  min-width: 0;
}
.attention-context {
  color: var(--bv-muted);
  font-size: 12.5px;
  white-space: nowrap;
}

.group-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 24px;
  border-bottom: 1px solid var(--bv-border);
}
.group-row:last-child {
  border-bottom: none;
}
.group-row .group-label {
  font-weight: 600;
}
.group-row .group-figure {
  color: var(--bv-muted);
  font-size: 13px;
  flex: 1;
}

.trend {
  background: var(--bv-card);
  border: 1px solid var(--bv-border);
  border-radius: var(--bv-radius-l);
  padding: 16px 24px;
  margin-bottom: 32px;
}
.trend-summary {
  color: var(--bv-ink-soft);
  font-size: 13.5px;
  margin: 8px 0 0;
}
```

- [ ] **Step 2: Implement OverviewTrend.tsx**

```tsx
import type { TrendDay } from "./overviewAgg";

const W = 640;
const H = 160;
const PAD = 8;

export function TrendChart({ days }: { days: TrendDay[] }) {
  const max = Math.max(1, ...days.map((d) => d.critical + d.high + d.other));
  const x = (i: number) => PAD + (i / Math.max(1, days.length - 1)) * (W - PAD * 2);
  const y = (v: number) => H - PAD - (v / max) * (H - PAD * 2);
  const layer = (pick: (d: TrendDay) => number, base: (d: TrendDay) => number) => {
    const top = days.map((d, i) => `${x(i)},${y(base(d) + pick(d))}`).join(" ");
    const bot = days
      .map((d, i) => `${x(i)},${y(base(d))}`)
      .reverse()
      .join(" ");
    return `M${top} L${bot} Z`;
  };
  const other = (d: TrendDay) => d.other;
  const highBase = (d: TrendDay) => d.other;
  const high = (d: TrendDay) => d.high;
  const critBase = (d: TrendDay) => d.other + d.high;
  const crit = (d: TrendDay) => d.critical;
  return (
    <div className="trend-chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Open findings trend, last 30 days" width="100%">
        <title>{`Peak ${max} open findings in the last 30 days`}</title>
        <path d={layer(other, () => 0)} fill="var(--bv-sev-info)" opacity={0.35} />
        <path d={layer(high, highBase)} fill="var(--bv-sev-high)" opacity={0.55} />
        <path d={layer(crit, critBase)} fill="var(--bv-sev-critical)" opacity={0.75} />
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
```

(`.sr-only` already exists in tokens.css lines ~194-201.)

- [ ] **Step 3: Gates**

Run: `npm run typecheck && npm run format` in `collector/ui`
Expected: PASS

---

### Task 4: Rewrite Overview (S0–S4) + render tests

**Files:**
- Modify: `ui/src/views/Overview.tsx` (full rewrite, keep file path + export name `Overview`)
- Test: `ui/src/views/overview.test.tsx` (part 2: render tests appended)

**Interfaces:**
- Consumes: `useApiList`, `listOf` (views/hooks.ts), all six endpoint/parser pairs, `overviewAgg.ts`, `TrendChart`, `StatCard` (with href/delta), `EmptyState`/`ErrorState`/`StatSkeleton`, `StatusBadge`/`SeverityBadge` for dots (or plain `.status-dot` spans).
- Produces: unchanged export `Overview()`; per-section skeletons (not one page spinner): each section renders its own `StatSkeleton`-scale placeholder while its data loads; a section renders only when all its inputs are ready; backend-error/invalid in ANY input → `ErrorState` (never partial numbers beside an error).

- [ ] **Step 1: Write failing render tests** (append to overview.test.tsx)

```tsx
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Overview } from "./Overview";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const ALERT = {
  id: "al-1",
  detection_ids: [],
  status: "ALERT_STATUS_OPEN",
  severity: "SEVERITY_CRITICAL",
  created_at: "2026-09-10T00:00:00Z",
  updated_at: "2026-09-10T00:00:00Z",
  title: "Critical finding",
};
const ASSET = { id: "as-1", type: "ASSET_TYPE_HOST", name: "host-1", status: "ASSET_STATUS_ACTIVE" };
const FULL = {
  "/api/v1/alerts": { data: [ALERT] },
  "/api/v1/assets": { data: [ASSET] },
  "/api/v1/incidents": { data: [] },
  "/api/v1/validation-results": { data: [] },
  "/api/v1/supply-chain/components": { data: [] },
  "/api/v1/supply-chain/policies": { data: [] },
};

describe("Overview executive", () => {
  it("renders status strip, four cards, trend, attention, and domains", async () => {
    mockApi(FULL);
    render(<Overview />);
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(screen.getByText(/needs attention/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /findings/i })).toBeInTheDocument();
    expect(screen.getByText(/trend/i)).toBeInTheDocument();
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });

  it("every stat number links to a pre-filtered workspace", async () => {
    mockApi(FULL);
    render(<Overview />);
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    const links = screen.getAllByRole("link");
    for (const l of links) {
      expect(l.getAttribute("href")).toMatch(/^#\//);
    }
    expect(links.some((l) => (l.getAttribute("href") ?? "").includes("?"))).toBe(true);
  });

  it("is honest when empty", async () => {
    mockApi({
      "/api/v1/alerts": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/incidents": { data: [] },
      "/api/v1/validation-results": { data: [] },
      "/api/v1/supply-chain/components": { data: [] },
      "/api/v1/supply-chain/policies": { data: [] },
    });
    render(<Overview />);
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(screen.getByText(/not enough data/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/overview.test.tsx`
Expected: FAIL — Overview has no status strip / links

- [ ] **Step 3: Rewrite Overview.tsx**

Structure (exact section order, exact copy):
1. `<h1 className="page-title">Overview</h1>` + `<p className="page-sub">Posture at a glance. Every number opens its workspace, pre-filtered.</p>` (keep these two lines verbatim so existing e2e/screenshot title assertions keep passing).
2. S0 `.status-strip.{tone}`: verdict precedence — (a) any input empty-of-data AND all empty → `unknown` + "Not enough data yet — connect a source to see posture." (b) critical open > 0 → `critical` + "Needs attention — {N} critical open, oldest {X} days." (c) failingPolicies > 0 → `critical` + "Needs attention — {name} failing ({N} violations)." (d) any open age > 30 → `attention` + "{N} aging findings (30+ days) — need a decision." (e) else `ok` + "Controlled — no critical open · {today YYYY-MM-DD}."
3. S1 four `StatCard` with `href` + `delta`:
   - Findings: value `{open} open`, caption `{C} critical · {H} high`, delta `[AGG] 7-day open delta (▲+N red-bad / ▼−N green-good / "— steady" neutral)` computed from `created_at` vs now−7d, href `#/findings?status=ALERT_STATUS_OPEN`. Low-data caption: "None open — clean or not yet scanned."
   - Coverage: value `{monitored} watched`, caption `{active} active · {stale} stale`, no delta, href `#/assets?status=ASSET_STATUS_STALE`.
   - Response age: value = mean age days of open (`{N}d avg`), caption `Oldest: {title} ({X}d)`, delta = 30-day mean trend direction (up=bad), href `#/findings?status=ALERT_STATUS_OPEN&sort=oldest`. Empty-open caption: "No open findings."
   - Validation: value = latest `validated_at` date (`MMM D`) or "—", caption `{R} results · {B} undetected` (B = ALLOWED_AND_NOT_DETECTED count), no delta, href `#/validation`. Empty caption: "Never validated — findings above are untested."
4. S2 `.trend`: `<h2 className="title">30-day trend</h2>` + `<TrendChart days>` + `<p className="trend-summary">{summarizeTrend(days, attention.length)}</p>`.
5. S3 attention: `<h2 className="title">Needs your decision</h2>` + `<ul className="attention-list">` rows (`status-dot` + text + context + `<a>Open →</a>`); when empty, render `<p className="body">✓ Nothing needs a decision this week.</p>` and NOT the list.
6. S4 domains: `<h2 className="title">Domains</h2>` + `<div className="panel">` rows `group-row` (dot + label + figure + `chevron →` link). Status dot uses `.status-dot` inside `.status-strip`-tone-colored span — simplest: `<span className={\`status-dot\`} style={{ background: "var(--bv-bad)" }} />` per status (ok→`--bv-ok`, attention→`--bv-warn`, critical→`--bv-bad`, unknown→`--bv-muted`).
7. Loading: per-section skeletons — while any input for a section is loading, that section shows `<StatSkeleton />` (S1), `<TableSkeleton rows={3} />` (S3/S4), heading skeleton for S2; sections pop in independently. Error: first backend-error/invalid across ALL inputs → whole-page `ErrorState` (same copy pattern as current code).

- [ ] **Step 4: Run full gates**

Run: `npm test && npm run build && npm run format` in `collector/ui`
Expected: PASS (68 + ~10 new tests)

---

## Self-Review

- Spec coverage: S0 ✓ S1 ✓ (4 cards, deltas, links) S2 ✓ (chart + deterministic template) S3 ✓ (5-item rule, Open-only) S4 ✓ (4 rows — spec said 5 groups; Identity folded into Attack Surface row? NO — fix: 5 rows: Attack Surface, Identity & Data, Supply Chain, Operations, Governance & Validation. Identity row: figure from alerts? Identity has no dedicated endpoint in the inventory above. RESOLUTION: 4 rows as implemented (surface/supply/ops/gov); Identity & Data coverage arrives with the workspace-strip rollout when its data source is wired. Record this as a deferred item, not silent scope cut.)
- Contract rules: every number links ✓ (test asserts), low-data next actions ✓, honest language ✓, max 5 sections ✓, per-section skeletons ✓.
- Placeholders: one executor-check (policy FAIL predicate + fixture/label names) — flagged explicitly with file:line pointers, not hidden.
- Type consistency: `href="#/findings?..."` strings match `hashQuery()` parsing in Task 2; `TrendDay` shared between agg/chart.
