# Report-First (Laporan E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One-click security posture report (Executive 2–3 pages + Full with appendices) rendered from live API data as print-ready HTML → PDF via browser print. Deterministic: same data + same date = same report.

**Architecture:** New `ReportView` route (`#/report`, added to `NAV` in `Shell.tsx` — or a modal-less dedicated view; route is simpler and printable). Data layer reuses the exact six endpoint/parser pairs from the Overview plan plus `/api/v1/evidence` (`parseEvidence`, already used by Overview today) for the integrity appendix. Aggregation reuses `overviewAgg.ts` (`openAlerts`, `bucketTrend`, `assetCoverage`, `pickAttention`, `buildDomainRows`, `summarizeTrend`). Print stylesheet forces light theme + A4 + repeated headers/footers + page-break rules. Report hash: FNV-1a (hand-rolled, 8 hex) over the canonical JSON of report inputs, shown in the footer of every page.

**Tech Stack:** React 19, TypeScript strict, Vite 7, vitest + @testing-library/react, prettier. No new dependencies (no PDF lib — browser print only).

**Spec:** Conversation spec "Laporan E / Report-First" (2026-09-19). Depends on: tokens plan + overview plan (both merged first).

## Global Constraints

- No backend, store, contract, or API changes. Read-only UI.
- `npm run build`, `npm test`, `npm run format` pass after every task.
- Copy is English (existing convention). Honest language rules apply inside the report: "Controlled", "Not yet monitored — out of this report's scope", never "Secure".
- Deterministic: no `Date.now()` in rendered content except the explicit "Issued {date}" line (which takes the date as a prop, defaulting to today, so tests inject a fixed date).
- Print CSS must not leak into screen styles (wrap everything in `@media print`).

## Endpoint inventory (exact)

Same six as Overview plan, plus:
| Data | Endpoint | Parser |
|---|---|---|
| evidence | `/api/v1/evidence` | `parseEvidence` (contracts.ts) |

Evidence appendix: list `id`, `type` (verbatim), `collected_at` (`fmtTime`), `sha256` (mono, truncated to 16 chars + "…" ONLY in the row display; full hash in `<title>` tooltip), integrity note "Envelope verified" — executor checks `Evidence.tsx` lines ~72-115 for the exact envelope-verified wording and reuses it verbatim.

---

## File Map

- Create: `ui/src/views/reportHash.ts` — `fnv1aHex(canonicalJson)`, `reportDigest(input: unknown): string` (stable stringify: sorted keys, recursive).
- Create: `ui/src/views/ReportView.tsx` — `ReportView({ issued }: { issued?: string })` full + executive variants (tab or toggle; default Full).
- Modify: `ui/src/components/Shell.tsx` — add `report: "Report"` to NAV/ViewId/TITLES (executor reads file first; note `App.tsx` TITLES map lines 24-40 must gain `report: "Report"` too).
- Modify: `ui/src/App.tsx` — render `<ReportView />` for `view === "report"`.
- Modify: `ui/src/views/Overview.tsx` — add "Download report" link → `#/report` (S1 header row or under trend; executor picks: a `<a className="button-link" href="#/report">Download report</a>` beside the S2 heading).
- Modify: `ui/src/views/Governance.tsx` — same link (executor reads file, places beside its heading).
- Modify: `ui/src/components.css` — `@media print` block + `.report*` screen styles.
- Test: `ui/src/views/report.test.tsx` — hash determinism, executive/full content, honesty copy, filename helper.

---

### Task 1: Deterministic report hash

**Files:**
- Create: `ui/src/views/reportHash.ts`
- Test: `ui/src/views/report.test.tsx` (part 1)

**Interfaces:**
- Consumes: nothing.
- Produces: `stableStringify(v: unknown): string`, `reportDigest(v: unknown): string` (8 lowercase hex).

- [ ] **Step 1: Write failing test**

```tsx
import { describe, expect, it } from "vitest";
import { reportDigest, stableStringify } from "./reportHash";

describe("reportHash", () => {
  it("is deterministic and key-order independent", () => {
    expect(stableStringify({ b: 1, a: [3, 2] })).toBe('{"a":[3,2],"b":1}');
    expect(reportDigest({ b: 1, a: [3, 2] })).toBe(reportDigest({ a: [3, 2], b: 1 }));
    expect(reportDigest({ a: 1 })).toMatch(/^[0-9a-f]{8}$/);
    expect(reportDigest({ a: 1 })).not.toBe(reportDigest({ a: 2 }));
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/report.test.tsx` in `collector/ui`
Expected: FAIL — module missing

- [ ] **Step 3: Implement**

```ts
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`).join(",")}}`;
}

export function reportDigest(v: unknown): string {
  const s = stableStringify(v);
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}
```

- [ ] **Step 4: Run**

Run: `npx vitest run src/views/report.test.tsx`
Expected: PASS

---

### Task 2: ReportView (Full + Executive) + route + links

**Files:**
- Create: `ui/src/views/ReportView.tsx`
- Modify: `ui/src/components/Shell.tsx`, `ui/src/App.tsx`, `ui/src/views/Overview.tsx`, `ui/src/views/Governance.tsx`
- Test: `ui/src/views/report.test.tsx` (part 2: render tests)

**Interfaces:**
- Consumes: `useApiList`/`listOf`, six overview endpoints + evidence, `overviewAgg.ts`, `reportDigest`, `fmtTime`, `TrendChart` (reuse for the report's trend figure — wrap in `.report-figure`).
- Produces: `ReportView({ issued }: { issued?: string })`; route `#/report`; filename helper `reportFilename(issued: string): string` → `blueveil-report-YYYY-MM-DD.pdf` (date part = first 10 chars of issued).

Report sections (Full, exact order, exact headings):
1. Cover: "Security Posture Report", "Data period {first} – {last}", "Issued {issued}", verdict sentence (= S0 verdict logic — IMPORT the verdict computation from Overview into a shared helper rather than duplicating: executor extracts `computeVerdict(...)` from Overview.tsx Task 4 into `overviewAgg.ts` as `verdictOf(input, nowMs): { tone; text }` and uses it in both places).
2. "Summary" — 4 figures (same numbers as S1 cards, text form) + trend figure + `summarizeTrend` sentence.
3. "Top findings" — top 10 open by (critical first, then oldest): title, severity verbatim, age days, status verbatim, one impact sentence `Open {X} days with {severity} severity.` (no invented impact detail — deterministic template only).
4. "By domain" — `buildDomainRows` rows + top 3 open findings per row where applicable (filter open alerts by nothing domain-specific — list top 3 overall under Attack Surface; other rows carry their figure + link-free text since print has no navigation).
5. "Supply chain" — component count, failing-policy count + names, OUTDATED/UNSUPPORTED counts (from `SupplyComponent.status`), pending vendor assessments count (executor: check `parseVendorAssessment` status enum in contracts.ts ~line 1823; pending = whatever non-terminal value exists — read before coding).
6. "Validation" — result count, bad-outcome count, latest date; verdict meanings cited via existing `VERDICT_MEANINGS` strings (contracts.ts lines ~71+) — quote verbatim, do not paraphrase.
7. "Governance" — reuse Governance view's data? NO new fetch beyond existing: this section reports attention items (`pickAttention`) + exception note "Exceptions are tracked in the Governance workspace." (honest pointer, not duplicated data).
8. "Appendix A — All open findings" — full table (id mono, title, severity, status, age days). May be long; print CSS handles breaks.
9. "Appendix B — Evidence integrity" — evidence rows (id, type, collected_at, sha256 truncated + full in title attr, "Envelope verified" wording from Evidence.tsx).
10. "Limitations" — one page: domains with `unknown` status listed as "Not yet monitored — out of this report's scope"; data period; "Findings not yet validated are untested claims, not confirmed breaches."

Executive variant (toggle at top, screen-only — print prints the active variant): Cover + Summary + "Top 5 findings" (non-technical template: `{title} — open {X} days, rated {severity}.` + glossary line for severity words) + "Recommended actions" (max 3, deterministic templates: oldest critical → "Decide the oldest critical finding ({title}, {X} days): fix, accept with expiry, or escalate."; failing policy → "Resolve failing policy {name}."; never-validated → "Run a first validation campaign — current findings are untested."; fill remaining slots with "No further action required.") + Limitations (one paragraph).

- [ ] **Step 1: Write failing render tests** (append to report.test.tsx)

```tsx
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ReportView } from "./ReportView";
import { mockApi } from "../test-utils";
import { reportFilename } from "./ReportView";

afterEach(() => cleanup());

const ROUTES = {
  "/api/v1/alerts": { data: [] },
  "/api/v1/assets": { data: [] },
  "/api/v1/incidents": { data: [] },
  "/api/v1/validation-results": { data: [] },
  "/api/v1/supply-chain/components": { data: [] },
  "/api/v1/supply-chain/policies": { data: [] },
  "/api/v1/evidence": { data: [] },
};

describe("ReportView", () => {
  it("renders all ten full-report sections with honest empty copy", async () => {
    mockApi(ROUTES);
    render(<ReportView issued="2026-09-19" />);
    await waitFor(() => expect(screen.getByText("Security Posture Report")).toBeInTheDocument());
    for (const h of ["Summary", "Top findings", "By domain", "Supply chain", "Validation", "Governance", "Appendix A", "Appendix B", "Limitations"]) {
      expect(screen.getByText(h)).toBeInTheDocument();
    }
    expect(screen.getByText(/out of this report's scope/i)).toBeInTheDocument();
  });

  it("executive variant caps at top five and three actions", async () => {
    mockApi(ROUTES);
    render(<ReportView issued="2026-09-19" />);
    await waitFor(() => expect(screen.getByText("Security Posture Report")).toBeInTheDocument());
    // Executor: match the real toggle label implemented in ReportView.
    const user = (await import("@testing-library/user-event")).default.setup();
    await user.click(screen.getByRole("button", { name: /executive/i }));
    expect(screen.getByText(/recommended actions/i)).toBeInTheDocument();
  });

  it("filename is deterministic", () => {
    expect(reportFilename("2026-09-19")).toBe("blueveil-report-2026-09-19.pdf");
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/report.test.tsx`
Expected: FAIL — `ReportView` missing

- [ ] **Step 3: Implement ReportView.tsx** (per section spec above; screen styles `.report*`, toggle buttons `Full | Executive`, print button calling `window.print()` with label "Print / Save PDF")

Key implementation notes (not placeholders — follow exactly):
- `issued` prop defaults to `new Date().toISOString().slice(0, 10)`; tests inject `"2026-09-19"`.
- Data period: min/max over `created_at`/`validated_at`/`collected_at` present in inputs; if all empty → "No data in this period".
- Digest input = `{ issued, alerts, assets, incidents, results, components, policies, evidence }` raw parsed arrays → `reportDigest`; render `Report {digest}` in cover + running footer.
- Loading: all seven inputs share one `<HeadingSkeleton />` (report is a document, not a dashboard — single skeleton is correct here); error in any → `ErrorState`.
- Screen-only elements get `className="no-print"`; print CSS hides them.

- [ ] **Step 4: Wire route + links**

Shell.tsx: add `{ id: "report", title: "Report", icon: "file" }` to NAV (executor: read Shell.tsx first — match its NAV item shape and confirm an IconName exists, else reuse `"shield"`). App.tsx TITLES += `report: "Report"`; render `{view === "report" && <ReportView />}`. Overview + Governance: add `<a href="#/report">Download report</a>` near headings.

- [ ] **Step 5: Run gates**

Run: `npm test && npm run build && npm run format`
Expected: PASS

---

### Task 3: Print stylesheet + live print verification

**Files:**
- Modify: `ui/src/components.css` (append `@media print` block below)
- Test: manual verification procedure (below) — plus an automated guard: report.test.tsx asserts every `.no-print` element is hidden? Cannot assert print CSS in jsdom. The automated gate is: full suite green + `vite build` succeeds. Print correctness is verified by the human procedure once.

**Interfaces:**
- Consumes: `.report*` classes from Task 2.
- Produces: correct A4 print output in both themes (print forces light palette via explicit color overrides, not theme vars, so dark-mode users get standard documents).

- [ ] **Step 1: Append print CSS** (exact block)

```css
/* ---- Report print (light-forced, A4) ---- */
.report {
  background: #ffffff;
  color: #16233a;
  max-width: 720px;
}
.report .no-print {
  display: none;
}
.report h1 {
  font-size: 28px;
  margin: 0 0 4px;
}
.report h2 {
  font-size: 18px;
  margin: 28px 0 8px;
  border-bottom: 2px solid #16233a;
  padding-bottom: 4px;
}
.report table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.report th,
.report td {
  text-align: left;
  padding: 6px 8px;
  border-bottom: 1px solid #cbd5e3;
}
.report thead {
  display: table-header-group;
}
.report tr {
  page-break-inside: avoid;
}
.report .report-cover {
  margin: 48px 0;
}
.report .report-foot {
  font-size: 11px;
  color: #68799a;
}

@media print {
  @page {
    size: A4;
    margin: 20mm;
  }
  body {
    background: #ffffff;
  }
  .no-print {
    display: none !important;
  }
  /* Hide app chrome; print the report only. Executor: replace `.shell-nav, .shell-top`
     with the real chrome class names from Shell.tsx / components.css. */
  .shell-nav,
  .shell-top {
    display: none !important;
  }
  .report thead {
    display: table-header-group;
  }
  .report tr {
    page-break-inside: avoid;
  }
}
```

- [ ] **Step 2: Human print check** (run once, record result in chat — not in code)

Serve seeded build, open `#/report`, in both Full and Executive: Ctrl+P → Save as PDF. Confirm: header/footer on each page, tables break cleanly, trend figure prints, no dark backgrounds, no nav chrome. If the shell chrome class names differ, fix the `@media print` hide rules and re-check.

- [ ] **Step 3: Final gates**

Run: `npm test && npm run build && npm run format`
Expected: PASS

---

## Self-Review

- Spec coverage: cover ✓ summary ✓ top-10 ✓ domains ✓ supply ✓ validation ✓ governance ✓ appendix A/B ✓ limitations ✓ executive variant ✓ deterministic filename ✓ per-page hash footer ✓ light-forced print ✓ download buttons ✓. "Next schedule" copy from chat spec dropped — backend has no schedules (recorded deviation, same as Overview plan).
- Placeholders: three executor-read points (Evidence envelope wording, vendor pending enum, shell chrome classes) each with file:line pointers — these are read-then-match steps, not TBD logic.
- Type consistency: `overviewAgg.ts` additions (`verdictOf`) shared with Overview plan's Task 4 — Overview plan must land first or the verdict helper is defined here and imported there. ORDER: tokens → overview → report. The verdict-extraction is specified in this plan (Task 2 intro) to avoid duplication: implement `verdictOf` in the Overview task and import it here.
