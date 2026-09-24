# Workspace Rollout (Strips + Drawers + Micro-sweep) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the Plan-1 shared chrome to all 14 workspaces: one `SummaryStrip` per view, grouped drawer fields, and a micro-consistency sweep — no backend changes, no new data.

**Architecture:** Strips compute counts over the UNFILTERED `listOf(...)` data each view already fetches (never over filtered rows — the strip describes the workspace, not the filter). Strips render only when their inputs are ready; loading/error/empty behavior of every view is untouched. Drawer grouping wraps existing `Field` items in `display:contents` groups (valid inside both `<dl>` and `<div>` parents). Micro-sweep is grep-driven with exact replacements.

**Tech Stack:** React 19, TypeScript strict, Vite 7, vitest + @testing-library/react, prettier. No new dependencies.

**Spec:** Conversation specs "Summary Strip table per workspace" + "Drawer grouping" + "Micro-consistency" (2026-09-19), as corrected below. Depends on: tokens + overview + report plans (all merged).

## Global Constraints

- No backend, store, contract, or API changes. Read-only UI.
- `npm test`, `npm run build`, `npm run format`, `npm run typecheck` pass after every task.
- Copy is English, honest. Strip statements are fixed sentences (provided verbatim below) with a zero-state variant where counts can be 0 — never render "0 threats blocked"-style vanity.
- Strip stats are plain counts with no links (self-links to the same view are noise; Overview owns click-through).
- Do not change filter logic, table columns, drawer content, or empty-state behavior — only ADD the strip, ADD group wrappers, and apply the micro replacements listed.

## Spec Corrections (binding)

1. Chat spec's per-workspace "micro-viz" is DROPPED for this rollout (donut/bar per view = 14 new visuals; the strip works without it; revisit only if a view proves it needs one).
2. Drawers already have `<h3 className="detail-section">` topic sections — KEEP them. Grouping applies INSIDE the top field-grid only (Identity / Risk / History), per the mapping rule in Task 5.

---

## File Map

- Modify (strips): each of the 14 `ui/src/views/*.tsx` (Overview excluded — done) — insert `<SummaryStrip>` between the `page-sub` paragraph and the `FilterBar`, rendered when row data is non-null.
- Create: `ui/src/views/strips.test.tsx` — one `describe` per view asserting statement + stats (mock maps COPIED from each view's existing test file — never invent fixture shapes).
- Modify (drawers): the 14 view files — wrap top field-grid `Field` items in `.field-group` divs with `<h4 className="group-head">`.
- Modify: `ui/src/components.css` — append `.field-group` rules (Task 5 Step 1).
- Modify (micro): various view files per grep results (Task 6).

---

### Task 1: Strips Batch A — Findings, Assets, SupplyChain (+ tests)

**Files:**
- Modify: `ui/src/views/Findings.tsx`, `ui/src/views/Assets.tsx`, `ui/src/views/SupplyChain.tsx`
- Test: `ui/src/views/strips.test.tsx` (new; describes for these 3 views)

**Interfaces:**
- Consumes: `SummaryStrip` (`components/SummaryStrip.tsx`), `listOf` (views/hooks.ts).
- Produces: strip pattern other batches copy.

- [ ] **Step 1: Write failing tests** (`strips.test.tsx`, first 3 describes)

```tsx
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import assetFullJson from "../../../../contracts/fixtures/asset/valid_full.json";
import { Findings } from "./Findings";
import { Assets } from "./Assets";
import { SupplyChain } from "./SupplyChain";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

describe("workspace strips", () => {
  it("Findings strip states open/critical/oldest", async () => {
    mockApi({
      "/api/v1/alerts": { data: [alertJson] },
      "/api/v1/detections": { data: [] },
      "/api/v1/telemetry": { data: [] },
    });
    render(<Findings onOpenIncident={() => {}} />);
    await waitFor(() =>
      expect(screen.getByText(/need a decision first/i)).toBeInTheDocument(),
    );
    expect(screen.getByText("Open")).toBeInTheDocument();
  });

  it("Assets strip states monitored/active/stale", async () => {
    mockApi({ "/api/v1/assets": { data: [assetFullJson] } });
    render(<Assets />);
    await waitFor(() =>
      expect(screen.getByText(/unobserved, not dead/i)).toBeInTheDocument(),
    );
    expect(screen.getByText("Monitored")).toBeInTheDocument();
  });

  it("SupplyChain strip states components/violations/policies", async () => {
    mockApi({
      "/api/v1/supply-chain/components": { data: [] },
      "/api/v1/supply-chain/sboms": { data: [] },
      "/api/v1/supply-chain/policies": { data: [] },
      "/api/v1/third-party/vendors": { data: [] },
      "/api/v1/third-party/assessments": { data: [] },
      "/api/v1/supply-chain/links": { data: [] },
      "/api/v1/continuous-security/checks": { data: [] },
      "/api/v1/continuous-security/history": { data: [] },
    });
    render(<SupplyChain />);
    await waitFor(() =>
      expect(screen.getByText(/supply-chain risk/i)).toBeInTheDocument(),
    );
  });
});
```

(Executor: BEFORE running, read `SupplyChain.tsx` lines 340-470 to find where ALL EIGHT lists are loading-gated and which tab renders by default; the strip must render when `components`+`policies` are ready regardless of tab, and the mock map above must match every endpoint the default tab fetches — extend with `dependencies` routes ONLY if the default render fetches them. Check `supplychain.test.tsx` mock map and copy any missing routes.)

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/views/strips.test.tsx` in `collector/ui`
Expected: FAIL — no strip statements rendered

- [ ] **Step 3: Implement the three strips**

Findings (`Findings.tsx`, after the `rows` useMemo; insert JSX between `page-sub` and `FilterBar`, render when `rows !== null`):
```tsx
{rows !== null && (() => {
  const all = joinRows(listOf(alerts) ?? [], listOf(detections) ?? [], listOf(telemetry) ?? []);
  const open = all.filter((r) => r.status === "ALERT_STATUS_OPEN" || r.status === "ALERT_STATUS_ACKNOWLEDGED");
  const crit = open.filter((r) => r.severity === "SEVERITY_CRITICAL").length;
  const oldest = open.reduce((m, r) => Math.max(m, alertAgeDays(r, Date.now())), 0);
  return (
    <SummaryStrip
      statement="Critical findings need a decision first; the rest can wait for triage."
      stats={[
        { label: "Open", value: String(open.length) },
        { label: "Critical", value: String(crit) },
        { label: "Oldest (days)", value: open.length === 0 ? "—" : String(oldest) },
      ]}
    />
  );
})()}
```
(Import `alertAgeDays` from `./overviewAgg`, `SummaryStrip` from `../components/SummaryStrip`. `joinRows` is module-scope in Findings.tsx — reuse directly.)

Assets (`Assets.tsx`; data is `listOf(assets)`; reuse `assetCoverage` from `./overviewAgg`):
```tsx
{(() => {
  const list = listOf(assets);
  if (!list) return null;
  const cov = assetCoverage(list);
  return (
    <SummaryStrip
      statement="Stale assets are unobserved, not dead — verify before removing."
      stats={[
        { label: "Monitored", value: String(cov.monitored) },
        { label: "Active", value: String(cov.active) },
        { label: "Stale", value: String(cov.stale) },
      ]}
    />
  );
})()}
```
(Executor: read `Assets.tsx` lines 109-180 to place the strip after `page-sub`, before `FilterBar`, and confirm the loading/error/empty blocks stay untouched.)

SupplyChain (`SupplyChain.tsx`; lists already fetched):
```tsx
{(() => {
  const list = listOf(components);
  const pols = listOf(policies);
  if (!list || !pols) return null;
  const viol = list.filter((c) => c.status === "POLICY_VIOLATION").length;
  const old = list.filter((c) => c.status === "OUTDATED" || c.status === "UNSUPPORTED").length;
  return (
    <SummaryStrip
      statement={
        old === 0
          ? "No outdated or unsupported components right now."
          : `${old} outdated or unsupported component${old === 1 ? "" : "s"} raise supply-chain risk.`
      }
      stats={[
        { label: "Components", value: String(list.length) },
        { label: "In violation", value: String(viol) },
        { label: "Policies", value: String(pols.length) },
      ]}
    />
  );
})()}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/views/strips.test.tsx` then `npm test`
Expected: PASS; existing suite unaffected

---

### Task 2: Strips Batch B — Network, Application, Infrastructure, Identity

**Files:**
- Modify: `ui/src/views/Network.tsx`, `Application.tsx`, `Infrastructure.tsx`, `Identity.tsx`
- Test: append 4 describes to `ui/src/views/strips.test.tsx`

**Interfaces:**
- Consumes: `SummaryStrip`, `listOf`, Task-1 pattern.
- Produces: 4 more strips.

Recipe per view (identical mechanics to Task 1): mock map COPIED from the view's existing test file (`network.test.tsx`, `application.test.tsx`, identity mocks in `identity.test.tsx`, infra mocks in `views.test.tsx`/`views2.test.tsx` — grep the endpoint list from the test file, copy verbatim); strip placed after `page-sub`, rendered when that view's main list(s) are non-null; statement verbatim from the table below; stats derived from UNFILTERED lists only.

| View | Statement (verbatim) | Stats (derivation) |
|---|---|---|
| Network | "Most rows are telemetry, not findings — denied and detected rows deserve a look." | Observations (listOf obs length); Denied (`verdict === "denied"`); Detected (`r.detected`) |
| Application | "Server errors deserve a look first; the rest is observed traffic." | Observations; Server errors (`(status_code ?? 0) >= 500`); Without status (`status_code === undefined`) |
| Infrastructure | "Privileged containers and detected actions deserve a look first." | Total = sum of the four listOf lengths (endpoint+server+container+cloud — executor reads `Infrastructure.tsx` for the four hook variable names); Detected (sum of `r.detected` across the four); Privileged containers (`container.privileged`) |
| Identity | "Failed logins deserve a look first; absence of identity data is not safety." | Auth observations (listOf auth length); Failed (executor mirrors the EXACT failed predicate the view's existing filter uses — read `Identity.tsx` filter code, do not invent: if the view filters `outcome !== "SUCCESS"`-style, reuse that expression verbatim); Detected (sum over identity+auth+data lists' `detected` where the field exists) |

Zero-state rule: when the main list is empty the view shows its existing EmptyState — the strip must NOT render (guard `list.length === 0 → null` is already implied by most views' `total > 0` gates; place the strip INSIDE the same conditional block that renders the table, never beside the empty panel).

- [ ] **Step 1: Write 4 failing describes** (mirror Task-1 test shape; statement regex from table)
- [ ] **Step 2: Run** — Expected: FAIL (4 new)
- [ ] **Step 3: Implement** per table (executor reads each view's hook names + filter predicates first)
- [ ] **Step 4: Run** `npx vitest run src/views/strips.test.tsx` + `npm test` — Expected: PASS

---

### Task 3: Strips Batch C — Monitoring, Investigations, Validation, Governance

Same recipe as Task 2. Mock maps copied from `monitoring.test.tsx`, `investigations.test.tsx`, `validation.test.tsx`, `governance.test.tsx`.

| View | Statement (verbatim) | Stats (derivation) |
|---|---|---|
| Monitoring | "Threat-intel matches deserve a look first; rules are only as good as their health." | Events (listOf monitoring events); Rules (listOf detection-rules); TI matches (listOf threat-intel matches). Executor reads `Monitoring.tsx` for the three hook variable names. |
| Investigations | "Open hypotheses wait on evidence — see what is still unattributed." | Hunting events; Timeline entries; Forensic artifacts (sum across forensic lists the view fetches — executor reads `Investigations.tsx` hook names). If the view tracks hypotheses with an open/closed field, add 4th stat "Open hypotheses" using the view's own predicate; else 3 stats. |
| Validation | "Undetected executions are the gap between assumed and real defense." | Campaigns; Completed (`status === "COMPLETED"` — executor confirms against `Validation.tsx`); Results; Undetected (`verdict === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED"`). |
| Governance | "Controls with no passing assessment are the compliance gap." | Controls; Assessments; Failing (executor mirrors the EXACT failing predicate `Governance.tsx` already uses to badge assessments — read it, reuse verbatim; if the view has no fail concept, stats are Controls + Assessments + Resilience rows needing attention per the view's own posture derivation). |

- [ ] Steps 1–4 identical to Task 2.

---

### Task 4: Strips Batch D — Incidents, Evidence, Responses

Same recipe. Mock maps: incidents/evidence/responses mocks live in `views.test.tsx` + `views2.test.tsx` (grep endpoint lists from those files).

| View | Statement (verbatim) | Stats (derivation) |
|---|---|---|
| Incidents | "Open incidents need owners; aging ones need decisions." | Open (`INCIDENT_STATUS_OPEN`); Investigating (`INCIDENT_STATUS_INVESTIGATING`); Resolved+Closed (sum). Executor reads `Incidents.tsx` for list variable name. |
| Evidence | "Every item here is digest-verified — anything else never renders." | Items (ready-list length; view renders ONLY when envelope verified, so no qualifier needed); Linked incidents (distinct `incident_id` count); With SHA-256 (`sha256` present count). Executor reads `Evidence.tsx` for the ready-list variable. |
| Responses | "Pending approvals block response; failed executions need review." | Pending approval (`RESPONSE_STATUS_PENDING_APPROVAL`); Executing (`RESPONSE_STATUS_EXECUTING`); Verified (`RESPONSE_STATUS_VERIFIED`); Failed (DENIED + EXECUTION_FAILED + VERIFICATION_FAILED — mirror `responseTone` in `StatusBadge.tsx` lines 105-121, reuse its exact three enum strings). Executor reads `Responses.tsx` for the recommendations list variable. |

- [ ] Steps 1–4 identical to Task 2.

---

### Task 5: Drawer grouping (all 14 views)

**Files:**
- Modify: `ui/src/components.css` (append rules below)
- Modify: all 14 `ui/src/views/*.tsx` (Overview + Report have no drawers — excluded)
- Test: no new unit tests (structure-only change); gate = full suite + live screenshot of 3 drawers (Findings, Assets, SupplyChain) asserting group headers present.

**Interfaces:**
- Consumes: `.group-head` (exists), new `.field-group`.
- Produces: grouped drawers.

Mapping rule (apply to the TOP field-grid of each drawer; existing `<h3 className="detail-section">` sections and everything under them are UNTOUCHED):
- Identity group (`<h4 className="group-head">Identity</h4>`): id, name, title, principal, user, asset, asset_id, source, sensor, type, kind, category, ecosystem, namespace, host, path, route, method, service, image, container, container_id, cluster, provider, account, region, target, operation, rule, rule_name, control, campaign, vendor, assessor, recommender — i.e. every Field whose label names the thing, its origin, or its actor.
- Risk group (`Risk`): severity, status, verdict, outcome, result, detected, failure_reason, risk, risk_basis, privileged, host_network, host_pid, approved/approval, coverage, score-like numbers — every Field that judges or qualifies.
- History group (`History`): created, updated, occurred, observed, collected, validated, requested, recommended, approved, started, finished, first_seen, last_seen, expires — every timestamp Field plus age/duration text.
- A Field matching none → stays ABOVE the first group header (ungrouped), never forced into a wrong group. A group with zero fields → header omitted entirely.

- [ ] **Step 1: Append CSS**

```css
/* ---- Drawer field groups (valid inside dl and div parents) ---- */
.field-group {
  display: contents;
}
.field-group .group-head {
  grid-column: 1 / -1;
  margin: 16px 0 0;
}
.field-group:first-child .group-head {
  margin-top: 0;
}
```

- [ ] **Step 2: Group all 14 drawers**

Pattern (identical in every drawer; `Field` import already exists everywhere):
```tsx
<div className="field-grid">
  <div className="field-group">
    <h4 className="group-head">Identity</h4>
    <Field label="...">...</Field>
  </div>
  <div className="field-group">
    <h4 className="group-head">Risk</h4>
    <Field label="...">...</Field>
  </div>
  <div className="field-group">
    <h4 className="group-head">History</h4>
    <Field label="...">...</Field>
  </div>
</div>
```
For `<dl className="field-grid">` parents the same markup is valid (`div` wrapping `dt`/`dd` groups inside `dl` is conforming; `Field` renders `dt`+`dd`). Executor: process views alphabetically (Application, Assets, Evidence, Findings, Governance, Identity, Incidents, Infrastructure, Investigations, Monitoring, Network, Responses, SupplyChain, Validation); in each drawer move — do not copy, do not reword — existing `Field` lines into the three groups per the mapping rule. Drawers with a second field-grid (e.g. NetworkDetail's asset-correlation grid) get groups ONLY in the top grid; secondary grids stay untouched.

- [ ] **Step 3: Gates**

Run: `npm test && npm run build && npm run format && npm run typecheck`
Expected: PASS (structure-only; no test asserts on group headers except the live check in Task 6)

---

### Task 6: Micro-sweep + full gates + live verification

**Files:** various `ui/src/views/*.tsx` per grep hits below.

Sub-task A — date uniformity. Run: `grep -rn "new Date(\|toLocaleString(\|toLocaleDateString(" src/views/*.tsx` (excluding `overviewAgg.ts`, `ReportView.tsx`, `OverviewTrend.tsx`). Every display timestamp MUST go through `fmtTime` (views/hooks.ts). Replace each hit with `fmtTime(...)` keeping the surrounding JSX identical. (The `.mono`/`.tabular` spans around dates stay.)

Sub-task B — tabular numerals. Every `stat-value`-like number, table time cell, and strip value already uses `.tabular` except possibly new code from Tasks 1–4. Run: `grep -rn "strip-value\|stat-value" src/components/*.tsx src/views/Overview.tsx` — confirm `tabular` present in `StatCard` (`stat-value tabular` — yes) and `SummaryStrip` (`strip-value tabular` — yes). No change expected; record the check.

Sub-task C — badge vocabulary audit. Run: `grep -rn "<StatusBadge" src/views/*.tsx`. For each hit where `tone` is `"info"` or `"neutral"` AND the value is a lifecycle/status enum (ASSET_STATUS_*, supply statuses, evidence kinds, RESOLVED/CLOSED-class states) — NOT severity, NOT verdicts, NOT incident/response tones with warn/bad semantics — add the `outline` prop. Verdicts (`verdictTone`), incident tones, response tones: UNTOUCHED (their colors carry meaning). Findings `StatusBadge` (OPEN→warn): UNTOUCHED.

Sub-task D — filter-empty actions. Run: `grep -rn "No matching" src/views/*.tsx`. Each filter-empty `EmptyState` gains `action={{ label: "Clear filters", onClick: <the view's existing clear/reset function> }}` — every view already has one (Findings `clear`, Network inline `onClear`, Assets — executor reads each view for its reset fn name; if a view genuinely has no reset fn, skip it rather than inventing state logic). Data-empty states (e.g. "No assets", "No findings") are UNTOUCHED — no fake next actions.

- [ ] **Step 1: Apply A–D**, running `npx prettier --write` on touched files after each sub-task.
- [ ] **Step 2: Full gates** — `npm test && npm run build && npm run format && npm run typecheck` — Expected: PASS.
- [ ] **Step 3: Live verification** — seed + serve + screenshot 6 views (Findings, Assets, SupplyChain, Network, Report, Overview) × light, plus 3 drawers open asserting `.group-head` count ≥ 2; zero pageerrors, zero horizontal overflow, zero backend-errors. (Same harness as the Plan-3 verification: `go run ./cmd/collector --seed`, `go build`, `--serve --ui-dir ui/dist`, Playwright asserts.)

---

## Self-Review

- Spec coverage: strips ×14 ✓ (Tasks 1–4), drawer grouping ✓ (Task 5), micro-sweep ✓ (Task 6: dates, tabular, badges, empty actions), sidebar identity icons (existing set already covers all 15 views incl. `report` — no new icon needed; dropped with reason).
- Placeholders: executor-read points all carry file:line pointers and reuse-verbatim rules (filter predicates, mock maps, reset fns) — no invented logic.
- Type consistency: `SummaryStrip` props (`statement/stats/viz`) match Plan-1; `alertAgeDays`/`assetCoverage` reused from `overviewAgg.ts`; `responseTone` enum strings reused verbatim for Responses stats.
