import { useMemo } from "react";
import {
  parseAlert,
  parseAsset,
  parseIncident,
  parseSupplyComponent,
  parseSupplyPolicy,
  parseValidationResult,
} from "../contracts";
import { StatCard } from "../components/StatCard";
import { EmptyState, ErrorState, StatSkeleton } from "../components/States";
import { listOf, useApiList } from "./hooks";
import {
  alertAgeDays,
  assetCoverage,
  bucketTrend,
  buildDomainRows,
  openAlerts,
  pickAttention,
  summarizeTrend,
  verdictOf,
  violatingComponents,
  type AttentionInput,
} from "./overviewAgg";
import { TrendChart } from "./OverviewTrend";

const WEEK_MS = 7 * 86_400_000;

const DOT_FOR: Record<string, string> = {
  ok: "var(--bv-ok)",
  attention: "var(--bv-warn)",
  critical: "var(--bv-bad)",
  unknown: "var(--bv-muted)",
};

export function Overview() {
  const alerts = useApiList("/api/v1/alerts", parseAlert);
  const assets = useApiList("/api/v1/assets", parseAsset);
  const incidents = useApiList("/api/v1/incidents", parseIncident);
  const results = useApiList(
    "/api/v1/validation-results",
    parseValidationResult,
  );
  const components = useApiList(
    "/api/v1/supply-chain/components",
    parseSupplyComponent,
  );
  const policies = useApiList(
    "/api/v1/supply-chain/policies",
    parseSupplyPolicy,
  );

  const inputs = useMemo<AttentionInput | null>(() => {
    const a = listOf(alerts);
    const as = listOf(assets);
    const i = listOf(incidents);
    const r = listOf(results);
    const c = listOf(components);
    const p = listOf(policies);
    if (!a || !as || !i || !r || !c || !p) return null;
    return {
      alerts: a,
      assets: as,
      incidents: i,
      results: r,
      components: c,
      policies: p,
    };
  }, [alerts, assets, incidents, results, components, policies]);

  const anyLoading =
    alerts.kind === "loading" ||
    assets.kind === "loading" ||
    incidents.kind === "loading" ||
    results.kind === "loading" ||
    components.kind === "loading" ||
    policies.kind === "loading";
  const firstError =
    (alerts.kind === "backend-error" && alerts.message) ||
    (assets.kind === "backend-error" && assets.message) ||
    (incidents.kind === "backend-error" && incidents.message) ||
    (results.kind === "backend-error" && results.message) ||
    (components.kind === "backend-error" && components.message) ||
    (policies.kind === "backend-error" && policies.message) ||
    (alerts.kind === "invalid" && alerts.message) ||
    (assets.kind === "invalid" && assets.message) ||
    (incidents.kind === "invalid" && incidents.message) ||
    (results.kind === "invalid" && results.message) ||
    (components.kind === "invalid" && components.message) ||
    (policies.kind === "invalid" && policies.message) ||
    null;

  const nowMs = Date.now();
  const verdict = inputs ? verdictOf(inputs, nowMs) : null;
  const open = inputs ? openAlerts(inputs.alerts) : [];
  const critical = open.filter((a) => a.severity === "SEVERITY_CRITICAL");
  const high = open.filter((a) => a.severity === "SEVERITY_HIGH");
  const cov = inputs ? assetCoverage(inputs.assets) : null;
  const ages = open.map((a) => alertAgeDays(a, nowMs));
  const meanAge =
    ages.length === 0 ? 0 : ages.reduce((n, x) => n + x, 0) / ages.length;
  const oldest = open.reduce<{ title: string; age: number } | null>(
    (best, a) => {
      const age = alertAgeDays(a, nowMs);
      return !best || age > best.age ? { title: a.title, age } : best;
    },
    null,
  );
  const openedWeek = open.filter(
    (a) => nowMs - Date.parse(a.created_at) <= WEEK_MS,
  ).length;
  const overWeek = open.filter(
    (a) => nowMs - Date.parse(a.created_at) > WEEK_MS,
  ).length;
  const badResults = inputs
    ? inputs.results.filter(
        (r) => r.verdict === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
      )
    : [];
  const latestValidation = inputs
    ? inputs.results
        .map((r) => r.validated_at)
        .filter((t) => !Number.isNaN(Date.parse(t)))
        .sort()
        .at(-1)
    : undefined;
  const violating = inputs ? violatingComponents(inputs.components) : [];
  const days = inputs ? bucketTrend(inputs.alerts, nowMs) : [];
  const attention = inputs ? pickAttention(inputs, nowMs) : [];
  const domains = inputs ? buildDomainRows(inputs) : [];
  const allEmpty =
    inputs &&
    inputs.alerts.length === 0 &&
    inputs.assets.length === 0 &&
    inputs.incidents.length === 0 &&
    inputs.results.length === 0 &&
    inputs.components.length === 0;

  return (
    <>
      <h1 className="page-title">Overview</h1>
      <p className="page-sub">
        Posture at a glance. Every number opens its workspace, pre-filtered.
      </p>
      {firstError && <ErrorState title="Backend error" message={firstError} />}
      {!firstError && (anyLoading || !inputs || !verdict || !cov) && (
        <StatSkeleton />
      )}
      {!firstError && inputs && verdict && cov && (
        <>
          <div
            className={`status-strip ${verdict.tone}`}
            role="status"
            aria-label={verdict.text}
          >
            <span className="status-dot" aria-hidden="true" />
            <span>{verdict.text}</span>
          </div>
          <div className="stat-grid">
            <StatCard
              label="Findings"
              value={`${open.length} open`}
              caption={
                open.length === 0
                  ? "None open — clean or not yet scanned"
                  : `${critical.length} critical · ${high.length} high`
              }
              delta={
                openedWeek > 0
                  ? `▲ +${openedWeek} opened this week`
                  : "— none new this week"
              }
              deltaTone={openedWeek > 0 ? "bad" : "neutral"}
              href="#/findings?status=ALERT_STATUS_OPEN"
              animate
            />
            <StatCard
              label="Coverage"
              value={`${cov.monitored} watched`}
              caption={
                cov.monitored === 0
                  ? "No assets yet — add the first one"
                  : `${cov.active} active · ${cov.stale} stale`
              }
              href="#/assets?status=ASSET_STATUS_STALE"
              animate
            />
            <StatCard
              label="Response age"
              value={open.length === 0 ? "—" : `${Math.round(meanAge)}d avg`}
              caption={
                !oldest
                  ? "No open findings"
                  : `Oldest: ${oldest.title} (${oldest.age}d)`
              }
              delta={
                overWeek > 0 ? `${overWeek} over 7 days old` : "— all fresh"
              }
              deltaTone={overWeek > 0 ? "bad" : "neutral"}
              href="#/findings?status=ALERT_STATUS_OPEN&sort=oldest"
              animate
            />
            <StatCard
              label="Validation"
              value={
                latestValidation
                  ? new Date(latestValidation).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  : "—"
              }
              caption={
                inputs.results.length === 0
                  ? "Never validated — findings above are untested"
                  : `${inputs.results.length} results · ${badResults.length} undetected`
              }
              href="#/validation"
              animate
            />
          </div>
          {allEmpty && (
            <div className="panel">
              <EmptyState
                icon="shield"
                title="No data yet"
                description="Run the collector pipeline against lab telemetry, then seed this database. Posture, trends, and decisions will appear here once data flows."
              />
            </div>
          )}
          <h2 className="title">30-day trend</h2>
          <div className="trend">
            <TrendChart days={days} />
            <p className="trend-summary">
              {summarizeTrend(days, attention.length)}{" "}
              <a href="#/report">Download report →</a>
            </p>
          </div>
          <h2 className="title">Needs your decision</h2>
          {allEmpty ? (
            <p className="body" style={{ color: "var(--bv-muted)" }}>
              Decisions will appear here once data flows.
            </p>
          ) : attention.length === 0 ? (
            <p className="body">✓ Nothing needs a decision this week.</p>
          ) : (
            <ul className="attention-list">
              {attention.map((item) => (
                <li key={item.key}>
                  <span
                    className="status-dot"
                    style={{
                      background:
                        item.severity === "critical"
                          ? "var(--bv-bad)"
                          : item.severity === "high"
                            ? "var(--bv-warn)"
                            : "var(--bv-muted)",
                    }}
                    aria-hidden="true"
                  />
                  <span className="attention-text">{item.text}</span>
                  <span className="attention-context">{item.context}</span>
                  <a href={item.href}>Open →</a>
                </li>
              ))}
            </ul>
          )}
          <h2 className="title">Domains</h2>
          <div className="panel">
            {domains.map((d) => (
              <div key={d.key} className="group-row">
                <span
                  className="status-dot"
                  style={{ background: DOT_FOR[d.status] ?? "var(--bv-muted)" }}
                  aria-hidden="true"
                />
                <span className="group-label">{d.label}</span>
                <span className="group-figure">{d.figure}</span>
                <a href={d.href} aria-label={`Open ${d.label}`}>
                  →
                </a>
              </div>
            ))}
          </div>
          {violating.length > 0 && (
            <p className="page-sub">
              {violating.length} supply component
              {violating.length === 1 ? " is" : "s are"} in policy violation.
              Statuses are observed metadata — see Supply Chain for basis.
            </p>
          )}
        </>
      )}
    </>
  );
}
