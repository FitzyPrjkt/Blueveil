import { useMemo, useState } from "react";
import {
  VERDICT_MEANINGS,
  parseAlert,
  parseAsset,
  parseIncident,
  parseSupplyComponent,
  parseSupplyPolicy,
  parseValidationResult,
  parseVendorAssessment,
} from "../contracts";
import { ErrorState, HeadingSkeleton } from "../components/States";
import { fmtTime, listOf, useApiList } from "./hooks";
import { useEvidenceEnvelope } from "./Evidence";
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
import { reportDigest } from "./reportHash";
import { TrendChart } from "./OverviewTrend";

export function reportFilename(issued: string): string {
  return `blueveil-report-${issued.slice(0, 10)}.pdf`;
}

const SEV_RANK: Record<string, number> = {
  SEVERITY_CRITICAL: 0,
  SEVERITY_HIGH: 1,
  SEVERITY_MEDIUM: 2,
  SEVERITY_LOW: 3,
  SEVERITY_INFO: 4,
};

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

export function ReportView({ issued }: { issued?: string }) {
  // Local calendar day, so "Issued" matches the reader's today.
  const day = issued ?? new Date().toLocaleDateString("en-CA");
  const [variant, setVariant] = useState<"full" | "executive">("full");
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
  const assessments = useApiList(
    "/api/v1/third-party/assessments",
    parseVendorAssessment,
  );
  const evidence = useEvidenceEnvelope();

  const lists = useMemo(() => {
    const a = listOf(alerts);
    const as = listOf(assets);
    const i = listOf(incidents);
    const r = listOf(results);
    const c = listOf(components);
    const p = listOf(policies);
    const va = listOf(assessments);
    const ev =
      evidence.kind === "ready"
        ? evidence.data
        : evidence.kind === "empty"
          ? []
          : null;
    if (!a || !as || !i || !r || !c || !p || !va || !ev) return null;
    return { a, as, i, r, c, p, va, ev };
  }, [
    alerts,
    assets,
    incidents,
    results,
    components,
    policies,
    assessments,
    evidence,
  ]);

  const loading =
    alerts.kind === "loading" ||
    assets.kind === "loading" ||
    incidents.kind === "loading" ||
    results.kind === "loading" ||
    components.kind === "loading" ||
    policies.kind === "loading" ||
    assessments.kind === "loading" ||
    evidence.kind === "loading";
  const error =
    (alerts.kind === "backend-error" && alerts.message) ||
    (assets.kind === "backend-error" && assets.message) ||
    (incidents.kind === "backend-error" && incidents.message) ||
    (results.kind === "backend-error" && results.message) ||
    (components.kind === "backend-error" && components.message) ||
    (policies.kind === "backend-error" && policies.message) ||
    (assessments.kind === "backend-error" && assessments.message) ||
    (evidence.kind === "backend-error" && evidence.message) ||
    (alerts.kind === "invalid" && alerts.message) ||
    (assets.kind === "invalid" && assets.message) ||
    (incidents.kind === "invalid" && incidents.message) ||
    (results.kind === "invalid" && results.message) ||
    (components.kind === "invalid" && components.message) ||
    (policies.kind === "invalid" && policies.message) ||
    (assessments.kind === "invalid" && assessments.message) ||
    (evidence.kind === "invalid" && evidence.message) ||
    null;

  const model = useMemo(() => {
    if (!lists) return null;
    const input: AttentionInput = {
      alerts: lists.a,
      assets: lists.as,
      incidents: lists.i,
      results: lists.r,
      components: lists.c,
      policies: lists.p,
    };
    const nowMs = Date.parse(`${day}T12:00:00Z`);
    const open = openAlerts(lists.a);
    const ranked = [...open].sort((x, y) => {
      const r = (SEV_RANK[x.severity] ?? 9) - (SEV_RANK[y.severity] ?? 9);
      if (r !== 0) return r;
      return Date.parse(x.created_at) - Date.parse(y.created_at);
    });
    const stamps = [
      ...lists.a.map((x) => x.created_at),
      ...lists.r.map((x) => x.validated_at),
      ...lists.ev.map((x) => x.collected_at),
    ]
      .map((t) => Date.parse(t))
      .filter((t) => !Number.isNaN(t))
      .sort((x, y) => x - y);
    const first = stamps[0] ?? NaN;
    const last = stamps[stamps.length - 1] ?? NaN;
    const period =
      stamps.length === 0
        ? "No data in this period"
        : `${new Date(first).toISOString().slice(0, 10)} – ${new Date(last).toISOString().slice(0, 10)}`;
    const pendingVendors = lists.va.filter((v) => v.status !== "REVIEWED");
    const outdated = lists.c.filter(
      (c) => c.status === "OUTDATED" || c.status === "UNSUPPORTED",
    );
    const digest = reportDigest({
      issued: day,
      alerts: lists.a,
      assets: lists.as,
      incidents: lists.i,
      results: lists.r,
      components: lists.c,
      policies: lists.p,
      assessments: lists.va,
      evidence: lists.ev,
    });
    return {
      input,
      nowMs,
      open,
      ranked,
      period,
      pendingVendors,
      outdated,
      digest,
      verdict: verdictOf(input, nowMs),
      coverage: assetCoverage(lists.as),
      days: bucketTrend(lists.a, nowMs),
      attention: pickAttention(input, nowMs),
      domains: buildDomainRows(input),
      violating: violatingComponents(lists.c),
      badResults: lists.r.filter(
        (r) => r.verdict === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
      ),
      latestValidation: lists.r
        .map((r) => r.validated_at)
        .filter((t) => !Number.isNaN(Date.parse(t)))
        .sort()
        .at(-1),
      unknownDomains: buildDomainRows(input)
        .filter((d) => d.status === "unknown")
        .map((d) => d.label),
    };
  }, [lists, day]);

  if (error) return <ErrorState title="Backend error" message={error} />;
  if (loading || !model || !lists)
    return (
      <>
        <h1 className="page-title">Report</h1>
        <HeadingSkeleton />
      </>
    );

  const foot = (
    <p className="report-foot">
      Report {model.digest} · Issued {day}
    </p>
  );

  const actions: string[] = [];
  const oldestCritical = model.ranked.find(
    (a) => a.severity === "SEVERITY_CRITICAL",
  );
  if (oldestCritical)
    actions.push(
      `Decide the oldest critical finding (${oldestCritical.title}, ${alertAgeDays(oldestCritical, model.nowMs)} days): fix, accept with expiry, or escalate.`,
    );
  if (model.violating.length > 0)
    actions.push(
      `Resolve ${model.violating.length} supply component${model.violating.length === 1 ? "" : "s"} in policy violation.`,
    );
  if (lists.r.length === 0)
    actions.push(
      "Run a first validation campaign — current findings are untested.",
    );
  while (actions.length < 3) actions.push("No further action required.");

  if (variant === "executive") {
    const top5 = model.ranked.slice(0, 5);
    return (
      <div className="report">
        <div className="no-print" style={{ marginBottom: 16 }}>
          <button
            type="button"
            className="btn"
            onClick={() => setVariant("full")}
          >
            Full report
          </button>{" "}
          <button type="button" className="btn" onClick={() => window.print()}>
            Print / Save PDF
          </button>
        </div>
        <div className="report-cover">
          <h1>Security Posture Report</h1>
          <p>Executive summary · Data period {model.period}</p>
          <p>
            Issued {day} · Report {model.digest}
          </p>
          <p>{model.verdict.text}</p>
        </div>
        {foot}
        <h2>Summary</h2>
        <p>
          {model.open.length} open findings · {model.coverage.monitored} assets
          watched · {model.attention.length} items need a decision.
        </p>
        <p>{summarizeTrend(model.days, model.attention.length)}</p>
        {foot}
        <h2>Top findings</h2>
        {top5.length === 0 ? (
          <p>No open findings in this period.</p>
        ) : (
          <ol>
            {top5.map((a) => (
              <li key={a.id}>
                {a.title} — open {alertAgeDays(a, model.nowMs)} days, rated{" "}
                {a.severity.replace("SEVERITY_", "")}.
              </li>
            ))}
          </ol>
        )}
        <p>
          Severity words, strongest first: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        </p>
        {foot}
        <h2>Recommended actions</h2>
        <ol>
          {actions.slice(0, 3).map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ol>
        {foot}
        <h2>Limitations</h2>
        <p>
          {model.unknownDomains.length === 0
            ? "All tracked domains contributed data to this report."
            : `${model.unknownDomains.join(", ")} contributed no data and ${model.unknownDomains.length === 1 ? "is" : "are"} out of this report's scope.`}{" "}
          Findings not yet validated are untested claims, not confirmed
          breaches. Data period {model.period}.
        </p>
        {foot}
      </div>
    );
  }

  return (
    <div className="report">
      <div className="no-print" style={{ marginBottom: 16 }}>
        <button
          type="button"
          className="btn"
          onClick={() => setVariant("executive")}
        >
          Executive summary
        </button>{" "}
        <button type="button" className="btn" onClick={() => window.print()}>
          Print / Save PDF
        </button>
      </div>
      <div className="report-cover">
        <h1>Security Posture Report</h1>
        <p>Data period {model.period}</p>
        <p>
          Issued {day} · Report {model.digest}
        </p>
        <p>{model.verdict.text}</p>
      </div>
      {foot}
      <h2>Summary</h2>
      <p>
        {model.open.length} open findings (
        {model.open.filter((a) => a.severity === "SEVERITY_CRITICAL").length}{" "}
        critical) · {model.coverage.monitored} assets watched (
        {model.coverage.stale} stale) · {lists.r.length} validation results ·{" "}
        {lists.c.length} supply components.
      </p>
      <div className="report-figure">
        <TrendChart days={model.days} />
      </div>
      <p>{summarizeTrend(model.days, model.attention.length)}</p>
      {foot}
      <h2>Top findings</h2>
      {model.ranked.length === 0 ? (
        <p>No open findings in this period.</p>
      ) : (
        <ol>
          {model.ranked.slice(0, 10).map((a) => (
            <li key={a.id}>
              {a.title} — {a.severity}, open {alertAgeDays(a, model.nowMs)}{" "}
              days, status {a.status}. Open {alertAgeDays(a, model.nowMs)} days
              with {a.severity} severity.
            </li>
          ))}
        </ol>
      )}
      {foot}
      <h2>By domain</h2>
      {model.domains.map((d) => (
        <div key={d.key}>
          <h3>
            {d.label} — {d.figure}
          </h3>
          {d.key === "surface" &&
            (model.ranked.length === 0 ? (
              <p>No open findings.</p>
            ) : (
              <ol>
                {model.ranked.slice(0, 3).map((a) => (
                  <li key={a.id}>
                    {a.title} ({a.severity})
                  </li>
                ))}
              </ol>
            ))}
        </div>
      ))}
      {foot}
      <h2>Supply chain</h2>
      <p>
        {lists.c.length} components · {model.violating.length} in policy
        violation · {model.outdated.length} outdated or unsupported ·{" "}
        {lists.p.length} policies defined · {model.pendingVendors.length} vendor
        assessments awaiting review.
      </p>
      {foot}
      <h2>Validation</h2>
      {lists.r.length === 0 ? (
        <p>No validation results yet — findings above are untested.</p>
      ) : (
        <>
          <p>
            {lists.r.length} results · {model.badResults.length} executed
            without detection · latest{" "}
            {model.latestValidation ? shortDate(model.latestValidation) : "—"}.
          </p>
          <ul>
            {[...new Set(lists.r.map((r) => r.verdict))].map((v) => (
              <li key={v}>
                {v}: {VERDICT_MEANINGS[v]}
              </li>
            ))}
          </ul>
        </>
      )}
      {foot}
      <h2>Governance</h2>
      {model.attention.length === 0 ? (
        <p>Nothing needs a decision this week.</p>
      ) : (
        <ol>
          {model.attention.map((item) => (
            <li key={item.key}>
              {item.text} ({item.context})
            </li>
          ))}
        </ol>
      )}
      <p>Exceptions are tracked in the Governance workspace.</p>
      {foot}
      <h2>Appendix A</h2>
      <p>All open findings.</p>
      {model.open.length === 0 ? (
        <p>None.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Finding</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Age (days)</th>
            </tr>
          </thead>
          <tbody>
            {model.ranked.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.id}</td>
                <td>{a.title}</td>
                <td>{a.severity}</td>
                <td>{a.status}</td>
                <td>{alertAgeDays(a, model.nowMs)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {foot}
      <h2>Appendix B</h2>
      <p>Evidence integrity.</p>
      {lists.ev.length === 0 ? (
        <p>No evidence items.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Kind</th>
              <th>Collected</th>
              <th>SHA-256</th>
              <th>Integrity</th>
            </tr>
          </thead>
          <tbody>
            {lists.ev.map((e) => (
              <tr key={e.id}>
                <td className="mono">{e.id}</td>
                <td>{e.type}</td>
                <td>{fmtTime(e.collected_at)}</td>
                <td className="mono" title={e.sha256 ?? ""}>
                  {(e.sha256 ?? "—").slice(0, 16)}…
                </td>
                <td>Envelope verified</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {foot}
      <h2>Limitations</h2>
      <p>
        {model.unknownDomains.length === 0
          ? "All tracked domains contributed data to this report."
          : `${model.unknownDomains.join(", ")} contributed no data and ${model.unknownDomains.length === 1 ? "is" : "are"} out of this report's scope.`}
      </p>
      <p>Data period {model.period}.</p>
      <p>
        Findings not yet validated are untested claims, not confirmed breaches.
        Component statuses are observed metadata with basis recorded in the
        Supply Chain workspace.
      </p>
      {foot}
    </div>
  );
}
