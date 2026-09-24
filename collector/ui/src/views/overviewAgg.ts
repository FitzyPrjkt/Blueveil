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
    // Older than 30 days: out of window for the chart, still counted in cards.
    if (!row) continue;
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

export function summarizeTrend(
  days: TrendDay[],
  attentionCount: number,
): string {
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

// Supply FAIL signals come from the components list: the policies endpoint
// carries definitions only (no inline evaluate result), while the Supply
// Chain workspace itself renders POLICY_VIOLATION / OUTDATED / UNSUPPORTED
// component statuses as its fail signal. Overview reuses that exact signal.
export function violatingComponents(
  components: SupplyComponent[],
): SupplyComponent[] {
  return components.filter((c) => c.status === "POLICY_VIOLATION");
}

export function pickAttention(
  input: AttentionInput,
  nowMs: number,
): AttentionItem[] {
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
  const violating = violatingComponents(input.components);
  if (violating.length > 0 && out.length < 5) {
    out.push({
      key: "supply-violation",
      severity: "critical",
      text: `${violating.length} component${violating.length === 1 ? "" : "s"} in policy violation`,
      context: violating
        .slice(0, 2)
        .map((c) => c.name)
        .join(", "),
      href: "#/supply-chain",
    });
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

export interface Verdict {
  tone: "critical" | "attention" | "ok" | "unknown";
  text: string;
}

// S0 verdict precedence. Shared with the report plan — import, don't copy.
export function verdictOf(input: AttentionInput, nowMs: number): Verdict {
  const open = openAlerts(input.alerts);
  const critical = open.filter((a) => a.severity === "SEVERITY_CRITICAL");
  const aging = open.filter((a) => alertAgeDays(a, nowMs) > 30);
  const violating = violatingComponents(input.components);
  // Local calendar day: the verdict is read by a human "today", not in UTC.
  const today = new Date(nowMs).toLocaleDateString("en-CA");
  const allEmpty =
    input.alerts.length === 0 &&
    input.assets.length === 0 &&
    input.incidents.length === 0 &&
    input.results.length === 0 &&
    input.components.length === 0;
  if (allEmpty)
    return {
      tone: "unknown",
      text: "Not enough data yet — connect a source to see posture.",
    };
  if (critical.length > 0) {
    const oldest = Math.max(...critical.map((a) => alertAgeDays(a, nowMs)));
    return {
      tone: "critical",
      text: `Needs attention — ${critical.length} critical open, oldest ${oldest} days.`,
    };
  }
  if (violating.length > 0)
    return {
      tone: "critical",
      text: `Needs attention — ${violating.length} component${violating.length === 1 ? " is" : "s are"} in policy violation.`,
    };
  if (aging.length > 0)
    return {
      tone: "attention",
      text: `${aging.length} aging finding${aging.length === 1 ? "" : "s"} (30+ days) — need${aging.length === 1 ? "s" : ""} a decision.`,
    };
  return { tone: "ok", text: `Controlled — no critical open · ${today}.` };
}

export function buildDomainRows(input: AttentionInput): DomainRow[] {
  const open = openAlerts(input.alerts);
  const activeIncidents = input.incidents.filter(
    (i) =>
      i.status === "INCIDENT_STATUS_OPEN" ||
      i.status === "INCIDENT_STATUS_INVESTIGATING",
  );
  const violating = violatingComponents(input.components);
  const badResults = input.results.filter(
    (r) => r.verdict === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
  );
  return [
    {
      key: "surface",
      label: "Attack Surface",
      status:
        open.length === 0 ? "unknown" : statusFor(open, ["SEVERITY_HIGH"]),
      figure: `${open.length} open findings`,
      href: "#/findings?status=ALERT_STATUS_OPEN",
    },
    {
      key: "supply",
      label: "Supply Chain",
      status:
        input.components.length === 0
          ? "unknown"
          : violating.length > 0
            ? "critical"
            : "ok",
      figure: `${input.components.length} components · ${violating.length} in violation`,
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
