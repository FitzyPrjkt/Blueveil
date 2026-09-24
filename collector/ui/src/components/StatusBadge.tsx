import type { Severity } from "../contracts";

// Status badge (G): pill + dot, semantic colors fixed across themes.
// Verdict/status strings render VERBATIM — never mapped to PASS/FAIL.
const SEV_CLASS: Record<
  Severity,
  "critical" | "high" | "medium" | "low" | "info"
> = {
  SEVERITY_CRITICAL: "critical",
  SEVERITY_HIGH: "high",
  SEVERITY_MEDIUM: "medium",
  SEVERITY_LOW: "low",
  SEVERITY_INFO: "info",
};

export function shortEnum(v: string): string {
  const parts = v.split("_");
  // Drop the family prefix: SEVERITY_HIGH → HIGH, INCIDENT_STATUS_OPEN → OPEN.
  if (parts[0] === "SEVERITY" || parts[0] === "VERIFICATION")
    return parts.slice(1).join(" ");
  if (
    parts[0] === "INCIDENT" ||
    parts[0] === "ALERT" ||
    parts[0] === "RESPONSE" ||
    parts[0] === "EVIDENCE" ||
    parts[0] === "VALIDATION" ||
    parts[0] === "OPERATION" ||
    parts[0] === "RISK"
  ) {
    return parts.slice(2).join(" ");
  }
  return v;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge ${SEV_CLASS[severity]}`}>
      <span className="dot" aria-hidden="true" />
      {shortEnum(severity)}
    </span>
  );
}

//tone: info default; warn for pending-ish; bad for denied/failed/gap;
//low (green) ONLY for verified/prevented-and-detected terminal goods.
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

export function verdictTone(
  v: string,
): "info" | "warn" | "bad" | "low" | "neutral" {
  if (
    v === "VALIDATION_VERDICT_PREVENTED" ||
    v === "VALIDATION_VERDICT_PREVENTED_AND_DETECTED"
  )
    return "low";
  if (v === "VALIDATION_VERDICT_DETECTED") return "info";
  if (v === "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED") return "bad";
  if (
    v === "VALIDATION_VERDICT_ALLOWED_BUT_DETECTED" ||
    v === "VALIDATION_VERDICT_RATE_LIMITED"
  )
    return "warn";
  return "neutral"; // UNKNOWN, NOT_TESTED: deliberately uncolored claims
}

// exerciseTone colors a purple-team exercise STATUS (not its verdict):
// the two vocabularies must never share one pill.
export function exerciseTone(
  s: string,
): "info" | "warn" | "bad" | "low" | "neutral" {
  if (s === "PREVENTED" || s === "PREVENTED_AND_DETECTED") return "low";
  if (s === "DETECTED") return "info";
  if (s === "ALLOWED_AND_NOT_DETECTED") return "bad";
  if (s === "ALLOWED_BUT_DETECTED" || s === "RATE_LIMITED") return "warn";
  return "neutral"; // ATTEMPTED, NOT_TESTED, UNKNOWN_OUTCOME, PROVIDER_FAILURE
}

export function incidentTone(
  v: string,
): "info" | "warn" | "bad" | "low" | "neutral" {
  if (v === "INCIDENT_STATUS_OPEN") return "bad";
  if (
    v === "INCIDENT_STATUS_INVESTIGATING" ||
    v === "INCIDENT_STATUS_CONTAINED"
  )
    return "warn";
  if (v === "INCIDENT_STATUS_RESOLVED" || v === "INCIDENT_STATUS_CLOSED")
    return "low";
  return "neutral";
}

export function responseTone(
  v: string,
): "info" | "warn" | "bad" | "low" | "neutral" {
  if (
    v === "RESPONSE_STATUS_DENIED" ||
    v === "RESPONSE_STATUS_EXECUTION_FAILED" ||
    v === "RESPONSE_STATUS_VERIFICATION_FAILED"
  )
    return "bad";
  if (
    v === "RESPONSE_STATUS_PENDING_APPROVAL" ||
    v === "RESPONSE_STATUS_EXECUTING"
  )
    return "warn";
  if (v === "RESPONSE_STATUS_VERIFIED") return "low";
  return "info";
}
