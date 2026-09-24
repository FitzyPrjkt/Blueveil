// Hand-mirrored contract types (snake_case, verbatim enum strings) plus
// validating parsers: unknown JSON in, typed object out, throw on mismatch.
// This is the UI's §12L response validation — zero dependencies.
//
// proto3 JSON semantics apply: absent default scalars (0, false, empty
// maps/lists) decode to their zero values. Required strings/enums/
// timestamps are always present (backend validators reject empties), so
// only confidence/success/approval_required carry explicit defaults below.

export type Severity =
  | "SEVERITY_INFO"
  | "SEVERITY_LOW"
  | "SEVERITY_MEDIUM"
  | "SEVERITY_HIGH"
  | "SEVERITY_CRITICAL";

export const SEVERITIES: Severity[] = [
  "SEVERITY_INFO",
  "SEVERITY_LOW",
  "SEVERITY_MEDIUM",
  "SEVERITY_HIGH",
  "SEVERITY_CRITICAL",
];

export type AlertStatus =
  "ALERT_STATUS_OPEN" | "ALERT_STATUS_ACKNOWLEDGED" | "ALERT_STATUS_CLOSED";
export const ALERT_STATUSES: AlertStatus[] = [
  "ALERT_STATUS_OPEN",
  "ALERT_STATUS_ACKNOWLEDGED",
  "ALERT_STATUS_CLOSED",
];

export type IncidentStatus =
  | "INCIDENT_STATUS_OPEN"
  | "INCIDENT_STATUS_INVESTIGATING"
  | "INCIDENT_STATUS_CONTAINED"
  | "INCIDENT_STATUS_RESOLVED"
  | "INCIDENT_STATUS_CLOSED";

export type EvidenceType =
  | "EVIDENCE_TYPE_LOG_EXCERPT"
  | "EVIDENCE_TYPE_HTTP_REQUEST"
  | "EVIDENCE_TYPE_HTTP_RESPONSE"
  | "EVIDENCE_TYPE_SCAN_RESULT"
  | "EVIDENCE_TYPE_FILE_HASH"
  | "EVIDENCE_TYPE_NOTE";

export type ValidationVerdict =
  | "VALIDATION_VERDICT_PREVENTED"
  | "VALIDATION_VERDICT_DETECTED"
  | "VALIDATION_VERDICT_PREVENTED_AND_DETECTED"
  | "VALIDATION_VERDICT_ALLOWED_BUT_DETECTED"
  | "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED"
  | "VALIDATION_VERDICT_UNKNOWN"
  | "VALIDATION_VERDICT_NOT_TESTED"
  | "VALIDATION_VERDICT_RATE_LIMITED";

export const VERDICTS: ValidationVerdict[] = [
  "VALIDATION_VERDICT_PREVENTED",
  "VALIDATION_VERDICT_DETECTED",
  "VALIDATION_VERDICT_PREVENTED_AND_DETECTED",
  "VALIDATION_VERDICT_ALLOWED_BUT_DETECTED",
  "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
  "VALIDATION_VERDICT_UNKNOWN",
  "VALIDATION_VERDICT_NOT_TESTED",
  "VALIDATION_VERDICT_RATE_LIMITED",
];

// Human meanings, verbatim semantics. There is deliberately no SECURE and
// no PASS/FAIL mapping anywhere in this file.
export const VERDICT_MEANINGS: Record<ValidationVerdict, string> = {
  VALIDATION_VERDICT_PREVENTED:
    "Attack blocked; no attacker-observable effect.",
  VALIDATION_VERDICT_DETECTED: "Attack executed but detected and logged.",
  VALIDATION_VERDICT_PREVENTED_AND_DETECTED: "Blocked and detected.",
  VALIDATION_VERDICT_ALLOWED_BUT_DETECTED:
    "Executed and detected: prevention failed, detection worked.",
  VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED:
    "Executed and not detected: control gap.",
  VALIDATION_VERDICT_UNKNOWN:
    "Validation ran without a determinate outcome: inconclusive.",
  VALIDATION_VERDICT_NOT_TESTED: "Validation was not performed.",
  VALIDATION_VERDICT_RATE_LIMITED:
    "Request throttled: neither clean prevention nor full allowance.",
};

export type ResponseStatus =
  | "RESPONSE_STATUS_PROPOSED"
  | "RESPONSE_STATUS_PENDING_APPROVAL"
  | "RESPONSE_STATUS_APPROVED"
  | "RESPONSE_STATUS_DENIED"
  | "RESPONSE_STATUS_EXECUTING"
  | "RESPONSE_STATUS_EXECUTED"
  | "RESPONSE_STATUS_EXECUTION_FAILED"
  | "RESPONSE_STATUS_VERIFIED"
  | "RESPONSE_STATUS_VERIFICATION_FAILED"
  | "RESPONSE_STATUS_VERIFICATION_UNKNOWN";

export interface TelemetryEvent {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  identity_id?: string;
  event_type: string;
  severity: Severity;
  attributes?: Record<string, string>;
  raw?: string;
}

export interface Detection {
  id: string;
  rule_id: string;
  rule_name: string;
  telemetry_event_ids: string[];
  detected_at: string;
  severity: Severity;
  confidence: number;
  title: string;
  description?: string;
  attributes?: Record<string, string>;
}

export interface Alert {
  id: string;
  detection_ids: string[];
  status: AlertStatus;
  severity: Severity;
  created_at: string;
  updated_at: string;
  title: string;
}

export interface Incident {
  id: string;
  alert_ids: string[];
  status: IncidentStatus;
  severity: Severity;
  created_at: string;
  updated_at: string;
  title: string;
  summary?: string;
}

export interface Evidence {
  id: string;
  incident_id: string;
  type: EvidenceType;
  collected_at: string;
  source: string;
  media_type: string;
  sha256?: string;
  content: string;
}

export interface EvidenceEnvelope {
  data: Evidence;
  integrity: "verified";
}

export interface ValidationRequest {
  id: string;
  control_id: string;
  target: string;
  context?: Record<string, string>;
  requested_at: string;
}

export interface ValidationResult {
  id: string;
  request_id: string;
  control_id: string;
  provider: string;
  provider_version?: string;
  contract_version: string;
  verdict: ValidationVerdict;
  validated_at: string;
  evidence_ids?: string[];
  note?: string;
}

export interface ResponseRecommendation {
  id: string;
  incident_id: string;
  operation: string;
  target: string;
  risk: string;
  reason: string;
  status: ResponseStatus;
  recommended_at: string;
  recommended_by: string;
  approval_required: boolean;
}

export interface ResponseApproval {
  id: string;
  recommendation_id: string;
  operation: string;
  target: string;
  risk: string;
  approver: string;
  approved_at: string;
  expires_at?: string;
  reason: string;
}

export interface ResponseExecution {
  id: string;
  recommendation_id: string;
  approval_id?: string;
  operation: string;
  target: string;
  started_at: string;
  finished_at: string;
  success: boolean;
  detail: string;
}

export interface ResponseVerification {
  id: string;
  execution_id: string;
  outcome: string;
  verified_at: string;
  detail: string;
}

export interface AuditEntry {
  id: string;
  decided_at: string;
  actor: string;
  operation: string;
  risk: string;
  decision: string;
  reason: string;
  result: string;
  response_id: string;
  phase: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function reqStr(o: Record<string, unknown>, key: string, what: string): string {
  const v = o[key];
  if (typeof v !== "string" || v === "")
    throw new Error(`${what}.${key} must be a non-empty string`);
  return v;
}

function optStr(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string | undefined {
  const v = o[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new Error(`${what}.${key} must be a string`);
  return v;
}

function reqEnum<T extends string>(
  o: Record<string, unknown>,
  key: string,
  what: string,
  allowed: readonly T[],
): T {
  const v = o[key];
  if (typeof v !== "string" || !(allowed as readonly string[]).includes(v)) {
    throw new Error(`${what}.${key} has unknown value ${JSON.stringify(v)}`);
  }
  return v as T;
}

function reqStrArr(
  o: Record<string, unknown>,
  key: string,
  what: string,
  nonEmpty: boolean,
): string[] {
  const v = o[key];
  if (
    !Array.isArray(v) ||
    (nonEmpty && v.length === 0) ||
    v.some((x) => typeof x !== "string")
  ) {
    throw new Error(`${what}.${key} must be a string array`);
  }
  return v as string[];
}

function reqTime(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string {
  const s = reqStr(o, key, what);
  if (Number.isNaN(Date.parse(s)))
    throw new Error(`${what}.${key} is not a timestamp`);
  return s;
}

function optStrMap(
  o: Record<string, unknown>,
  key: string,
  what: string,
): Record<string, string> | undefined {
  const v = o[key];
  // Explicit null ≡ absent for optional maps (Go serializes nil maps as
  // null). Consistent with reqStrArrOpt, which already tolerates null.
  if (v === undefined || v === null) return undefined;
  if (!isRecord(v) || Object.values(v).some((x) => typeof x !== "string")) {
    throw new Error(`${what}.${key} must be a string map`);
  }
  return v as Record<string, string>;
}

function reqNum(o: Record<string, unknown>, key: string, what: string): number {
  const v = o[key];
  if (typeof v !== "number") throw new Error(`${what}.${key} must be a number`);
  return v;
}

function parseConfidence(o: Record<string, unknown>): number {
  if (o["confidence"] === undefined) return 0;
  const c = reqNum(o, "confidence", "Detection");
  if (!Number.isFinite(c) || c < 0 || c > 1) {
    throw new Error(`Detection.confidence ${JSON.stringify(c)} out of [0, 1]`);
  }
  return c;
}

function reqBool(
  o: Record<string, unknown>,
  key: string,
  what: string,
): boolean {
  const v = o[key];
  if (typeof v !== "boolean")
    throw new Error(`${what}.${key} must be a boolean`);
  return v;
}

function asObject(v: unknown, what: string): Record<string, unknown> {
  if (!isRecord(v)) throw new Error(`${what} must be an object`);
  return v;
}

export function parseTelemetryEvent(v: unknown): TelemetryEvent {
  const o = asObject(v, "TelemetryEvent");
  return {
    id: reqStr(o, "id", "TelemetryEvent"),
    occurred_at: reqTime(o, "occurred_at", "TelemetryEvent"),
    source: reqStr(o, "source", "TelemetryEvent"),
    asset_id: reqStr(o, "asset_id", "TelemetryEvent"),
    identity_id: optStr(o, "identity_id", "TelemetryEvent"),
    event_type: reqStr(o, "event_type", "TelemetryEvent"),
    severity: reqEnum(o, "severity", "TelemetryEvent", SEVERITIES),
    attributes: optStrMap(o, "attributes", "TelemetryEvent"),
    raw: optStr(o, "raw", "TelemetryEvent"),
  };
}

export function parseDetection(v: unknown): Detection {
  const o = asObject(v, "Detection");
  return {
    id: reqStr(o, "id", "Detection"),
    rule_id: reqStr(o, "rule_id", "Detection"),
    rule_name: reqStr(o, "rule_name", "Detection"),
    telemetry_event_ids: reqStrArr(o, "telemetry_event_ids", "Detection", true),
    detected_at: reqTime(o, "detected_at", "Detection"),
    severity: reqEnum(o, "severity", "Detection", SEVERITIES),
    confidence: parseConfidence(o),
    title: reqStr(o, "title", "Detection"),
    description: optStr(o, "description", "Detection"),
    attributes: optStrMap(o, "attributes", "Detection"),
  };
}

export function parseAlert(v: unknown): Alert {
  const o = asObject(v, "Alert");
  return {
    id: reqStr(o, "id", "Alert"),
    detection_ids: reqStrArr(o, "detection_ids", "Alert", true),
    status: reqEnum(o, "status", "Alert", ALERT_STATUSES),
    severity: reqEnum(o, "severity", "Alert", SEVERITIES),
    created_at: reqTime(o, "created_at", "Alert"),
    updated_at: reqTime(o, "updated_at", "Alert"),
    title: reqStr(o, "title", "Alert"),
  };
}

export function parseIncident(v: unknown): Incident {
  const o = asObject(v, "Incident");
  const statuses: IncidentStatus[] = [
    "INCIDENT_STATUS_OPEN",
    "INCIDENT_STATUS_INVESTIGATING",
    "INCIDENT_STATUS_CONTAINED",
    "INCIDENT_STATUS_RESOLVED",
    "INCIDENT_STATUS_CLOSED",
  ];
  return {
    id: reqStr(o, "id", "Incident"),
    alert_ids: reqStrArr(o, "alert_ids", "Incident", true),
    status: reqEnum(o, "status", "Incident", statuses),
    severity: reqEnum(o, "severity", "Incident", SEVERITIES),
    created_at: reqTime(o, "created_at", "Incident"),
    updated_at: reqTime(o, "updated_at", "Incident"),
    title: reqStr(o, "title", "Incident"),
    summary: optStr(o, "summary", "Incident"),
  };
}

export function parseEvidence(v: unknown): Evidence {
  const o = asObject(v, "Evidence");
  const types: EvidenceType[] = [
    "EVIDENCE_TYPE_LOG_EXCERPT",
    "EVIDENCE_TYPE_HTTP_REQUEST",
    "EVIDENCE_TYPE_HTTP_RESPONSE",
    "EVIDENCE_TYPE_SCAN_RESULT",
    "EVIDENCE_TYPE_FILE_HASH",
    "EVIDENCE_TYPE_NOTE",
  ];
  return {
    id: reqStr(o, "id", "Evidence"),
    incident_id: reqStr(o, "incident_id", "Evidence"),
    type: reqEnum(o, "type", "Evidence", types),
    collected_at: reqTime(o, "collected_at", "Evidence"),
    source: reqStr(o, "source", "Evidence"),
    media_type: reqStr(o, "media_type", "Evidence"),
    sha256: parseSha256(o),
    content: reqStr(o, "content", "Evidence"),
  };
}

function parseSha256(o: Record<string, unknown>): string {
  const v = optStr(o, "sha256", "Evidence") ?? "";
  if (v !== "" && !/^[0-9a-f]{64}$/.test(v)) {
    throw new Error(`Evidence.sha256 must be 64 lowercase-hex chars`);
  }
  return v;
}

export function parseEvidenceEnvelope(v: unknown): EvidenceEnvelope {
  const o = asObject(v, "EvidenceEnvelope");
  const integrity = o["integrity"];
  if (integrity !== "verified")
    throw new Error('EvidenceEnvelope.integrity must be "verified"');
  return { data: parseEvidence(o["data"]), integrity: "verified" };
}

export function parseValidationResult(v: unknown): ValidationResult {
  const o = asObject(v, "ValidationResult");
  return {
    id: reqStr(o, "id", "ValidationResult"),
    request_id: reqStr(o, "request_id", "ValidationResult"),
    control_id: reqStr(o, "control_id", "ValidationResult"),
    provider: reqStr(o, "provider", "ValidationResult"),
    provider_version: optStr(o, "provider_version", "ValidationResult"),
    contract_version: reqStr(o, "contract_version", "ValidationResult"),
    verdict: reqEnum(o, "verdict", "ValidationResult", VERDICTS),
    validated_at: reqTime(o, "validated_at", "ValidationResult"),
    evidence_ids:
      o["evidence_ids"] === undefined
        ? undefined
        : reqStrArr(o, "evidence_ids", "ValidationResult", false),
    note: optStr(o, "note", "ValidationResult"),
  };
}

export function parseRecommendation(v: unknown): ResponseRecommendation {
  const o = asObject(v, "ResponseRecommendation");
  const statuses: ResponseStatus[] = [
    "RESPONSE_STATUS_PROPOSED",
    "RESPONSE_STATUS_PENDING_APPROVAL",
    "RESPONSE_STATUS_APPROVED",
    "RESPONSE_STATUS_DENIED",
    "RESPONSE_STATUS_EXECUTING",
    "RESPONSE_STATUS_EXECUTED",
    "RESPONSE_STATUS_EXECUTION_FAILED",
    "RESPONSE_STATUS_VERIFIED",
    "RESPONSE_STATUS_VERIFICATION_FAILED",
    "RESPONSE_STATUS_VERIFICATION_UNKNOWN",
  ];
  return {
    id: reqStr(o, "id", "ResponseRecommendation"),
    incident_id: reqStr(o, "incident_id", "ResponseRecommendation"),
    operation: reqStr(o, "operation", "ResponseRecommendation"),
    target: reqStr(o, "target", "ResponseRecommendation"),
    risk: reqStr(o, "risk", "ResponseRecommendation"),
    reason: reqStr(o, "reason", "ResponseRecommendation"),
    status: reqEnum(o, "status", "ResponseRecommendation", statuses),
    recommended_at: reqTime(o, "recommended_at", "ResponseRecommendation"),
    recommended_by: reqStr(o, "recommended_by", "ResponseRecommendation"),
    approval_required:
      o["approval_required"] === undefined
        ? false
        : reqBool(o, "approval_required", "ResponseRecommendation"),
  };
}

export function parseApproval(v: unknown): ResponseApproval {
  const o = asObject(v, "ResponseApproval");
  return {
    id: reqStr(o, "id", "ResponseApproval"),
    recommendation_id: reqStr(o, "recommendation_id", "ResponseApproval"),
    operation: reqStr(o, "operation", "ResponseApproval"),
    target: reqStr(o, "target", "ResponseApproval"),
    risk: reqStr(o, "risk", "ResponseApproval"),
    approver: reqStr(o, "approver", "ResponseApproval"),
    approved_at: reqTime(o, "approved_at", "ResponseApproval"),
    expires_at: optTimeOpt(o, "expires_at", "ResponseApproval"),
    reason: reqStr(o, "reason", "ResponseApproval"),
  };
}

export function parseExecution(v: unknown): ResponseExecution {
  const o = asObject(v, "ResponseExecution");
  return {
    id: reqStr(o, "id", "ResponseExecution"),
    recommendation_id: reqStr(o, "recommendation_id", "ResponseExecution"),
    approval_id: optStr(o, "approval_id", "ResponseExecution"),
    operation: reqStr(o, "operation", "ResponseExecution"),
    target: reqStr(o, "target", "ResponseExecution"),
    started_at: reqTime(o, "started_at", "ResponseExecution"),
    finished_at: reqTime(o, "finished_at", "ResponseExecution"),
    success:
      o["success"] === undefined
        ? false
        : reqBool(o, "success", "ResponseExecution"),
    detail: reqStr(o, "detail", "ResponseExecution"),
  };
}

export function parseVerification(v: unknown): ResponseVerification {
  const o = asObject(v, "ResponseVerification");
  return {
    id: reqStr(o, "id", "ResponseVerification"),
    execution_id: reqStr(o, "execution_id", "ResponseVerification"),
    outcome: reqStr(o, "outcome", "ResponseVerification"),
    verified_at: reqTime(o, "verified_at", "ResponseVerification"),
    detail: reqStr(o, "detail", "ResponseVerification"),
  };
}

export function parseAuditEntry(v: unknown): AuditEntry {
  const o = asObject(v, "AuditEntry");
  return {
    id: reqStr(o, "id", "AuditEntry"),
    decided_at: reqTime(o, "decided_at", "AuditEntry"),
    actor: reqStr(o, "actor", "AuditEntry"),
    operation: reqStr(o, "operation", "AuditEntry"),
    risk: reqStr(o, "risk", "AuditEntry"),
    decision: reqStr(o, "decision", "AuditEntry"),
    reason: optStr(o, "reason", "AuditEntry") ?? "",
    result: optStr(o, "result", "AuditEntry") ?? "",
    response_id: optStr(o, "response_id", "AuditEntry") ?? "",
    phase: optStr(o, "phase", "AuditEntry") ?? "",
  };
}

export function parseValidationRequest(v: unknown): ValidationRequest {
  const o = asObject(v, "ValidationRequest");
  return {
    id: reqStr(o, "id", "ValidationRequest"),
    control_id: reqStr(o, "control_id", "ValidationRequest"),
    target: reqStr(o, "target", "ValidationRequest"),
    context: optStrMap(o, "context", "ValidationRequest"),
    requested_at: reqTime(o, "requested_at", "ValidationRequest"),
  };
}

export function parseTelemetryList(v: unknown): TelemetryEvent[] {
  if (!Array.isArray(v)) throw new Error("expected array");
  return v.map(parseTelemetryEvent);
}

export type AssetType =
  | "ASSET_TYPE_HOST"
  | "ASSET_TYPE_CONTAINER"
  | "ASSET_TYPE_SERVICE"
  | "ASSET_TYPE_NETWORK"
  | "ASSET_TYPE_CLOUD_RESOURCE"
  | "ASSET_TYPE_USER_DEVICE"
  | "ASSET_TYPE_OTHER"
  | "ASSET_TYPE_DOMAIN"
  | "ASSET_TYPE_IP_ADDRESS"
  | "ASSET_TYPE_URL"
  | "ASSET_TYPE_APPLICATION";

export const ASSET_TYPES: AssetType[] = [
  "ASSET_TYPE_HOST",
  "ASSET_TYPE_CONTAINER",
  "ASSET_TYPE_SERVICE",
  "ASSET_TYPE_NETWORK",
  "ASSET_TYPE_CLOUD_RESOURCE",
  "ASSET_TYPE_USER_DEVICE",
  "ASSET_TYPE_OTHER",
  "ASSET_TYPE_DOMAIN",
  "ASSET_TYPE_IP_ADDRESS",
  "ASSET_TYPE_URL",
  "ASSET_TYPE_APPLICATION",
];

export type AssetStatus =
  | "ASSET_STATUS_DISCOVERED"
  | "ASSET_STATUS_ACTIVE"
  | "ASSET_STATUS_STALE"
  | "ASSET_STATUS_RETIRED";

export const ASSET_STATUSES: AssetStatus[] = [
  "ASSET_STATUS_DISCOVERED",
  "ASSET_STATUS_ACTIVE",
  "ASSET_STATUS_STALE",
  "ASSET_STATUS_RETIRED",
];

export interface AssetIdentifier {
  type: string;
  value: string;
}

export interface Asset {
  id: string;
  type: AssetType;
  name: string;
  identifiers?: AssetIdentifier[];
  criticality?: Severity;
  environment?: string;
  status?: AssetStatus;
  first_seen?: string;
  last_seen?: string;
  attributes?: Record<string, string>;
}

export interface AssetRelationship {
  parent_id: string;
  child_id: string;
  kind: string;
  source: string;
  observed_at: string;
}

export function parseAsset(v: unknown): Asset {
  const o = asObject(v, "Asset");
  const rawIds = o["identifiers"];
  let identifiers: AssetIdentifier[] | undefined;
  if (rawIds !== undefined) {
    if (!Array.isArray(rawIds))
      throw new Error("Asset.identifiers must be an array");
    identifiers = rawIds.map((item, i) => {
      const io = asObject(item, `Asset.identifiers[${i}]`);
      return {
        type: reqStr(io, "type", "Asset"),
        value: reqStr(io, "value", "Asset"),
      };
    });
  }
  const crit = o["criticality"];
  const status = o["status"];
  return {
    id: reqStr(o, "id", "Asset"),
    type: reqEnum(o, "type", "Asset", ASSET_TYPES),
    name: reqStr(o, "name", "Asset"),
    identifiers,
    criticality:
      crit === undefined
        ? undefined
        : reqEnum(o, "criticality", "Asset", SEVERITIES),
    environment: optStr(o, "environment", "Asset"),
    status:
      status === undefined
        ? undefined
        : reqEnum(o, "status", "Asset", ASSET_STATUSES),
    first_seen: optTime(o, "first_seen", "Asset"),
    last_seen: optTime(o, "last_seen", "Asset"),
    attributes: optStrMap(o, "attributes", "Asset"),
  };
}

function optTime(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string | undefined {
  const v = o[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) {
    throw new Error(`${what}.${key} must be a timestamp`);
  }
  return v;
}

// optTimeOrEmpty: backend emits "" for unset timestamps, RFC3339 otherwise.
// Anything else is corrupt and must invalidate the row.
function optTimeOrEmpty(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string {
  const v = o[key];
  if (v === "" || v === undefined) return "";
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) {
    throw new Error(`${what}.${key} must be a timestamp`);
  }
  return v;
}

// optTimeOpt: optional timestamp that must parse when present.
function optTimeOpt(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string | undefined {
  const v = o[key];
  if (v === undefined || v === "") return undefined;
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) {
    throw new Error(`${what}.${key} must be a timestamp`);
  }
  return v;
}

export function parseAssetRelationship(v: unknown): AssetRelationship {
  const o = asObject(v, "AssetRelationship");
  return {
    parent_id: reqStr(o, "parent_id", "AssetRelationship"),
    child_id: reqStr(o, "child_id", "AssetRelationship"),
    kind: reqStr(o, "kind", "AssetRelationship"),
    source: reqStr(o, "source", "AssetRelationship"),
    observed_at: reqTime(o, "observed_at", "AssetRelationship"),
  };
}

export interface NetworkObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  direction?: string;
  verdict?: string;
  detected: boolean;
}

export function parseNetworkObservation(v: unknown): NetworkObservation {
  const o = asObject(v, "NetworkObservation");
  const id = reqStr(o, "id", "NetworkObservation");
  const occurred_at = reqTime(o, "occurred_at", "NetworkObservation");
  const source = reqStr(o, "source", "NetworkObservation");
  const asset_id = reqStr(o, "asset_id", "NetworkObservation");
  const severity = reqEnum(o, "severity", "NetworkObservation", SEVERITIES);
  const src_ip = reqStr(o, "src_ip", "NetworkObservation");
  const dst_ip = reqStr(o, "dst_ip", "NetworkObservation");
  const detected = reqBool(o, "detected", "NetworkObservation");
  let src_port: number | undefined;
  if (o["src_port"] !== undefined)
    src_port = reqNum(o, "src_port", "NetworkObservation");
  let dst_port: number | undefined;
  if (o["dst_port"] !== undefined)
    dst_port = reqNum(o, "dst_port", "NetworkObservation");
  const protocol = optStr(o, "protocol", "NetworkObservation");
  const direction = optStr(o, "direction", "NetworkObservation");
  const verdict = optStr(o, "verdict", "NetworkObservation");
  return {
    id,
    occurred_at,
    source,
    asset_id,
    severity,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    direction,
    verdict,
    detected,
  };
}

export interface ApplicationObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  method: string;
  host: string;
  path: string;
  scheme?: string;
  status_code?: number;
  content_type?: string;
  route?: string;
  api_version?: string;
  direction?: string;
  auth_outcome?: string;
  detected: boolean;
}

export function parseApplicationObservation(
  v: unknown,
): ApplicationObservation {
  const o = asObject(v, "ApplicationObservation");
  return {
    id: reqStr(o, "id", "ApplicationObservation"),
    occurred_at: reqTime(o, "occurred_at", "ApplicationObservation"),
    source: reqStr(o, "source", "ApplicationObservation"),
    asset_id: reqStr(o, "asset_id", "ApplicationObservation"),
    severity: reqEnum(o, "severity", "ApplicationObservation", SEVERITIES),
    method: reqStr(o, "method", "ApplicationObservation"),
    host: reqStr(o, "host", "ApplicationObservation"),
    path: reqStr(o, "path", "ApplicationObservation"),
    scheme: optStr(o, "scheme", "ApplicationObservation"),
    status_code:
      o["status_code"] !== undefined
        ? reqNum(o, "status_code", "ApplicationObservation")
        : undefined,
    content_type: optStr(o, "content_type", "ApplicationObservation"),
    route: optStr(o, "route", "ApplicationObservation"),
    api_version: optStr(o, "api_version", "ApplicationObservation"),
    direction: optStr(o, "direction", "ApplicationObservation"),
    auth_outcome: optStr(o, "auth_outcome", "ApplicationObservation"),
    detected: reqBool(o, "detected", "ApplicationObservation"),
  };
}

export interface EndpointObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  host: string;
  process: string;
  action: string;
  result: string;
  detected: boolean;
  user?: string;
  integrity_level?: string;
}

export function parseEndpointObservation(v: unknown): EndpointObservation {
  const o = asObject(v, "EndpointObservation");
  return {
    id: reqStr(o, "id", "EndpointObservation"),
    occurred_at: reqTime(o, "occurred_at", "EndpointObservation"),
    source: reqStr(o, "source", "EndpointObservation"),
    asset_id: reqStr(o, "asset_id", "EndpointObservation"),
    severity: reqEnum(o, "severity", "EndpointObservation", SEVERITIES),
    host: reqStr(o, "host", "EndpointObservation"),
    process: reqStr(o, "process", "EndpointObservation"),
    action: reqStr(o, "action", "EndpointObservation"),
    result: optStr(o, "result", "EndpointObservation") ?? "",
    detected: reqBool(o, "detected", "EndpointObservation"),
    user: optStr(o, "user", "EndpointObservation"),
    integrity_level: optStr(o, "integrity_level", "EndpointObservation"),
  };
}

export interface ServerObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  hostname: string;
  service: string;
  action: string;
  result: string;
  detected: boolean;
}

export function parseServerObservation(v: unknown): ServerObservation {
  const o = asObject(v, "ServerObservation");
  return {
    id: reqStr(o, "id", "ServerObservation"),
    occurred_at: reqTime(o, "occurred_at", "ServerObservation"),
    source: reqStr(o, "source", "ServerObservation"),
    asset_id: reqStr(o, "asset_id", "ServerObservation"),
    severity: reqEnum(o, "severity", "ServerObservation", SEVERITIES),
    hostname: reqStr(o, "hostname", "ServerObservation"),
    service: reqStr(o, "service", "ServerObservation"),
    action: reqStr(o, "action", "ServerObservation"),
    result: optStr(o, "result", "ServerObservation") ?? "",
    detected: reqBool(o, "detected", "ServerObservation"),
  };
}

export interface ContainerObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  container_id: string;
  image: string;
  cluster: string;
  namespace: string;
  privileged: boolean;
  host_network: boolean;
  host_pid: boolean;
  result: string;
  detected: boolean;
}

export function parseContainerObservation(v: unknown): ContainerObservation {
  const o = asObject(v, "ContainerObservation");
  return {
    id: reqStr(o, "id", "ContainerObservation"),
    occurred_at: reqTime(o, "occurred_at", "ContainerObservation"),
    source: reqStr(o, "source", "ContainerObservation"),
    asset_id: reqStr(o, "asset_id", "ContainerObservation"),
    severity: reqEnum(o, "severity", "ContainerObservation", SEVERITIES),
    container_id: reqStr(o, "container_id", "ContainerObservation"),
    image: reqStr(o, "image", "ContainerObservation"),
    cluster: optStr(o, "cluster", "ContainerObservation") ?? "",
    namespace: optStr(o, "namespace", "ContainerObservation") ?? "",
    privileged: reqBool(o, "privileged", "ContainerObservation"),
    host_network: reqBool(o, "host_network", "ContainerObservation"),
    host_pid: reqBool(o, "host_pid", "ContainerObservation"),
    result: optStr(o, "result", "ContainerObservation") ?? "",
    detected: reqBool(o, "detected", "ContainerObservation"),
  };
}

export interface CloudObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  provider: string;
  account: string;
  region: string;
  principal: string;
  action: string;
  result: string;
  detected: boolean;
}

export function parseCloudObservation(v: unknown): CloudObservation {
  const o = asObject(v, "CloudObservation");
  return {
    id: reqStr(o, "id", "CloudObservation"),
    occurred_at: reqTime(o, "occurred_at", "CloudObservation"),
    source: reqStr(o, "source", "CloudObservation"),
    asset_id: reqStr(o, "asset_id", "CloudObservation"),
    severity: reqEnum(o, "severity", "CloudObservation", SEVERITIES),
    provider: reqStr(o, "provider", "CloudObservation"),
    account: optStr(o, "account", "CloudObservation") ?? "",
    region: optStr(o, "region", "CloudObservation") ?? "",
    principal: optStr(o, "principal", "CloudObservation") ?? "",
    action: reqStr(o, "action", "CloudObservation"),
    result: reqStr(o, "result", "CloudObservation"),
    detected: reqBool(o, "detected", "CloudObservation"),
  };
}

export interface IdentityObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  principal: string;
  action: string;
  target?: string;
  result?: string;
  provider?: string;
  detected: boolean;
}

export function parseIdentityObservation(v: unknown): IdentityObservation {
  const o = asObject(v, "IdentityObservation");
  return {
    id: reqStr(o, "id", "IdentityObservation"),
    occurred_at: reqTime(o, "occurred_at", "IdentityObservation"),
    source: reqStr(o, "source", "IdentityObservation"),
    asset_id: reqStr(o, "asset_id", "IdentityObservation"),
    severity: reqEnum(o, "severity", "IdentityObservation", SEVERITIES),
    principal: reqStr(o, "principal", "IdentityObservation"),
    action: reqStr(o, "action", "IdentityObservation"),
    target: optStr(o, "target", "IdentityObservation"),
    result: optStr(o, "result", "IdentityObservation"),
    provider: optStr(o, "provider", "IdentityObservation"),
    detected: reqBool(o, "detected", "IdentityObservation"),
  };
}

export interface AuthObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  principal: string;
  outcome: string;
  method?: string;
  provider?: string;
  target?: string;
  failure_reason?: string;
  detected: boolean;
}

export function parseAuthObservation(v: unknown): AuthObservation {
  const o = asObject(v, "AuthObservation");
  return {
    id: reqStr(o, "id", "AuthObservation"),
    occurred_at: reqTime(o, "occurred_at", "AuthObservation"),
    source: reqStr(o, "source", "AuthObservation"),
    asset_id: reqStr(o, "asset_id", "AuthObservation"),
    severity: reqEnum(o, "severity", "AuthObservation", SEVERITIES),
    principal: reqStr(o, "principal", "AuthObservation"),
    outcome: reqStr(o, "outcome", "AuthObservation"),
    method: optStr(o, "method", "AuthObservation"),
    provider: optStr(o, "provider", "AuthObservation"),
    target: optStr(o, "target", "AuthObservation"),
    failure_reason: optStr(o, "failure_reason", "AuthObservation"),
    detected: reqBool(o, "detected", "AuthObservation"),
  };
}

export interface DataObservation {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  severity: string;
  resource: string;
  action: string;
  store?: string;
  principal?: string;
  classification?: string;
  result?: string;
  detected: boolean;
}

export function parseDataObservation(v: unknown): DataObservation {
  const o = asObject(v, "DataObservation");
  return {
    id: reqStr(o, "id", "DataObservation"),
    occurred_at: reqTime(o, "occurred_at", "DataObservation"),
    source: reqStr(o, "source", "DataObservation"),
    asset_id: reqStr(o, "asset_id", "DataObservation"),
    severity: reqEnum(o, "severity", "DataObservation", SEVERITIES),
    resource: reqStr(o, "resource", "DataObservation"),
    action: reqStr(o, "action", "DataObservation"),
    store: optStr(o, "store", "DataObservation"),
    principal: optStr(o, "principal", "DataObservation"),
    classification: optStr(o, "classification", "DataObservation"),
    result: optStr(o, "result", "DataObservation"),
    detected: reqBool(o, "detected", "DataObservation"),
  };
}

export interface MonitoringEvent {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  event_type: string;
  severity: string;
  attributes?: Record<string, string>;
}

export function parseMonitoringEvent(v: unknown): MonitoringEvent {
  const o = asObject(v, "MonitoringEvent");
  return {
    id: reqStr(o, "id", "MonitoringEvent"),
    occurred_at: reqTime(o, "occurred_at", "MonitoringEvent"),
    source: reqStr(o, "source", "MonitoringEvent"),
    asset_id: reqStr(o, "asset_id", "MonitoringEvent"),
    event_type: reqStr(o, "event_type", "MonitoringEvent"),
    severity: reqEnum(o, "severity", "MonitoringEvent", SEVERITIES),
    attributes: optStrMap(o, "attributes", "MonitoringEvent"),
  };
}

export interface MonitoringCorrelation {
  id: string;
  type: string;
  event_ids: string[];
  principal: string;
  asset_id: string;
  observed_at: string;
  status: string;
}

export function parseMonitoringCorrelation(v: unknown): MonitoringCorrelation {
  const o = asObject(v, "MonitoringCorrelation");
  return {
    id: reqStr(o, "id", "MonitoringCorrelation"),
    type: reqStr(o, "type", "MonitoringCorrelation"),
    event_ids: reqStrArr(o, "event_ids", "MonitoringCorrelation", false),
    principal: optStr(o, "principal", "MonitoringCorrelation") ?? "",
    asset_id: optStr(o, "asset_id", "MonitoringCorrelation") ?? "",
    observed_at: reqTime(o, "observed_at", "MonitoringCorrelation"),
    status: reqStr(o, "status", "MonitoringCorrelation"),
  };
}

export interface DetectionRuleMeta {
  id: string;
  version: string;
  title: string;
  description: string;
  domain: string;
  event_types: string[];
  severity_basis: string;
  confidence_basis: string;
  stateful: boolean;
  enabled: boolean;
}

export function parseDetectionRuleMeta(v: unknown): DetectionRuleMeta {
  const o = asObject(v, "DetectionRuleMeta");
  return {
    id: reqStr(o, "id", "DetectionRuleMeta"),
    version: reqStr(o, "version", "DetectionRuleMeta"),
    title: reqStr(o, "title", "DetectionRuleMeta"),
    description: reqStr(o, "description", "DetectionRuleMeta"),
    domain: reqStr(o, "domain", "DetectionRuleMeta"),
    event_types: reqStrArr(o, "event_types", "DetectionRuleMeta", false),
    severity_basis: reqStr(o, "severity_basis", "DetectionRuleMeta"),
    confidence_basis: reqStr(o, "confidence_basis", "DetectionRuleMeta"),
    stateful: reqBool(o, "stateful", "DetectionRuleMeta"),
    enabled: reqBool(o, "enabled", "DetectionRuleMeta"),
  };
}

export interface RuleHealthRow {
  rule_id: string;
  version: string;
  name: string;
  enabled: boolean;
  evaluated: number;
  detections: number;
  errors: number;
}

export function parseRuleHealthRow(v: unknown): RuleHealthRow {
  const o = asObject(v, "RuleHealthRow");
  return {
    rule_id: reqStr(o, "rule_id", "RuleHealthRow"),
    version: reqStr(o, "version", "RuleHealthRow"),
    name: reqStr(o, "name", "RuleHealthRow"),
    enabled: reqBool(o, "enabled", "RuleHealthRow"),
    evaluated: reqNum(o, "evaluated", "RuleHealthRow"),
    detections: reqNum(o, "detections", "RuleHealthRow"),
    errors: reqNum(o, "errors", "RuleHealthRow"),
  };
}

export interface IOCEntry {
  kind: string;
  value: string;
  source: string;
  set_id: string;
  set_version: string;
}

export function parseIOCEntry(v: unknown): IOCEntry {
  const o = asObject(v, "IOCEntry");
  return {
    kind: reqStr(o, "kind", "IOCEntry"),
    value: reqStr(o, "value", "IOCEntry"),
    source: reqStr(o, "source", "IOCEntry"),
    set_id: reqStr(o, "set_id", "IOCEntry"),
    set_version: reqStr(o, "set_version", "IOCEntry"),
  };
}

export interface IOCMatchRow {
  id: string;
  event_id: string;
  occurred_at: string;
  asset_id: string;
  kind: string;
  indicator: string;
  matched_field: string;
  set_id: string;
  set_version: string;
  list_source: string;
}

export function parseIOCMatchRow(v: unknown): IOCMatchRow {
  const o = asObject(v, "IOCMatchRow");
  return {
    id: reqStr(o, "id", "IOCMatchRow"),
    event_id: reqStr(o, "event_id", "IOCMatchRow"),
    occurred_at: reqTime(o, "occurred_at", "IOCMatchRow"),
    asset_id: reqStr(o, "asset_id", "IOCMatchRow"),
    kind: reqStr(o, "kind", "IOCMatchRow"),
    indicator: reqStr(o, "indicator", "IOCMatchRow"),
    matched_field: reqStr(o, "matched_field", "IOCMatchRow"),
    set_id: reqStr(o, "set_id", "IOCMatchRow"),
    set_version: reqStr(o, "set_version", "IOCMatchRow"),
    list_source: reqStr(o, "list_source", "IOCMatchRow"),
  };
}

export interface HuntRow {
  id: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  event_type: string;
  severity: string;
  attributes?: Record<string, string>;
  kind: string;
}

export function parseHuntRow(v: unknown): HuntRow {
  const o = asObject(v, "HuntRow");
  return {
    id: reqStr(o, "id", "HuntRow"),
    occurred_at: reqTime(o, "occurred_at", "HuntRow"),
    source: reqStr(o, "source", "HuntRow"),
    asset_id: reqStr(o, "asset_id", "HuntRow"),
    event_type: reqStr(o, "event_type", "HuntRow"),
    severity: reqEnum(o, "severity", "HuntRow", SEVERITIES),
    attributes: optStrMap(o, "attributes", "HuntRow"),
    kind: reqStr(o, "kind", "HuntRow"),
  };
}

export interface TimelineRow {
  id: string;
  kind: string;
  occurred_at: string;
  source: string;
  asset_id: string;
  principal: string;
  rule_id: string;
  correlation_id: string;
  evidence_id: string;
  incident_id: string;
  summary: string;
}

export function parseTimelineRow(v: unknown): TimelineRow {
  const o = asObject(v, "TimelineRow");
  const req = (k: string) => {
    const val = o[k];
    if (typeof val !== "string")
      throw new Error(`TimelineRow.${k} must be a string`);
    return val;
  };
  return {
    id: reqStr(o, "id", "TimelineRow"),
    kind: reqStr(o, "kind", "TimelineRow"),
    occurred_at: reqTime(o, "occurred_at", "TimelineRow"),
    source: req("source"),
    asset_id: req("asset_id"),
    principal: req("principal"),
    rule_id: req("rule_id"),
    correlation_id: req("correlation_id"),
    evidence_id: req("evidence_id"),
    incident_id: req("incident_id"),
    summary: reqStr(o, "summary", "TimelineRow"),
  };
}

export interface ForensicArtifactRow {
  type: string;
  event_id: string;
  asset_id: string;
  source: string;
  observed_at: string;
  metadata: Record<string, string>;
  digest: string;
}

export function parseForensicArtifactRow(v: unknown): ForensicArtifactRow {
  const o = asObject(v, "ForensicArtifactRow");
  const meta = o["metadata"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    throw new Error("ForensicArtifactRow.metadata must be an object");
  }
  for (const [k, val] of Object.entries(meta as Record<string, unknown>)) {
    if (typeof val !== "string")
      throw new Error(`ForensicArtifactRow.metadata.${k} must be a string`);
  }
  return {
    type: reqStr(o, "type", "ForensicArtifactRow"),
    event_id: reqStr(o, "event_id", "ForensicArtifactRow"),
    asset_id: reqStr(o, "asset_id", "ForensicArtifactRow"),
    source: reqStr(o, "source", "ForensicArtifactRow"),
    observed_at: reqTime(o, "observed_at", "ForensicArtifactRow"),
    metadata: meta as Record<string, string>,
    digest: reqStr(o, "digest", "ForensicArtifactRow"),
  };
}

export interface CampaignSummary {
  total: number;
  by_verdict: Record<string, number>;
  provider_errors: number;
  not_tested: number;
  rate_limited: number;
  unknown: number;
}

export interface ValidationCampaign {
  id: string;
  name: string;
  description: string;
  target: string;
  provider: string;
  source: string;
  status: string;
  created_at: string;
  started_at: string;
  completed_at: string;
  case_ids: string[];
  result_ids: string[];
  summary: CampaignSummary;
}

function reqStrArrOpt(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string[] {
  const v = o[key];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new Error(`${what}.${key} must be a string array`);
  }
  return v as string[];
}

function reqTimeOpt(
  o: Record<string, unknown>,
  key: string,
  what: string,
): string {
  const v = o[key];
  if (v === undefined || v === "") return "";
  if (typeof v !== "string" || Number.isNaN(Date.parse(v))) {
    throw new Error(`${what}.${key} is not a timestamp`);
  }
  return v;
}

export function parseCampaignSummary(
  v: unknown,
  what: string,
): CampaignSummary {
  const o = asObject(v, what);
  const by = o["by_verdict"];
  if (typeof by !== "object" || by === null || Array.isArray(by)) {
    throw new Error(`${what}.by_verdict must be an object`);
  }
  const byVerdict: Record<string, number> = {};
  for (const [k, val] of Object.entries(by as Record<string, unknown>)) {
    if (typeof val !== "number")
      throw new Error(`${what}.by_verdict.${k} must be a number`);
    byVerdict[k] = val;
  }
  return {
    total: reqNum(o, "total", what),
    by_verdict: byVerdict,
    provider_errors: reqNum(o, "provider_errors", what),
    not_tested: reqNum(o, "not_tested", what),
    rate_limited: reqNum(o, "rate_limited", what),
    unknown: reqNum(o, "unknown", what),
  };
}

export function parseValidationCampaign(v: unknown): ValidationCampaign {
  const o = asObject(v, "ValidationCampaign");
  const status = reqStr(o, "status", "ValidationCampaign");
  if (!["DRAFT", "RUNNING", "COMPLETED", "FAILED"].includes(status)) {
    throw new Error(
      `ValidationCampaign.status has unknown value ${JSON.stringify(status)}`,
    );
  }
  return {
    id: reqStr(o, "id", "ValidationCampaign"),
    name: reqStr(o, "name", "ValidationCampaign"),
    description: optStr(o, "description", "ValidationCampaign") ?? "",
    target: reqStr(o, "target", "ValidationCampaign"),
    provider: reqStr(o, "provider", "ValidationCampaign"),
    source: reqStr(o, "source", "ValidationCampaign"),
    status,
    created_at: reqTimeOpt(o, "created_at", "ValidationCampaign"),
    started_at: reqTimeOpt(o, "started_at", "ValidationCampaign"),
    completed_at: reqTimeOpt(o, "completed_at", "ValidationCampaign"),
    case_ids: reqStrArrOpt(o, "case_ids", "ValidationCampaign"),
    result_ids: reqStrArrOpt(o, "result_ids", "ValidationCampaign"),
    summary: parseCampaignSummary(o["summary"], "ValidationCampaign.summary"),
  };
}

export interface PurpleTeamEntry {
  case_id: string;
  request_id: string;
  result_id: string;
  verdict: string;
  status: string;
  telemetry_ids: string[];
  detection_ids: string[];
  alert_ids: string[];
  incident_ids: string[];
  evidence_ids: string[];
}

export interface PurpleTeamExercise {
  id: string;
  campaign_id: string;
  name: string;
  source: string;
  entries: PurpleTeamEntry[];
}

const EXERCISE_VERDICTS = [
  "VALIDATION_VERDICT_PREVENTED",
  "VALIDATION_VERDICT_DETECTED",
  "VALIDATION_VERDICT_PREVENTED_AND_DETECTED",
  "VALIDATION_VERDICT_ALLOWED_BUT_DETECTED",
  "VALIDATION_VERDICT_ALLOWED_AND_NOT_DETECTED",
  "VALIDATION_VERDICT_NOT_TESTED",
  "VALIDATION_VERDICT_RATE_LIMITED",
  "VALIDATION_VERDICT_UNKNOWN",
];

const EXERCISE_STATUSES = [
  "ATTEMPTED",
  "PREVENTED",
  "DETECTED",
  "PREVENTED_AND_DETECTED",
  "ALLOWED_BUT_DETECTED",
  "ALLOWED_AND_NOT_DETECTED",
  "NOT_TESTED",
  "RATE_LIMITED",
  "UNKNOWN_OUTCOME",
  "PROVIDER_FAILURE",
];

export function parsePurpleTeamExercise(v: unknown): PurpleTeamExercise {
  const o = asObject(v, "PurpleTeamExercise");
  const rawEntries = o["entries"];
  if (!Array.isArray(rawEntries))
    throw new Error("PurpleTeamExercise.entries must be an array");
  const entries: PurpleTeamEntry[] = rawEntries.map((item, i) => {
    const e = asObject(item, `PurpleTeamExercise.entries[${i}]`);
    return {
      case_id: reqStr(e, "case_id", "PurpleTeamExercise"),
      request_id: reqStr(e, "request_id", "PurpleTeamExercise"),
      result_id: reqStr(e, "result_id", "PurpleTeamExercise"),
      verdict: reqEnum(e, "verdict", "PurpleTeamExercise", EXERCISE_VERDICTS),
      status: reqEnum(e, "status", "PurpleTeamExercise", EXERCISE_STATUSES),
      telemetry_ids: reqStrArrOpt(e, "telemetry_ids", "PurpleTeamExercise"),
      detection_ids: reqStrArrOpt(e, "detection_ids", "PurpleTeamExercise"),
      alert_ids: reqStrArrOpt(e, "alert_ids", "PurpleTeamExercise"),
      incident_ids: reqStrArrOpt(e, "incident_ids", "PurpleTeamExercise"),
      evidence_ids: reqStrArrOpt(e, "evidence_ids", "PurpleTeamExercise"),
    };
  });
  return {
    id: reqStr(o, "id", "PurpleTeamExercise"),
    campaign_id: reqStr(o, "campaign_id", "PurpleTeamExercise"),
    name: reqStr(o, "name", "PurpleTeamExercise"),
    source: reqStr(o, "source", "PurpleTeamExercise"),
    entries,
  };
}

export interface GRCFramework {
  id: string;
  version: string;
  kind: string;
  title: string;
}

export function parseGRCFramework(v: unknown): GRCFramework {
  const o = asObject(v, "GRCFramework");
  return {
    id: reqStr(o, "id", "GRCFramework"),
    version: reqStr(o, "version", "GRCFramework"),
    kind: reqStr(o, "kind", "GRCFramework"),
    title: reqStr(o, "title", "GRCFramework"),
  };
}

export interface GRCControl {
  id: string;
  title: string;
  description: string;
  domain: string;
  framework: string;
  framework_version: string;
  implementation: string;
}

export function parseGRCControl(v: unknown): GRCControl {
  const o = asObject(v, "GRCControl");
  return {
    id: reqStr(o, "id", "GRCControl"),
    title: reqStr(o, "title", "GRCControl"),
    description: optStr(o, "description", "GRCControl") ?? "",
    domain: reqStr(o, "domain", "GRCControl"),
    framework: reqStr(o, "framework", "GRCControl"),
    framework_version: reqStr(o, "framework_version", "GRCControl"),
    implementation: reqStr(o, "implementation", "GRCControl"),
  };
}

export interface GRCAssessment {
  id: string;
  control_id: string;
  target: string;
  status: string;
  assessor: string;
  observed_at: string;
  evidence_ids: string[];
  basis: string;
  notes: string;
  risk: string;
  risk_basis: string;
}

export function parseGRCAssessment(v: unknown): GRCAssessment {
  const o = asObject(v, "GRCAssessment");
  const allowed = [
    "COMPLIANT",
    "PARTIALLY_COMPLIANT",
    "NON_COMPLIANT",
    "NOT_ASSESSED",
    "NOT_APPLICABLE",
    "UNKNOWN",
  ];
  const status = reqStr(o, "status", "GRCAssessment");
  if (!allowed.includes(status)) {
    throw new Error(
      `GRCAssessment.status has unknown value ${JSON.stringify(status)}`,
    );
  }
  return {
    id: reqStr(o, "id", "GRCAssessment"),
    control_id: reqStr(o, "control_id", "GRCAssessment"),
    target: reqStr(o, "target", "GRCAssessment"),
    status,
    assessor: reqStr(o, "assessor", "GRCAssessment"),
    observed_at: reqTime(o, "observed_at", "GRCAssessment"),
    evidence_ids: reqStrArrOpt(o, "evidence_ids", "GRCAssessment"),
    basis: optStr(o, "basis", "GRCAssessment") ?? "",
    notes: optStr(o, "notes", "GRCAssessment") ?? "",
    risk: optStr(o, "risk", "GRCAssessment") ?? "",
    risk_basis: optStr(o, "risk_basis", "GRCAssessment") ?? "",
  };
}

export interface ArchNode {
  asset_id: string;
  kind: string;
  name: string;
  boundary: string;
}

export function parseArchNode(v: unknown): ArchNode {
  const o = asObject(v, "ArchNode");
  return {
    asset_id: reqStr(o, "asset_id", "ArchNode"),
    kind: reqStr(o, "kind", "ArchNode"),
    name: reqStr(o, "name", "ArchNode"),
    boundary: optStr(o, "boundary", "ArchNode") ?? "",
  };
}

export interface ArchEdge {
  parent_id: string;
  child_id: string;
  kind: string;
}

export function parseArchEdge(v: unknown): ArchEdge {
  const o = asObject(v, "ArchEdge");
  return {
    parent_id: reqStr(o, "parent_id", "ArchEdge"),
    child_id: reqStr(o, "child_id", "ArchEdge"),
    kind: reqStr(o, "kind", "ArchEdge"),
  };
}

export interface ResilienceRow {
  id: string;
  target: string;
  assessor: string;
  observed_at: string;
  status: string;
  backup_observed: boolean;
  backup_at: string;
  restore_test_observed: boolean;
  restore_test_at: string;
  procedure_declared: boolean;
  dependencies: string[];
  evidence_ids: string[];
  retention_configured: boolean;
  encryption_observed: boolean;
}

export function parseResilienceRow(v: unknown): ResilienceRow {
  const o = asObject(v, "ResilienceRow");
  return {
    id: reqStr(o, "id", "ResilienceRow"),
    target: reqStr(o, "target", "ResilienceRow"),
    assessor: reqStr(o, "assessor", "ResilienceRow"),
    observed_at: reqTime(o, "observed_at", "ResilienceRow"),
    status: reqEnum(o, "status", "ResilienceRow", [
      "READY",
      "DEGRADED",
      "NOT_READY",
      "NOT_ASSESSED",
      "UNKNOWN",
    ]),
    backup_observed: reqBool(o, "backup_observed", "ResilienceRow"),
    backup_at: optTimeOrEmpty(o, "backup_at", "ResilienceRow"),
    restore_test_observed: reqBool(o, "restore_test_observed", "ResilienceRow"),
    restore_test_at: optTimeOrEmpty(o, "restore_test_at", "ResilienceRow"),
    procedure_declared: reqBool(o, "procedure_declared", "ResilienceRow"),
    dependencies: reqStrArrOpt(o, "dependencies", "ResilienceRow"),
    evidence_ids: reqStrArrOpt(o, "evidence_ids", "ResilienceRow"),
    retention_configured: reqBool(o, "retention_configured", "ResilienceRow"),
    encryption_observed: reqBool(o, "encryption_observed", "ResilienceRow"),
  };
}

export interface SupplyComponent {
  id: string;
  type: string;
  ecosystem: string;
  namespace: string;
  name: string;
  version: string;
  requested_version: string;
  resolved_version: string;
  digest: string;
  source_revision: string;
  license: string;
  license_source: string;
  provenance: string;
  source: string;
  observed_at: string;
  status: string;
  status_basis: string;
}

const SUPPLY_TYPES = [
  "PACKAGE",
  "LIBRARY",
  "FRAMEWORK",
  "CONTAINER_IMAGE",
  "BINARY",
  "SOURCE_REPOSITORY",
  "BUILD_ARTIFACT",
  "INFRASTRUCTURE_MODULE",
  "UNKNOWN",
];

const SUPPLY_STATUSES = [
  "OBSERVED",
  "VERIFIED",
  "OUTDATED",
  "UNSUPPORTED",
  "POLICY_VIOLATION",
  "NOT_ASSESSED",
  "UNKNOWN",
];

const SUPPLY_PROVENANCE = [
  "MANIFEST",
  "LOCKFILE",
  "BUILD_METADATA",
  "CONTAINER_METADATA",
  "SOURCE_REPOSITORY",
  "DEPLOYMENT_OBSERVATION",
  "OPERATOR_DECLARATION",
  "SBOM_IMPORT",
];

export function parseSupplyComponent(v: unknown): SupplyComponent {
  const o = asObject(v, "SupplyComponent");
  return {
    id: reqStr(o, "id", "SupplyComponent"),
    type: reqEnum(o, "type", "SupplyComponent", SUPPLY_TYPES),
    ecosystem: reqStr(o, "ecosystem", "SupplyComponent"),
    namespace: optStr(o, "namespace", "SupplyComponent") ?? "",
    name: reqStr(o, "name", "SupplyComponent"),
    version: optStr(o, "version", "SupplyComponent") ?? "",
    requested_version: optStr(o, "requested_version", "SupplyComponent") ?? "",
    resolved_version: optStr(o, "resolved_version", "SupplyComponent") ?? "",
    digest: optStr(o, "digest", "SupplyComponent") ?? "",
    source_revision: optStr(o, "source_revision", "SupplyComponent") ?? "",
    license: optStr(o, "license", "SupplyComponent") ?? "",
    license_source: optStr(o, "license_source", "SupplyComponent") ?? "",
    provenance: reqEnum(o, "provenance", "SupplyComponent", SUPPLY_PROVENANCE),
    source: reqStr(o, "source", "SupplyComponent"),
    observed_at: reqTime(o, "observed_at", "SupplyComponent"),
    status: reqEnum(o, "status", "SupplyComponent", SUPPLY_STATUSES),
    status_basis: optStr(o, "status_basis", "SupplyComponent") ?? "",
  };
}

export interface SupplyDependency {
  parent_id: string;
  parent_kind: string;
  child_id: string;
  kind: string;
  source: string;
  observed_at: string;
}

export function parseSupplyDependency(v: unknown): SupplyDependency {
  const o = asObject(v, "SupplyDependency");
  return {
    parent_id: reqStr(o, "parent_id", "SupplyDependency"),
    parent_kind: optStr(o, "parent_kind", "SupplyDependency") ?? "",
    child_id: reqStr(o, "child_id", "SupplyDependency"),
    kind: reqEnum(o, "kind", "SupplyDependency", [
      "DEPENDS_ON",
      "CONTAINS",
      "BUILT_FROM",
      "DERIVED_FROM",
    ]),
    source: reqStr(o, "source", "SupplyDependency"),
    observed_at: reqTime(o, "observed_at", "SupplyDependency"),
  };
}

export interface SupplySBOM {
  id: string;
  format: string;
  format_version: string;
  component_ids: string[];
  generated_at: string;
  source: string;
  digest: string;
}

export function parseSupplySBOM(v: unknown): SupplySBOM {
  const o = asObject(v, "SupplySBOM");
  return {
    id: reqStr(o, "id", "SupplySBOM"),
    format: reqEnum(o, "format", "SupplySBOM", [
      "SPDX",
      "CycloneDX",
      "UNKNOWN",
    ]),
    format_version: optStr(o, "format_version", "SupplySBOM") ?? "",
    component_ids: reqStrArrOpt(o, "component_ids", "SupplySBOM"),
    generated_at: reqTime(o, "generated_at", "SupplySBOM"),
    source: reqStr(o, "source", "SupplySBOM"),
    digest: optStr(o, "digest", "SupplySBOM") ?? "",
  };
}

export interface SupplyPolicy {
  id: string;
  name: string;
  source: string;
  allowed_ecosystems: string[];
  allowed_licenses: string[];
  allowed_provenance: string[];
  require_digest: boolean;
  min_versions: Record<string, string>;
  prohibited: string[];
  require_sbom: boolean;
  approved_repos: string[];
}

export function parseSupplyPolicy(v: unknown): SupplyPolicy {
  const o = asObject(v, "SupplyPolicy");
  return {
    id: reqStr(o, "id", "SupplyPolicy"),
    name: reqStr(o, "name", "SupplyPolicy"),
    source: reqStr(o, "source", "SupplyPolicy"),
    allowed_ecosystems: reqStrArrOpt(o, "allowed_ecosystems", "SupplyPolicy"),
    allowed_licenses: reqStrArrOpt(o, "allowed_licenses", "SupplyPolicy"),
    allowed_provenance: reqStrArrOpt(o, "allowed_provenance", "SupplyPolicy"),
    require_digest: reqBool(o, "require_digest", "SupplyPolicy"),
    min_versions: optStrMap(o, "min_versions", "SupplyPolicy") ?? {},
    prohibited: reqStrArrOpt(o, "prohibited", "SupplyPolicy"),
    require_sbom: reqBool(o, "require_sbom", "SupplyPolicy"),
    approved_repos: reqStrArrOpt(o, "approved_repos", "SupplyPolicy"),
  };
}

export interface Vendor {
  id: string;
  name: string;
  service: string;
  category: string;
  environment: string;
  status: string;
  source: string;
  observed_at: string;
}

export function parseVendor(v: unknown): Vendor {
  const o = asObject(v, "Vendor");
  return {
    id: reqStr(o, "id", "Vendor"),
    name: reqStr(o, "name", "Vendor"),
    service: reqStr(o, "service", "Vendor"),
    category: optStr(o, "category", "Vendor") ?? "",
    environment: optStr(o, "environment", "Vendor") ?? "",
    status: reqEnum(o, "status", "Vendor", [
      "ACTIVE",
      "INACTIVE",
      "UNKNOWN",
      "NOT_ASSESSED",
    ]),
    source: reqStr(o, "source", "Vendor"),
    observed_at: reqTime(o, "observed_at", "Vendor"),
  };
}

export interface VendorAssessment {
  id: string;
  vendor_id: string;
  status: string;
  assessor: string;
  observed_at: string;
  evidence_ids: string[];
  note: string;
}

export function parseVendorAssessment(v: unknown): VendorAssessment {
  const o = asObject(v, "VendorAssessment");
  return {
    id: reqStr(o, "id", "VendorAssessment"),
    vendor_id: reqStr(o, "vendor_id", "VendorAssessment"),
    status: reqEnum(o, "status", "VendorAssessment", [
      "REVIEWED",
      "REQUIREMENT_DECLARED",
      "NOT_ASSESSED",
      "UNKNOWN",
    ]),
    assessor: reqStr(o, "assessor", "VendorAssessment"),
    observed_at: reqTime(o, "observed_at", "VendorAssessment"),
    evidence_ids: reqStrArrOpt(o, "evidence_ids", "VendorAssessment"),
    note: optStr(o, "note", "VendorAssessment") ?? "",
  };
}

export interface SupplyLink {
  id: string;
  control_id: string;
  subject_kind: string;
  subject_id: string;
  basis: string;
}

export function parseSupplyLink(v: unknown): SupplyLink {
  const o = asObject(v, "SupplyLink");
  return {
    id: reqStr(o, "id", "SupplyLink"),
    control_id: reqStr(o, "control_id", "SupplyLink"),
    subject_kind: reqEnum(o, "subject_kind", "SupplyLink", [
      "component",
      "vendor",
      "sbom",
    ]),
    subject_id: reqStr(o, "subject_id", "SupplyLink"),
    basis: reqStr(o, "basis", "SupplyLink"),
  };
}

export interface ContinuousCheck {
  rule_id: string;
  version: string;
  subject_id: string;
  outcome: string;
  basis: string;
}

export function parseContinuousCheck(v: unknown): ContinuousCheck {
  const o = asObject(v, "ContinuousCheck");
  return {
    rule_id: reqEnum(o, "rule_id", "ContinuousCheck", [
      "supply-missing-sbom",
      "supply-unverified-provenance",
      "supply-policy-violation",
      "supply-stale-vendor-assessment",
      "supply-posture-regression",
    ]),
    version: reqStr(o, "version", "ContinuousCheck"),
    subject_id: reqStr(o, "subject_id", "ContinuousCheck"),
    outcome: reqEnum(o, "outcome", "ContinuousCheck", [
      "PASS",
      "FAIL",
      "NOT_APPLICABLE",
      "DISABLED",
    ]),
    basis: reqStr(o, "basis", "ContinuousCheck"),
  };
}

export interface PostureHistoryEntry {
  id: string;
  occurred_at: string;
  kind: string;
  subject_id: string;
  summary: string;
}

export function parsePostureHistoryEntry(v: unknown): PostureHistoryEntry {
  const o = asObject(v, "PostureHistoryEntry");
  return {
    id: reqStr(o, "id", "PostureHistoryEntry"),
    occurred_at: reqTime(o, "occurred_at", "PostureHistoryEntry"),
    kind: reqEnum(o, "kind", "PostureHistoryEntry", [
      "component",
      "vendor-assessment",
      "sbom",
    ]),
    subject_id: reqStr(o, "subject_id", "PostureHistoryEntry"),
    summary: reqStr(o, "summary", "PostureHistoryEntry"),
  };
}
