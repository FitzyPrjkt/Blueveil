// Contract-conformance tests: real Step-2/8 fixtures in, typed objects
// out. The UI never duplicates contract data — it parses the same files
// the Go and Rust validators use.
import { describe, expect, it } from "vitest";
import alertJson from "../../../contracts/fixtures/alert/valid.json";
import detectionJson from "../../../contracts/fixtures/detection/valid.json";
import evidenceJson from "../../../contracts/fixtures/evidence/valid.json";
import incidentJson from "../../../contracts/fixtures/incident/valid.json";
import telemetryJson from "../../../contracts/fixtures/telemetry/valid.json";
import approvalJson from "../../../contracts/fixtures/response/valid_approval.json";
import executionJson from "../../../contracts/fixtures/response/valid_execution.json";
import recommendationJson from "../../../contracts/fixtures/response/valid_recommendation.json";
import verificationJson from "../../../contracts/fixtures/response/valid_verification.json";
import notTestedJson from "../../../contracts/fixtures/validation/valid_result_not_tested.json";
import resultJson from "../../../contracts/fixtures/validation/valid_result.json";
import {
  VERDICTS,
  parseAlert,
  parseApproval,
  parseDetection,
  parseEvidence,
  parseExecution,
  parseIncident,
  parsePurpleTeamExercise,
  parseRecommendation,
  parseResilienceRow,
  parseSupplyPolicy,
  parseTelemetryEvent,
  parseValidationResult,
  parseVerification,
} from "./contracts";

describe("contract fixtures parse", () => {
  it("parses every entity fixture", () => {
    expect(parseTelemetryEvent(telemetryJson).id).toBe("evt-test-001");
    expect(parseDetection(detectionJson).rule_id).toBeTruthy();
    expect(parseAlert(alertJson).detection_ids.length).toBeGreaterThan(0);
    expect(parseIncident(incidentJson).alert_ids.length).toBeGreaterThan(0);
    expect(parseEvidence(evidenceJson).incident_id).toBeTruthy();
    expect(parseRecommendation(recommendationJson).incident_id).toBeTruthy();
    expect(parseApproval(approvalJson).recommendation_id).toBe(
      parseRecommendation(recommendationJson).id,
    );
    expect(parseExecution(executionJson).recommendation_id).toBe(
      parseRecommendation(recommendationJson).id,
    );
    expect(parseVerification(verificationJson).execution_id).toBe(
      parseExecution(executionJson).id,
    );
    expect(parseValidationResult(resultJson).verdict).not.toBe(
      "VALIDATION_VERDICT_NOT_TESTED",
    );
    expect(parseValidationResult(notTestedJson).verdict).toBe(
      "VALIDATION_VERDICT_NOT_TESTED",
    );
  });

  it("rejects invalid payloads instead of rendering them", () => {
    expect(() => parseAlert({})).toThrow();
    expect(() =>
      parseAlert({ ...alertJson, severity: "SEVERITY_BOGUS" }),
    ).toThrow();
    expect(() => parseIncident({ ...incidentJson, alert_ids: [] })).toThrow();
    expect(() => parseEvidence({ ...evidenceJson, content: "" })).toThrow();
    expect(() =>
      parseValidationResult({ ...resultJson, verdict: "SECURE" }),
    ).toThrow();
  });

  it("bounds confidence, severity, status, digests, and timestamps", () => {
    expect(() =>
      parseDetection({ ...detectionJson, confidence: 1.5 }),
    ).toThrow();
    expect(() =>
      parseDetection({ ...detectionJson, confidence: Number.NaN }),
    ).toThrow();
    expect(() =>
      parseDetection({ ...detectionJson, severity: "SEVERITY_BOGUS" }),
    ).toThrow();
    expect(() => parseEvidence({ ...evidenceJson, sha256: "ZZZ" })).toThrow();
    expect(() =>
      parseEvidence({ ...evidenceJson, sha256: "A".repeat(64) }),
    ).toThrow();
    expect(() =>
      parseResilienceRow({
        id: "grsl-x",
        target: "t",
        assessor: "s",
        observed_at: "2026-09-12T10:00:00Z",
        status: "READY_NOW",
        backup_observed: false,
        backup_at: "",
        restore_test_observed: false,
        restore_test_at: "",
        procedure_declared: false,
        dependencies: [],
        evidence_ids: [],
        retention_configured: false,
        encryption_observed: false,
      }),
    ).toThrow();
    expect(() =>
      parsePurpleTeamExercise({
        id: "pex-x",
        campaign_id: "c",
        name: "n",
        source: "s",
        entries: [
          {
            case_id: "case-1",
            request_id: "vreq-1",
            result_id: "vres-1",
            verdict: "PREVENTED",
            status: "PREVENTED",
            telemetry_ids: ["evt-1"],
            detection_ids: [],
            alert_ids: [],
            incident_ids: [],
            evidence_ids: [],
          },
        ],
      }),
    ).toThrow();
  });

  it("has no SECURE or PASS verdict anywhere", () => {
    for (const v of VERDICTS) {
      expect(v).toMatch(/^VALIDATION_VERDICT_/);
      expect(v).not.toMatch(/SECURE|PASS|SUCCESS/);
    }
    expect(VERDICTS).toHaveLength(8);
  });
});

describe("optional null tolerance", () => {
  it("treats explicit null min_versions as absent (backend emits null for empty maps)", () => {
    const policy = {
      id: "pol-lab-allowlist",
      name: "lab allowlist",
      source: "seed-lab-supply-chain",
      allowed_ecosystems: ["npm"],
      allowed_licenses: ["MIT"],
      allowed_provenance: ["LOCKFILE"],
      require_digest: false,
      min_versions: null,
      prohibited: [],
      require_sbom: false,
      approved_repos: [],
    };
    expect(parseSupplyPolicy(policy).min_versions).toEqual({});
  });
});
