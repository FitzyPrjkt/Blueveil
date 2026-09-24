import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import assetFullJson from "../../../../contracts/fixtures/asset/valid_full.json";
import detectionJson from "../../../../contracts/fixtures/detection/valid.json";
import telemetryJson from "../../../../contracts/fixtures/telemetry/valid.json";
import incidentJson from "../../../../contracts/fixtures/incident/valid.json";
import evidenceJson from "../../../../contracts/fixtures/evidence/valid.json";
import approvalJson from "../../../../contracts/fixtures/response/valid_approval.json";
import executionJson from "../../../../contracts/fixtures/response/valid_execution.json";
import recommendationJson from "../../../../contracts/fixtures/response/valid_recommendation.json";
import verificationJson from "../../../../contracts/fixtures/response/valid_verification.json";
import { Findings } from "./Findings";
import { Assets } from "./Assets";
import { SupplyChain } from "./SupplyChain";
import { Network } from "./Network";
import { Application } from "./Application";
import { Infrastructure } from "./Infrastructure";
import { Identity } from "./Identity";
import { Monitoring } from "./Monitoring";
import { Investigations } from "./Investigations";
import { Validation } from "./Validation";
import { Governance } from "./Governance";
import { Incidents } from "./Incidents";
import { EvidenceView } from "./Evidence";
import { Responses } from "./Responses";
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
    // Empty inventory takes the honest empty-state branch of the strip
    // statement (no outdated/unsupported components), not the risk branch.
    await waitFor(() =>
      expect(
        screen.getByText(/no outdated or unsupported/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText("In violation")).toBeInTheDocument();
  });
});

const NETWORK_OBS = {
  data: [
    {
      id: "evt-seed-net-001",
      occurred_at: "2026-09-12T09:04:00Z",
      source: "seed-lab-net",
      asset_id: "seed-net-01",
      severity: "SEVERITY_INFO",
      src_ip: "127.0.0.1",
      dst_ip: "127.0.0.1",
      src_port: 43110,
      dst_port: 8080,
      protocol: "TCP",
      direction: "outbound",
      verdict: "allowed",
      detected: false,
    },
    {
      id: "evt-seed-net-002",
      occurred_at: "2026-09-12T09:05:00Z",
      source: "seed-lab-net",
      asset_id: "seed-net-01",
      severity: "SEVERITY_MEDIUM",
      src_ip: "10.0.0.9",
      dst_ip: "203.0.113.7",
      dst_port: 4444,
      protocol: "TCP",
      verdict: "allowed",
      detected: true,
    },
  ],
};

describe("Network strip", () => {
  it("states telemetry-first summary with observations/denied/detected", async () => {
    mockApi({
      "/api/v1/network/observations": NETWORK_OBS,
      "/api/v1/network/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/detections": { data: [] },
    });
    render(<Network />);
    await waitFor(() =>
      expect(
        screen.getByText(/denied and detected rows deserve a look/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Observations");
    expect(strip.textContent).toContain("Denied");
    expect(strip.textContent).toContain("Detected");
  });

  it("does not render when there are no observations", async () => {
    mockApi({ "/api/v1/network/observations": { data: [] } });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("No network observations")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/denied and detected rows deserve a look/i),
    ).not.toBeInTheDocument();
  });
});

const APP_OBS = {
  data: [
    {
      id: "evt-http-001",
      occurred_at: "2026-09-12T09:12:00Z",
      source: "seed-lab-http",
      asset_id: "seed-http-01",
      severity: "SEVERITY_INFO",
      method: "GET",
      host: "seed-lab.example",
      path: "/api/users",
      status_code: 200,
      route: "/api/users",
      detected: false,
    },
    {
      id: "evt-http-002",
      occurred_at: "2026-09-12T09:13:00Z",
      source: "seed-lab-http",
      asset_id: "seed-http-01",
      severity: "SEVERITY_INFO",
      method: "GET",
      host: "seed-lab.example",
      path: "/api/users",
      status_code: 500,
      route: "/api/users",
      detected: true,
    },
  ],
};

describe("Application strip", () => {
  it("states server-errors-first summary with observations/errors/missing-status", async () => {
    mockApi({
      "/api/v1/application/observations": APP_OBS,
      "/api/v1/application/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
    });
    render(<Application />);
    await waitFor(() =>
      expect(
        screen.getByText(/server errors deserve a look first/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Observations");
    expect(strip.textContent).toContain("Server errors");
    expect(strip.textContent).toContain("Without status");
  });

  it("does not render when there are no observations", async () => {
    mockApi({ "/api/v1/application/observations": { data: [] } });
    render(<Application />);
    await waitFor(() =>
      expect(
        screen.getByText("No application observations"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/server errors deserve a look first/i),
    ).not.toBeInTheDocument();
  });
});

const INFRA_ENDPOINT = {
  data: [
    {
      id: "evt-infra-endpoint-001",
      occurred_at: "2026-09-12T09:50:00Z",
      source: "seed-lab-infra",
      asset_id: "seed-infra-01",
      severity: "SEVERITY_INFO",
      host: "host-01",
      process: "agent",
      action: "exec",
      result: "allowed",
      detected: false,
    },
  ],
};

const INFRA_SERVER = {
  data: [
    {
      id: "evt-infra-server-001",
      occurred_at: "2026-09-12T09:51:00Z",
      source: "seed-lab-infra",
      asset_id: "seed-infra-01",
      severity: "SEVERITY_MEDIUM",
      hostname: "srv-01",
      service: "sshd",
      action: "login",
      result: "success",
      detected: true,
    },
  ],
};

const INFRA_CONTAINER = {
  data: [
    {
      id: "evt-infra-container-001",
      occurred_at: "2026-09-12T09:52:00Z",
      source: "seed-lab-infra",
      asset_id: "seed-infra-01",
      severity: "SEVERITY_INFO",
      container_id: "abcdef1234567890",
      image: "app:1.0",
      cluster: "prod",
      namespace: "default",
      privileged: true,
      host_network: false,
      host_pid: false,
      result: "running",
      detected: false,
    },
  ],
};

const INFRA_CLOUD = {
  data: [
    {
      id: "evt-infra-cloud-001",
      occurred_at: "2026-09-12T09:53:00Z",
      source: "seed-lab-infra",
      asset_id: "seed-infra-01",
      severity: "SEVERITY_INFO",
      provider: "aws",
      account: "123456789012",
      region: "us-east-1",
      principal: "role/app",
      action: "s3:GetObject",
      result: "allowed",
      detected: false,
    },
  ],
};

function mockInfra(
  endpoint = INFRA_ENDPOINT,
  server = INFRA_SERVER,
  container = INFRA_CONTAINER,
  cloud = INFRA_CLOUD,
) {
  mockApi({
    "/api/v1/endpoint/observations": endpoint,
    "/api/v1/server/observations": server,
    "/api/v1/container/observations": container,
    "/api/v1/cloud/observations": cloud,
  });
}

describe("Infrastructure strip", () => {
  it("states privileged/detected-first summary with total/detected/privileged", async () => {
    mockInfra();
    render(<Infrastructure />);
    await waitFor(() =>
      expect(
        screen.getByText(
          /privileged containers and detected actions deserve a look first/i,
        ),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Total");
    expect(strip.textContent).toContain("Detected");
    expect(strip.textContent).toContain("Privileged containers");
  });

  it("does not render when the current tab is empty", async () => {
    mockInfra({ data: [] }, { data: [] }, { data: [] }, { data: [] });
    render(<Infrastructure />);
    await waitFor(() =>
      expect(screen.getByText("No endpoint observations")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(
        /privileged containers and detected actions deserve a look first/i,
      ),
    ).not.toBeInTheDocument();
  });
});

const IDENTITY_OBS = {
  data: [
    {
      id: "evt-seed-ident-001",
      occurred_at: "2026-09-12T09:35:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_INFO",
      principal: "alice",
      action: "login",
      result: "success",
      detected: false,
    },
    {
      id: "evt-seed-ident-002",
      occurred_at: "2026-09-12T09:36:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_INFO",
      principal: "alice",
      action: "role_change",
      target: "admin-role",
      detected: true,
    },
  ],
};

const AUTH_OBS = {
  data: [
    {
      id: "evt-seed-auth-001",
      occurred_at: "2026-09-12T09:38:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_INFO",
      principal: "alice",
      outcome: "success",
      method: "sso",
      detected: false,
    },
    {
      id: "evt-seed-auth-002",
      occurred_at: "2026-09-12T09:39:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_INFO",
      principal: "carol",
      outcome: "failure",
      method: "password",
      detected: true,
    },
  ],
};

const DATA_OBS = {
  data: [
    {
      id: "evt-seed-data-001",
      occurred_at: "2026-09-12T09:46:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_INFO",
      resource: "blog",
      action: "read",
      classification: "public",
      detected: false,
    },
    {
      id: "evt-seed-data-002",
      occurred_at: "2026-09-12T09:47:00Z",
      source: "seed-lab-identity",
      asset_id: "seed-ident-01",
      severity: "SEVERITY_HIGH",
      resource: "customers",
      action: "export",
      classification: "restricted",
      detected: true,
    },
  ],
};

function mockIdentityAll() {
  mockApi({
    "/api/v1/identity/observations": IDENTITY_OBS,
    "/api/v1/authentication/observations": AUTH_OBS,
    "/api/v1/data/observations": DATA_OBS,
    "/api/v1/identity/relationships": { data: [] },
    "/api/v1/assets": { data: [] },
  });
}

describe("Identity strip", () => {
  it("states failed-logins-first summary with auth/failed/detected", async () => {
    mockIdentityAll();
    render(<Identity />);
    await waitFor(() =>
      expect(
        screen.getByText(/failed logins deserve a look first/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Auth observations");
    expect(strip.textContent).toContain("Failed");
    expect(strip.textContent).toContain("Detected");
  });

  it("does not render when the current tab is empty", async () => {
    mockApi({
      "/api/v1/identity/observations": { data: [] },
      "/api/v1/authentication/observations": { data: [] },
      "/api/v1/data/observations": { data: [] },
      "/api/v1/identity/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
    });
    render(<Identity />);
    await waitFor(() =>
      expect(screen.getByText("No identity observations")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/failed logins deserve a look first/i),
    ).not.toBeInTheDocument();
  });
});

const MON_EVENTS = {
  data: [
    {
      id: "evt-seed-mon-auth-001",
      occurred_at: "2026-09-12T09:50:00Z",
      source: "seed-lab-monitoring",
      asset_id: "seed-mon-01",
      event_type: "auth.activity",
      severity: "SEVERITY_INFO",
      attributes: { "auth.principal": "erin", "auth.outcome": "failure" },
    },
    {
      id: "evt-seed-mon-net-001",
      occurred_at: "2026-09-12T09:53:00Z",
      source: "seed-lab-monitoring",
      asset_id: "seed-mon-01",
      event_type: "net.connection",
      severity: "SEVERITY_INFO",
      attributes: { "net.dst_ip": "203.0.113.7" },
    },
  ],
};

const MON_CORRS = {
  data: [
    {
      id: "corr-aaa",
      type: "auth-to-identity-change",
      event_ids: ["evt-seed-mon-auth-001", "evt-seed-mon-auth-002"],
      principal: "erin",
      asset_id: "",
      observed_at: "2026-09-12T09:52:00Z",
      status: "CORRELATED",
    },
  ],
};

const MON_RULES = {
  data: [
    {
      id: "waf-block-high-severity",
      version: "1",
      title: "High-severity blocked request",
      description: "d",
      domain: "waf",
      event_types: ["waf.request_blocked"],
      severity_basis: "source",
      confidence_basis: "boolean-condition-unmeasured",
      stateful: false,
      enabled: true,
    },
  ],
};

const MON_HEALTH = {
  status: "ok",
  data: [
    {
      rule_id: "waf-block-high-severity",
      version: "1",
      name: "High-severity blocked request",
      enabled: true,
      evaluated: 4,
      detections: 1,
      errors: 0,
    },
  ],
};

const MON_IOCS = {
  status: "ok",
  set_id: "lab-ioc-set",
  set_version: "v1",
  data: [
    {
      kind: "ip",
      value: "203.0.113.7",
      source: "lab-ioc-v1",
      set_id: "lab-ioc-set",
      set_version: "v1",
    },
  ],
};

const MON_MATCHES = {
  status: "ok",
  data: [
    {
      id: "iocm-bbb",
      event_id: "evt-seed-mon-net-001",
      occurred_at: "2026-09-12T09:53:00Z",
      asset_id: "seed-mon-01",
      kind: "ip",
      indicator: "203.0.113.7",
      matched_field: "attributes.net.dst_ip",
      set_id: "lab-ioc-set",
      set_version: "v1",
      list_source: "lab-ioc-v1",
    },
  ],
};

function mockMonitoringAll(events: unknown = MON_EVENTS) {
  mockApi({
    "/api/v1/monitoring/events": events,
    "/api/v1/monitoring/correlations": MON_CORRS,
    "/api/v1/detection-rules": MON_RULES,
    "/api/v1/detection-rules/health": MON_HEALTH,
    "/api/v1/threat-intelligence/iocs": MON_IOCS,
    "/api/v1/threat-intelligence/matches": MON_MATCHES,
  });
}

describe("Monitoring strip", () => {
  it("states threat-intel-first summary with events/rules/ti-matches", async () => {
    mockMonitoringAll();
    render(<Monitoring />);
    await waitFor(() =>
      expect(
        screen.getByText(/threat-intel matches deserve a look first/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Events");
    expect(strip.textContent).toContain("Rules");
    expect(strip.textContent).toContain("TI matches");
  });

  it("does not render when there are no monitoring events", async () => {
    mockMonitoringAll({ data: [] });
    render(<Monitoring />);
    await waitFor(() =>
      expect(screen.getByText("No monitoring events")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/threat-intel matches deserve a look first/i),
    ).not.toBeInTheDocument();
  });
});

const INV_HUNT = {
  data: [
    {
      id: "evt-seed-inv-auth-001",
      occurred_at: "2026-09-12T09:00:00Z",
      source: "seed-lab-investigation",
      asset_id: "seed-inv-01",
      event_type: "auth.activity",
      severity: "SEVERITY_INFO",
      attributes: { "auth.principal": "frank", "auth.outcome": "failure" },
      kind: "HUNT_RESULT",
    },
    {
      id: "evt-seed-inv-net-001",
      occurred_at: "2026-09-12T09:04:00Z",
      source: "seed-lab-investigation",
      asset_id: "seed-inv-01",
      event_type: "net.connection",
      severity: "SEVERITY_INFO",
      attributes: {},
      kind: "HUNT_RESULT",
    },
  ],
};

const INV_TIMELINE = {
  data: [
    {
      id: "evt-seed-inv-auth-001",
      kind: "telemetry",
      occurred_at: "2026-09-12T09:00:00Z",
      source: "seed-lab-investigation",
      asset_id: "seed-inv-01",
      principal: "frank",
      rule_id: "",
      correlation_id: "",
      evidence_id: "",
      incident_id: "",
      summary: "auth.activity",
    },
    {
      id: "det-x",
      kind: "detection",
      occurred_at: "2026-09-12T09:05:00Z",
      source: "",
      asset_id: "",
      principal: "",
      rule_id: "repeated-cross-domain-principal-activity",
      correlation_id: "",
      evidence_id: "",
      incident_id: "",
      summary: "Cross-domain principal activity observed",
    },
  ],
};

const INV_ARTIFACTS = {
  data: [
    {
      type: "PROCESS",
      event_id: "evt-seed-inv-endpoint-001",
      asset_id: "seed-inv-01",
      source: "seed-lab-investigation",
      observed_at: "2026-09-12T09:06:00Z",
      metadata: { "endpoint.process": "agent" },
      digest: "abc123",
    },
    {
      type: "NETWORK",
      event_id: "evt-seed-inv-net-001",
      asset_id: "seed-inv-01",
      source: "seed-lab-investigation",
      observed_at: "2026-09-12T09:04:00Z",
      metadata: {},
      digest: "def456",
    },
  ],
};

function mockInvestigationsAll(hunt: unknown = INV_HUNT) {
  mockApi({
    "/api/v1/hunting/events": hunt,
    "/api/v1/hunting/timeline": INV_TIMELINE,
    "/api/v1/forensics/artifacts": INV_ARTIFACTS,
    "/api/v1/forensics/endpoint": { data: [INV_ARTIFACTS.data[0]] },
    "/api/v1/forensics/network": { data: [INV_ARTIFACTS.data[1]] },
    "/api/v1/forensics/cloud": { data: [] },
    "/api/v1/forensics/identity": { data: [] },
  });
}

describe("Investigations strip", () => {
  it("states evidence-waiting summary with hunting/timeline/artifacts", async () => {
    mockInvestigationsAll();
    render(<Investigations />);
    await waitFor(() =>
      expect(
        screen.getByText(/open hypotheses wait on evidence/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Hunting events");
    expect(strip.textContent).toContain("Timeline entries");
    expect(strip.textContent).toContain("Forensic artifacts");
  });

  it("does not render when there are no hunting results", async () => {
    mockInvestigationsAll({ data: [] });
    render(<Investigations />);
    await waitFor(() =>
      expect(screen.getByText("No hunting results")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/open hypotheses wait on evidence/i),
    ).not.toBeInTheDocument();
  });
});

const VAL_RESULTS = {
  data: [
    {
      id: "vres-a",
      request_id: "vreq-a",
      control_id: "ctl-lab",
      provider: "blueveil/provider/native-test",
      provider_version: "seed",
      contract_version: "blueveil.contracts.v1",
      verdict: "VALIDATION_VERDICT_DETECTED",
      validated_at: "2026-09-12T10:00:00Z",
      evidence_ids: [],
      note: "",
    },
  ],
};

const VAL_CAMPAIGNS = {
  data: [
    {
      id: "vcamp-abc",
      name: "lab campaign",
      description: "d",
      target: "seed-lab",
      provider: "blueveil/provider/native-test",
      source: "seed-lab-validation",
      status: "COMPLETED",
      created_at: "2026-09-12T10:00:00Z",
      started_at: "2026-09-12T10:00:00Z",
      completed_at: "2026-09-12T10:05:00Z",
      case_ids: ["vcase-a"],
      result_ids: ["vres-a"],
      summary: {
        total: 1,
        by_verdict: { VALIDATION_VERDICT_DETECTED: 1 },
        provider_errors: 0,
        not_tested: 0,
        rate_limited: 0,
        unknown: 0,
      },
    },
  ],
};

const VAL_EXERCISES = {
  data: [
    {
      id: "pex-abc",
      campaign_id: "vcamp-abc",
      name: "lab exercise",
      source: "seed-lab-validation",
      entries: [
        {
          case_id: "vcase-a",
          request_id: "vreq-a",
          result_id: "vres-a",
          verdict: "VALIDATION_VERDICT_DETECTED",
          status: "DETECTED",
          telemetry_ids: ["evt-1"],
          detection_ids: ["det-1"],
          alert_ids: ["alert-1"],
          incident_ids: ["inc-1"],
          evidence_ids: ["ev-1"],
        },
      ],
    },
  ],
};

function mockValidationAll(results: unknown = VAL_RESULTS) {
  mockApi({
    "/api/v1/validation-results": results,
    "/api/v1/validation/campaigns": VAL_CAMPAIGNS,
    "/api/v1/validation/history": VAL_RESULTS,
    "/api/v1/purple-team/exercises": VAL_EXERCISES,
  });
}

describe("Validation strip", () => {
  it("states undetected-gap summary with campaigns/completed/results/undetected", async () => {
    mockValidationAll();
    render(<Validation />);
    await waitFor(() =>
      expect(
        screen.getByText(/undetected executions are the gap/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Campaigns");
    expect(strip.textContent).toContain("Completed");
    expect(strip.textContent).toContain("Results");
    expect(strip.textContent).toContain("Undetected");
  });

  it("does not render when there are no validation results", async () => {
    mockValidationAll({ data: [] });
    render(<Validation />);
    await waitFor(() =>
      expect(screen.getByText("No validation results")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/undetected executions are the gap/i),
    ).not.toBeInTheDocument();
  });
});

const GOV_CONTROLS = {
  data: [
    {
      id: "AC-1",
      title: "Authentication required",
      description: "d",
      domain: "identity",
      framework: "BLUEVEIL-BASELINE",
      framework_version: "1.0.0-lab",
      implementation: "IMPLEMENTED",
    },
  ],
};

const GOV_ASSESSMENTS = {
  data: [
    {
      id: "gass-1",
      control_id: "AC-1",
      target: "seed-lab",
      status: "COMPLIANT",
      assessor: "seed-lab-grc",
      observed_at: "2026-09-12T10:00:00Z",
      evidence_ids: ["ev-1"],
      basis: "validation observed",
      notes: "",
      risk: "LOW",
      risk_basis: "lab",
    },
    {
      id: "gass-2",
      control_id: "RC-1",
      target: "seed-lab",
      status: "NOT_ASSESSED",
      assessor: "seed-lab-grc",
      observed_at: "2026-09-12T10:00:00Z",
      evidence_ids: [],
      basis: "",
      notes: "",
      risk: "UNKNOWN",
      risk_basis: "",
    },
  ],
};

const GOV_NODES = {
  data: [
    {
      asset_id: "ast-1",
      kind: "ASSET_TYPE_HOST",
      name: "web01",
      boundary: "lab",
    },
  ],
};

const GOV_EDGES = {
  data: [{ parent_id: "ast-1", child_id: "ast-2", kind: "RUNS" }],
};

const GOV_POSTURE = {
  data: [
    {
      id: "grsl-1",
      target: "seed-lab",
      assessor: "seed-lab-grc",
      observed_at: "2026-09-12T10:00:00Z",
      status: "READY",
      backup_observed: true,
      backup_at: "2026-09-12T10:00:00Z",
      restore_test_observed: true,
      restore_test_at: "2026-09-12T10:00:00Z",
      procedure_declared: true,
      dependencies: [],
      evidence_ids: ["ev-1"],
      retention_configured: true,
      encryption_observed: true,
    },
    {
      id: "grsl-2",
      target: "seed-lab-edge",
      assessor: "seed-lab-grc",
      observed_at: "2026-09-12T10:00:00Z",
      status: "NOT_ASSESSED",
      backup_observed: false,
      backup_at: "",
      restore_test_observed: false,
      restore_test_at: "",
      procedure_declared: false,
      dependencies: [],
      evidence_ids: [],
      retention_configured: false,
      encryption_observed: false,
    },
  ],
};

function mockGovernanceAll(controls: unknown = GOV_CONTROLS) {
  mockApi({
    "/api/v1/grc/frameworks": {
      data: [
        {
          id: "BLUEVEIL-BASELINE",
          version: "1.0.0-lab",
          kind: "INTERNAL_BASELINE",
          title: "t",
        },
      ],
    },
    "/api/v1/grc/controls": controls,
    "/api/v1/grc/assessments": GOV_ASSESSMENTS,
    "/api/v1/architecture/assets": GOV_NODES,
    "/api/v1/architecture/relationships": GOV_EDGES,
    "/api/v1/resilience/posture": GOV_POSTURE,
    "/api/v1/resilience/recovery": GOV_POSTURE,
  });
}

describe("Governance strip", () => {
  it("states compliance-gap summary with controls/assessments/failing", async () => {
    mockGovernanceAll();
    render(<Governance />);
    await waitFor(() =>
      expect(
        screen.getByText(/controls with no passing assessment/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Controls");
    expect(strip.textContent).toContain("Assessments");
    expect(strip.textContent).toContain("Failing");
  });

  it("does not render when there are no controls", async () => {
    mockGovernanceAll({ data: [] });
    render(<Governance />);
    await waitFor(() =>
      expect(screen.getByText("No controls")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/controls with no passing assessment/i),
    ).not.toBeInTheDocument();
  });
});

const INCIDENT_OPEN = {
  ...(incidentJson as Record<string, unknown>),
  id: "inc-strip-open",
  status: "INCIDENT_STATUS_OPEN",
};

const INCIDENT_INVESTIGATING = {
  ...(incidentJson as Record<string, unknown>),
  id: "inc-strip-inv",
  status: "INCIDENT_STATUS_INVESTIGATING",
};

const INCIDENT_RESOLVED = {
  ...(incidentJson as Record<string, unknown>),
  id: "inc-strip-res",
  status: "INCIDENT_STATUS_RESOLVED",
};

const INCIDENT_CLOSED = {
  ...(incidentJson as Record<string, unknown>),
  id: "inc-strip-closed",
  status: "INCIDENT_STATUS_CLOSED",
};

function mockIncidentsAll(incidents: unknown = [INCIDENT_OPEN]) {
  mockApi({
    "/api/v1/alerts": { data: [alertJson] },
    "/api/v1/detections": { data: [detectionJson] },
    "/api/v1/telemetry": { data: [telemetryJson] },
    "/api/v1/incidents": { data: incidents },
    "/api/v1/evidence": {
      integrity: "verified",
      data: [{ ...evidenceJson, incident_id: "inc-strip-open" }],
    },
  });
}

describe("Incidents strip", () => {
  it("states owner-first summary with open/investigating/resolved-closed", async () => {
    mockIncidentsAll([
      INCIDENT_OPEN,
      INCIDENT_INVESTIGATING,
      INCIDENT_RESOLVED,
      INCIDENT_CLOSED,
    ]);
    render(<Incidents focusAlertId={null} />);
    await waitFor(() =>
      expect(
        screen.getByText(/open incidents need owners/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Open");
    expect(strip.textContent).toContain("Investigating");
    expect(strip.textContent).toContain("Resolved + closed");
  });

  it("does not render when there are no incidents", async () => {
    mockIncidentsAll([]);
    render(<Incidents focusAlertId={null} />);
    await waitFor(() =>
      expect(screen.getByText("No incidents")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/open incidents need owners/i),
    ).not.toBeInTheDocument();
  });
});

const EVIDENCE_A = { ...evidenceJson, incident_id: "inc-strip-open" };

const EVIDENCE_B = {
  ...(evidenceJson as Record<string, unknown>),
  id: "ev-strip-002",
  incident_id: "inc-strip-other",
  sha256: "",
} as unknown as typeof evidenceJson;

function mockEvidenceAll(evidence: unknown = [EVIDENCE_A, EVIDENCE_B]) {
  mockApi({
    "/api/v1/evidence": { integrity: "verified", data: evidence },
    "/api/v1/incidents": { data: [incidentJson] },
  });
}

describe("Evidence strip", () => {
  it("states digest-verified summary with items/linked-incidents/sha256", async () => {
    mockEvidenceAll();
    render(<EvidenceView />);
    await waitFor(() =>
      expect(screen.getByText(/digest-verified/i)).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Items");
    expect(strip.textContent).toContain("Linked incidents");
    expect(strip.textContent).toContain("With SHA-256");
  });

  it("does not render when there is no evidence", async () => {
    mockEvidenceAll([]);
    render(<EvidenceView />);
    await waitFor(() =>
      expect(screen.getByText("No evidence")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/digest-verified/i)).not.toBeInTheDocument();
  });
});

const REC_BASE = recommendationJson as Record<string, unknown>;

function mockResponsesAll(recs: unknown) {
  mockApi({
    "/api/v1/recommendations": { data: recs },
    "/api/v1/approvals": { data: [approvalJson] },
    "/api/v1/executions": { data: [executionJson] },
    "/api/v1/verifications": { data: [verificationJson] },
  });
}

const RECS_MIXED = [
  {
    ...REC_BASE,
    id: "rec-strip-pending",
    status: "RESPONSE_STATUS_PENDING_APPROVAL",
  },
  { ...REC_BASE, id: "rec-strip-exec", status: "RESPONSE_STATUS_EXECUTING" },
  { ...REC_BASE, id: "rec-strip-verified", status: "RESPONSE_STATUS_VERIFIED" },
  { ...REC_BASE, id: "rec-strip-denied", status: "RESPONSE_STATUS_DENIED" },
  {
    ...REC_BASE,
    id: "rec-strip-execfail",
    status: "RESPONSE_STATUS_EXECUTION_FAILED",
  },
  {
    ...REC_BASE,
    id: "rec-strip-verfail",
    status: "RESPONSE_STATUS_VERIFICATION_FAILED",
  },
];

describe("Responses strip", () => {
  it("states approval-blocked summary with pending/executing/verified/failed", async () => {
    mockResponsesAll(RECS_MIXED);
    render(<Responses />);
    await waitFor(() =>
      expect(
        screen.getByText(/pending approvals block response/i),
      ).toBeInTheDocument(),
    );
    const strip = screen.getByRole("region", { name: "Summary" });
    expect(strip.textContent).toContain("Pending approval");
    expect(strip.textContent).toContain("Executing");
    expect(strip.textContent).toContain("Verified");
    expect(strip.textContent).toContain("Failed");
  });

  it("does not render when there are no responses", async () => {
    mockResponsesAll([]);
    render(<Responses />);
    await waitFor(() =>
      expect(screen.getByText("No responses")).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/pending approvals block response/i),
    ).not.toBeInTheDocument();
  });
});
