import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import detectionJson from "../../../../contracts/fixtures/detection/valid.json";
import evidenceJson from "../../../../contracts/fixtures/evidence/valid.json";
import incidentJson from "../../../../contracts/fixtures/incident/valid.json";
import telemetryJson from "../../../../contracts/fixtures/telemetry/valid.json";
import approvalJson from "../../../../contracts/fixtures/response/valid_approval.json";
import executionJson from "../../../../contracts/fixtures/response/valid_execution.json";
import recommendationJson from "../../../../contracts/fixtures/response/valid_recommendation.json";
import verificationJson from "../../../../contracts/fixtures/response/valid_verification.json";
import notTestedJson from "../../../../contracts/fixtures/validation/valid_result_not_tested.json";
import resultJson from "../../../../contracts/fixtures/validation/valid_result.json";
import { Incidents } from "../views/Incidents";
import { EvidenceView } from "../views/Evidence";
import { Validation } from "../views/Validation";
import { Responses } from "../views/Responses";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const FULL = {
  "/api/v1/alerts": { data: [alertJson] },
  "/api/v1/detections": { data: [detectionJson] },
  "/api/v1/telemetry": { data: [telemetryJson] },
  "/api/v1/incidents": { data: [incidentJson] },
  "/api/v1/evidence": {
    integrity: "verified",
    data: [
      { ...evidenceJson, incident_id: (incidentJson as { id: string }).id },
    ],
  },
  "/api/v1/recommendations": { data: [recommendationJson] },
  "/api/v1/approvals": { data: [approvalJson] },
  "/api/v1/executions": { data: [executionJson] },
  "/api/v1/verifications": { data: [verificationJson] },
  "/api/v1/validation-results": { data: [resultJson, notTestedJson] },
};

describe("Incidents", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the relationship chain in detail", async () => {
    const user = userEvent.setup();
    mockApi(FULL);
    render(<Incidents focusAlertId={null} />);
    const title = (incidentJson as { title: string }).title;
    await waitFor(() => expect(screen.getByText(title)).toBeInTheDocument());
    await user.click(screen.getByText(title));
    await waitFor(() => {
      // Chain: alert title unique; rule shared by both alerts (appears twice).
      expect(
        screen.getByText((alertJson as { title: string }).title),
      ).toBeInTheDocument();
      expect(
        screen.getAllByText(
          new RegExp((detectionJson as { rule_name: string }).rule_name),
        ).length,
      ).toBeGreaterThanOrEqual(1);
    });
    expect(
      screen.getByRole("heading", { name: "Lifecycle" }),
    ).toBeInTheDocument();
  });

  it("shows empty copy when no incidents", async () => {
    mockApi({ ...FULL, "/api/v1/incidents": { data: [] } });
    render(<Incidents focusAlertId={null} />);
    await waitFor(() =>
      expect(screen.getByText("No incidents")).toBeInTheDocument(),
    );
    expect(screen.getByText(/correlated into an incident/)).toBeInTheDocument();
  });
});

describe("Evidence", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders verified integrity and safe plain-text content", async () => {
    const user = userEvent.setup();
    mockApi(FULL);
    render(<EvidenceView />);
    const id = (evidenceJson as { id: string }).id;
    await waitFor(() => expect(screen.getByText(id)).toBeInTheDocument());
    expect(screen.getAllByText("VERIFIED").length).toBeGreaterThan(0);
    await user.click(screen.getByText(id));
    const pre = await screen.findByText(
      (evidenceJson as { content: string }).content,
    );
    expect(pre.tagName).toBe("PRE");
  });

  it("withholds VERIFIED when the integrity envelope is missing", async () => {
    mockApi({
      ...FULL,
      "/api/v1/evidence": {
        data: [
          {
            ...evidenceJson,
            incident_id: (incidentJson as { id: string }).id,
          },
        ],
      },
    });
    render(<EvidenceView />);
    await waitFor(() =>
      expect(screen.getByText("Invalid data")).toBeInTheDocument(),
    );
    expect(screen.queryByText("VERIFIED")).not.toBeInTheDocument();
  });
});

describe("Validation", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders all eight verdicts verbatim plus honest NOT_TESTED/UNKNOWN copy", async () => {
    mockApi(FULL);
    render(<Validation />);
    // RATE LIMITED exists only in the legend (seed has no such result): unique load signal.
    await screen.findByText("RATE LIMITED");
    for (const v of [
      "PREVENTED",
      "DETECTED",
      "PREVENTED AND DETECTED",
      "ALLOWED BUT DETECTED",
      "ALLOWED AND NOT DETECTED",
      "UNKNOWN",
      "NOT TESTED",
      "RATE LIMITED",
    ]) {
      // Legend chips + table badges both render: at least one occurrence.
      expect(screen.getAllByText(v).length).toBeGreaterThanOrEqual(1);
    }
    expect(screen.queryByText(/SECURE/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PASS/)).not.toBeInTheDocument();
  });

  it("explains NOT_TESTED honestly in detail", async () => {
    const user = userEvent.setup();
    mockApi(FULL);
    render(<Validation />);
    const table = await screen.findByRole("table");
    const { getAllByText } = within(table);
    // First NOT TESTED row badge (legend chips live outside the table).
    const badge = getAllByText("NOT TESTED")[0];
    if (!badge) throw new Error("expected a NOT TESTED row");
    await user.click(badge);
    await waitFor(() =>
      expect(
        screen.getByText("Validation was not performed"),
      ).toBeInTheDocument(),
    );
  });
});

describe("Responses", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the safety timeline and no action buttons", async () => {
    const user = userEvent.setup();
    mockApi(FULL);
    const { container } = render(<Responses />);
    const table = await screen.findByRole("table");
    // Open the first recommendation's drawer: timeline lives in detail.
    const rows = within(table).getAllByRole("row");
    const firstRow = rows[1];
    if (!firstRow) throw new Error("expected at least one data row");
    await user.click(firstRow);
    await waitFor(() =>
      expect(container.querySelector(".timeline")).toBeInTheDocument(),
    );
    const buttons = Array.from(container.querySelectorAll("button")).map((b) =>
      (b.textContent ?? "").toLowerCase(),
    );
    for (const label of ["block", "isolate", "delete", "execute"]) {
      expect(buttons.some((t) => t.includes(label))).toBe(false);
    }
  });

  it("renders the EXECUTING phase instead of skipping it", async () => {
    mockApi({
      ...FULL,
      "/api/v1/recommendations": {
        data: [
          {
            ...(recommendationJson as Record<string, unknown>),
            status: "RESPONSE_STATUS_EXECUTING",
          },
        ],
      },
    });
    const { container } = render(<Responses />);
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row");
    const firstRow = rows[1];
    if (!firstRow) throw new Error("expected at least one data row");
    const user = userEvent.setup();
    await user.click(firstRow);
    await waitFor(() =>
      expect(container.querySelector(".timeline")).toBeInTheDocument(),
    );
    // EXECUTING is a real phase: the timeline must show it as current,
    // not blank every step.
    expect(container.querySelector(".timeline")?.textContent).toMatch(
      /EXECUTING/,
    );
  });
});
