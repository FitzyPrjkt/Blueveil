import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { Governance } from "./Governance";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const CONTROLS = {
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

const ASSESSMENTS = {
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

const NODES = {
  data: [
    {
      asset_id: "ast-1",
      kind: "ASSET_TYPE_HOST",
      name: "web01",
      boundary: "lab",
    },
  ],
};

const EDGES = {
  data: [{ parent_id: "ast-1", child_id: "ast-2", kind: "RUNS" }],
};

const POSTURE = {
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

function mockAll() {
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
    "/api/v1/grc/controls": CONTROLS,
    "/api/v1/grc/assessments": ASSESSMENTS,
    "/api/v1/architecture/assets": NODES,
    "/api/v1/architecture/relationships": EDGES,
    "/api/v1/resilience/posture": POSTURE,
    "/api/v1/resilience/recovery": POSTURE,
  });
}

describe("Governance", () => {
  it("renders controls with distinct statuses", async () => {
    mockAll();
    render(<Governance />);
    await waitFor(() =>
      expect(screen.getByText("Authentication required")).toBeInTheDocument(),
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Assessments" }));
    const table = await screen.findByRole("table");
    await waitFor(() =>
      expect(within(table).getByText("COMPLIANT")).toBeInTheDocument(),
    );
    expect(within(table).getByText("NOT_ASSESSED")).toBeInTheDocument();
    // Statuses are text badges, never score rings or percentages.
    expect(screen.queryByText(/100% secure/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SECURE/)).not.toBeInTheDocument();
  });

  it("filters assessments by status", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Governance />);
    await user.click(screen.getByRole("tab", { name: "Assessments" }));
    const table = await screen.findByRole("table");
    await waitFor(() =>
      expect(within(table).getByText("COMPLIANT")).toBeInTheDocument(),
    );
    await user.selectOptions(screen.getByLabelText("Status"), "NOT_ASSESSED");
    expect(within(table).queryByText("COMPLIANT")).not.toBeInTheDocument();
    expect(within(table).getByText("NOT_ASSESSED")).toBeInTheDocument();
  });

  it("shows architecture nodes and edges from real data", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Governance />);
    await user.click(screen.getByRole("tab", { name: "Architecture" }));
    await waitFor(() => expect(screen.getByText("web01")).toBeInTheDocument());
    expect(screen.getByText("RUNS")).toBeInTheDocument();
  });

  it("shows resilience observed vs declared vs not assessed", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Governance />);
    await user.click(screen.getByRole("tab", { name: "Resilience" }));
    await waitFor(() => expect(screen.getByText("READY")).toBeInTheDocument());
    expect(screen.getByText("NOT_ASSESSED")).toBeInTheDocument();
    expect(screen.queryByText(/resilience score/i)).not.toBeInTheDocument();
  });

  it("opens assessment drawer with basis and provenance", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Governance />);
    await user.click(screen.getByRole("tab", { name: "Assessments" }));
    const table = await screen.findByRole("table");
    await waitFor(() =>
      expect(within(table).getByText("COMPLIANT")).toBeInTheDocument(),
    );
    await user.click(within(table).getByText("AC-1"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(
        within(dialog).getByText("validation observed"),
      ).toBeInTheDocument(),
    );
  });

  it("shows honest empty states", async () => {
    mockApi({
      "/api/v1/grc/frameworks": { data: [] },
      "/api/v1/grc/controls": { data: [] },
      "/api/v1/grc/assessments": { data: [] },
      "/api/v1/architecture/assets": { data: [] },
      "/api/v1/architecture/relationships": { data: [] },
      "/api/v1/resilience/posture": { data: [] },
      "/api/v1/resilience/recovery": { data: [] },
    });
    render(<Governance />);
    await waitFor(() =>
      expect(screen.getByText("No controls")).toBeInTheDocument(),
    );
  });
});
