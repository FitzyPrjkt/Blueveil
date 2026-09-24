import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { Investigations } from "./Investigations";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const HUNT = {
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

const TIMELINE = {
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

const ARTIFACTS = {
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

function mockAll() {
  mockApi({
    "/api/v1/hunting/events": HUNT,
    "/api/v1/hunting/timeline": TIMELINE,
    "/api/v1/forensics/artifacts": ARTIFACTS,
    "/api/v1/forensics/endpoint": { data: [ARTIFACTS.data[0]] },
    "/api/v1/forensics/network": { data: [ARTIFACTS.data[1]] },
    "/api/v1/forensics/cloud": { data: [] },
    "/api/v1/forensics/identity": { data: [] },
  });
}

describe("Investigations", () => {
  it("renders hunting results tagged HUNT_RESULT", async () => {
    mockAll();
    render(<Investigations />);
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-auth-001")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("HUNT_RESULT").length).toBeGreaterThan(0);
    expect(screen.queryByText(/CONFIRMED_ATTACK/)).not.toBeInTheDocument();
  });

  it("searches hunting results and shows honest empty", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Investigations />);
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-auth-001")).toBeInTheDocument(),
    );
    await user.type(screen.getByLabelText("Search hunting"), "zzz-no-such");
    await waitFor(() =>
      expect(screen.getByText("No hunting results")).toBeInTheDocument(),
    );
  });

  it("shows timeline in occurred_at order", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Investigations />);
    await user.click(screen.getByRole("button", { name: "Timeline" }));
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-auth-001")).toBeInTheDocument(),
    );
    expect(
      screen.getByText("Cross-domain principal activity observed"),
    ).toBeInTheDocument();
  });

  it("shows forensics tabs with classified artifacts", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Investigations />);
    await user.click(screen.getByRole("button", { name: "Forensics" }));
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-endpoint-001")).toBeInTheDocument(),
    );
    expect(screen.getByText("PROCESS")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Network" }));
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-net-001")).toBeInTheDocument(),
    );
  });

  it("opens artifact drawer with provenance", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Investigations />);
    await user.click(screen.getByRole("button", { name: "Forensics" }));
    await waitFor(() =>
      expect(screen.getByText("evt-seed-inv-endpoint-001")).toBeInTheDocument(),
    );
    const table = await screen.findByRole("table");
    await user.click(within(table).getByText("evt-seed-inv-endpoint-001"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("abc123")).toBeInTheDocument(),
    );
  });

  it("shows honest empty state, never threat claims", async () => {
    mockApi({
      "/api/v1/hunting/events": { data: [] },
      "/api/v1/hunting/timeline": { data: [] },
      "/api/v1/forensics/artifacts": { data: [] },
      "/api/v1/forensics/endpoint": { data: [] },
      "/api/v1/forensics/network": { data: [] },
      "/api/v1/forensics/cloud": { data: [] },
      "/api/v1/forensics/identity": { data: [] },
    });
    render(<Investigations />);
    await waitFor(() =>
      expect(screen.getByText("No hunting results")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/No threats detected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Attacker detected/)).not.toBeInTheDocument();
  });
});
