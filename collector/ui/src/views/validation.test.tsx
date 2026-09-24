import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Validation } from "../views/Validation";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const RESULTS = {
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

const CAMPAIGNS = {
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

const EXERCISES = {
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

describe("Validation workspace tabs", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("defaults to results and shows campaigns tab", async () => {
    mockApi({
      "/api/v1/validation-results": RESULTS,
      "/api/v1/validation/campaigns": CAMPAIGNS,
      "/api/v1/validation/history": RESULTS,
      "/api/v1/purple-team/exercises": EXERCISES,
    });
    render(<Validation />);
    await screen.findByText("ctl-lab");
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Campaigns" }));
    await screen.findByText("lab campaign");
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
  });

  it("campaign detail distinguishes verdicts without pass badges", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/validation-results": RESULTS,
      "/api/v1/validation/campaigns": CAMPAIGNS,
      "/api/v1/validation/history": RESULTS,
      "/api/v1/purple-team/exercises": EXERCISES,
    });
    render(<Validation />);
    await user.click(screen.getByRole("tab", { name: "Campaigns" }));
    await screen.findByText("lab campaign");
    const table = await screen.findByRole("table");
    await user.click(within(table).getByText("lab campaign"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("Provider errors")).toBeInTheDocument(),
    );
    expect(within(dialog).queryByText(/PASSED/)).not.toBeInTheDocument();
    expect(
      within(dialog).getByText(/never a success story|Counts only/),
    ).toBeInTheDocument();
  });

  it("purple team shows neutral exercise status", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/validation-results": RESULTS,
      "/api/v1/validation/campaigns": CAMPAIGNS,
      "/api/v1/validation/history": RESULTS,
      "/api/v1/purple-team/exercises": EXERCISES,
    });
    render(<Validation />);
    await user.click(screen.getByRole("tab", { name: "Purple Team" }));
    await screen.findByText("lab exercise");
    expect(screen.queryByText(/COMPROMISED/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BREACHED/)).not.toBeInTheDocument();
  });

  it("empty campaigns explain honestly", async () => {
    mockApi({
      "/api/v1/validation-results": { data: [] },
      "/api/v1/validation/campaigns": { data: [] },
      "/api/v1/validation/history": { data: [] },
      "/api/v1/purple-team/exercises": { data: [] },
    });
    render(<Validation />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "Campaigns" }));
    await waitFor(() =>
      expect(screen.getByText("No validation campaigns")).toBeInTheDocument(),
    );
  });
});
