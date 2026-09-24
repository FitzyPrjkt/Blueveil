import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { Application } from "./Application";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const OBS = {
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

describe("Application", () => {
  it("renders populated rows", async () => {
    mockApi({
      "/api/v1/application/observations": OBS,
      "/api/v1/application/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
    });
    render(<Application />);
    await waitFor(() =>
      expect(screen.getAllByText("/api/users").length).toBe(2),
    );
    expect(screen.getAllByText("seed-lab.example").length).toBeGreaterThan(0);
    expect(screen.getByText("DETECTED")).toBeInTheDocument();
  });

  it("filters by method and detected", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/application/observations": OBS,
      "/api/v1/application/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
    });
    render(<Application />);
    await waitFor(() =>
      expect(screen.getAllByText("/api/users").length).toBe(2),
    );
    await user.selectOptions(screen.getByLabelText("Method"), "GET");
    expect(screen.getAllByRole("row").length).toBeGreaterThan(1);
    await user.click(screen.getByLabelText("Detected only"));
    // Only the 500 row is detected; 200 should be filtered out from table.
    await waitFor(async () => {
      const table = screen.getByRole("table");
      expect(within(table).queryByText("200")).not.toBeInTheDocument();
    });
    expect(
      within(screen.getByRole("table")).getByText("500"),
    ).toBeInTheDocument();
  });

  it("shows empty honestly", async () => {
    mockApi({ "/api/v1/application/observations": { data: [] } });
    render(<Application />);
    await waitFor(() =>
      expect(
        screen.getByText("No application observations"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText(
        "HTTP/API telemetry will appear here when observations are ingested.",
      ),
    ).toBeInTheDocument();
  });

  it("opens detail", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/application/observations": OBS,
      "/api/v1/application/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
    });
    render(<Application />);
    await waitFor(() =>
      expect(screen.getAllByText("/api/users").length).toBe(2),
    );
    await user.click(screen.getByLabelText("Open evt-http-002"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("Asset")).toBeInTheDocument(),
    );
    expect(
      within(dialog).getByText(/This observation triggered/),
    ).toBeInTheDocument();
  });
});
