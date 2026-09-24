import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Network } from "./Network";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const OBS = {
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

describe("Network", () => {
  it("renders populated rows with key columns", async () => {
    mockApi({
      "/api/v1/network/observations": OBS,
      "/api/v1/network/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/detections": { data: [] },
    });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("127.0.0.1:43110")).toBeInTheDocument(),
    );
    expect(screen.getByText("203.0.113.7:4444")).toBeInTheDocument();
    expect(screen.getByText("DETECTED")).toBeInTheDocument();
  });

  it("filters by protocol and detected-only", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/network/observations": OBS,
      "/api/v1/network/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/detections": { data: [] },
    });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("127.0.0.1:43110")).toBeInTheDocument(),
    );
    await user.selectOptions(screen.getByLabelText("Protocol"), "TCP");
    expect(screen.getAllByRole("row").length).toBeGreaterThan(1);
    await user.click(screen.getByLabelText("Detected only"));
    await waitFor(() =>
      expect(screen.queryByText("127.0.0.1:43110")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("203.0.113.7:4444")).toBeInTheDocument();
  });

  it("searches by IP", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/network/observations": OBS,
      "/api/v1/network/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/detections": { data: [] },
    });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("127.0.0.1:43110")).toBeInTheDocument(),
    );
    await user.type(screen.getByLabelText("Search network"), "203.0.113");
    await waitFor(() =>
      expect(screen.queryByText("127.0.0.1:43110")).not.toBeInTheDocument(),
    );
  });

  it("shows empty copy honestly", async () => {
    mockApi({ "/api/v1/network/observations": { data: [] } });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("No network observations")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(
        "Network telemetry will appear here when observations are ingested.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/No threats/)).not.toBeInTheDocument();
  });

  it("opens detail with verdict and asset correlation", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/network/observations": OBS,
      "/api/v1/network/relationships": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/detections": { data: [] },
    });
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("203.0.113.7:4444")).toBeInTheDocument(),
    );
    await user.click(screen.getByLabelText("Open evt-seed-net-002"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("Asset correlation")).toBeInTheDocument(),
    );
    expect(
      within(dialog).getAllByText(/No asset observed/).length,
    ).toBeGreaterThanOrEqual(1);
    expect(
      within(dialog).getByText(/This observation triggered/),
    ).toBeInTheDocument();
  });

  it("handles backend error and invalid data", async () => {
    const { mockApiError, mockApiFailure } = await import("../test-utils");
    mockApiError("INTERNAL", "backend error");
    const { unmount } = render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("Backend error")).toBeInTheDocument(),
    );
    unmount();
    cleanup();
    vi.restoreAllMocks();
    mockApiFailure();
    render(<Network />);
    await waitFor(() =>
      expect(screen.getByText("Backend error")).toBeInTheDocument(),
    );
  });
});
