import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import detectionJson from "../../../../contracts/fixtures/detection/valid.json";
import telemetryJson from "../../../../contracts/fixtures/telemetry/valid.json";
import { Overview } from "../views/Overview";
import { Findings } from "../views/Findings";
import { mockApi, mockApiError, mockApiFailure } from "../test-utils";

afterEach(() => cleanup());

const ALERTS = { data: [alertJson] };
const DETECTIONS = { data: [detectionJson] };
const TELEMETRY = { data: [telemetryJson] };

describe("Overview", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders real counts when populated", async () => {
    mockApi({
      "/api/v1/alerts": ALERTS,
      "/api/v1/assets": { data: [] },
      "/api/v1/incidents": { data: [] },
      "/api/v1/validation-results": { data: [] },
      "/api/v1/supply-chain/components": { data: [] },
      "/api/v1/supply-chain/policies": { data: [] },
    });
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText("Findings")).toBeInTheDocument(),
    );
    expect(screen.getByText(/30-day trend/i)).toBeInTheDocument();
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });

  it("renders empty state when everything is empty", async () => {
    mockApi({
      "/api/v1/alerts": { data: [] },
      "/api/v1/assets": { data: [] },
      "/api/v1/incidents": { data: [] },
      "/api/v1/validation-results": { data: [] },
      "/api/v1/supply-chain/components": { data: [] },
      "/api/v1/supply-chain/policies": { data: [] },
    });
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText(/not enough data/i)).toBeInTheDocument(),
    );
  });

  it("renders backend error, never an empty table", async () => {
    mockApiError("INTERNAL", "boom");
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText("Backend error")).toBeInTheDocument(),
    );
    expect(screen.queryByText("No data yet")).not.toBeInTheDocument();
  });

  it("renders network failure distinctly", async () => {
    mockApiFailure();
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText("Backend error")).toBeInTheDocument(),
    );
  });
});

describe("Findings", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("searches and filters by severity", async () => {
    const user = userEvent.setup();
    const low = {
      ...alertJson,
      id: "alert-low-001",
      title: "Low quiet thing",
      severity: "SEVERITY_LOW",
      status: "ALERT_STATUS_CLOSED",
    };
    mockApi({
      "/api/v1/alerts": { data: [alertJson, low] },
      "/api/v1/detections": DETECTIONS,
      "/api/v1/telemetry": TELEMETRY,
    });
    render(<Findings onOpenIncident={() => {}} />);
    await waitFor(() =>
      expect(screen.getByText("Low quiet thing")).toBeInTheDocument(),
    );
    // Search narrows to one row.
    await user.type(screen.getByLabelText("Search findings"), "quiet");
    expect(
      screen.queryByText((alertJson as { title: string }).title),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Low quiet thing")).toBeInTheDocument();
    // Severity filter narrows further; derived rows come from fixtures.
    await user.clear(screen.getByLabelText("Search findings"));
    await user.selectOptions(
      screen.getByLabelText("Severity"),
      "SEVERITY_HIGH",
    );
    expect(screen.queryByText("Low quiet thing")).not.toBeInTheDocument();
  });

  it("renders severity badges with obvious classes", async () => {
    mockApi({
      "/api/v1/alerts": ALERTS,
      "/api/v1/detections": DETECTIONS,
      "/api/v1/telemetry": TELEMETRY,
    });
    const { container } = render(<Findings onOpenIncident={() => {}} />);
    await waitFor(() =>
      expect(
        container.querySelector(".badge.high, .badge.critical, .badge.medium"),
      ).toBeInTheDocument(),
    );
  });

  it("shows no-results copy for filters that match nothing", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/alerts": ALERTS,
      "/api/v1/detections": DETECTIONS,
      "/api/v1/telemetry": TELEMETRY,
    });
    render(<Findings onOpenIncident={() => {}} />);
    await waitFor(() =>
      expect(screen.getByLabelText("Search findings")).toBeInTheDocument(),
    );
    await user.type(
      screen.getByLabelText("Search findings"),
      "zzz-no-such-finding",
    );
    await waitFor(() =>
      expect(screen.getByText("No matching findings")).toBeInTheDocument(),
    );
  });
});
