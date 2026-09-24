import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import {
  assetCoverage,
  bucketTrend,
  openAlerts,
  pickAttention,
  summarizeTrend,
} from "./overviewAgg";
import { Overview } from "./Overview";
import { mockApi } from "../test-utils";
import type { Alert } from "../contracts";

const NOW = Date.parse("2026-09-19T12:00:00Z");
function alert(
  id: string,
  created_at: string,
  severity: Alert["severity"] = "SEVERITY_HIGH",
  status: Alert["status"] = "ALERT_STATUS_OPEN",
): Alert {
  return {
    id,
    detection_ids: [],
    status,
    severity,
    created_at,
    updated_at: created_at,
    title: `finding ${id}`,
  };
}

describe("overviewAgg", () => {
  it("openAlerts excludes closed findings", () => {
    const all = [
      alert("a", "2026-09-18T00:00:00Z"),
      alert(
        "b",
        "2026-09-18T00:00:00Z",
        "SEVERITY_LOW",
        "ALERT_STATUS_ACKNOWLEDGED",
      ),
      alert("c", "2026-09-18T00:00:00Z", "SEVERITY_LOW", "ALERT_STATUS_CLOSED"),
    ];
    expect(openAlerts(all).map((a) => a.id)).toEqual(["a", "b"]);
  });

  it("bucketTrend stacks 30 days by severity", () => {
    const days = bucketTrend(
      [
        alert("a", "2026-09-19T01:00:00Z", "SEVERITY_CRITICAL"),
        alert("b", "2026-09-10T01:00:00Z", "SEVERITY_HIGH"),
        alert("c", "2026-08-01T01:00:00Z"),
      ],
      NOW,
    );
    expect(days).toHaveLength(30);
    expect(days[29]).toMatchObject({ critical: 1, high: 0, other: 0 });
    expect(days[20]).toMatchObject({ critical: 0, high: 1, other: 0 });
    expect(days.reduce((n, d) => n + d.critical + d.high + d.other, 0)).toBe(2);
  });

  it("assetCoverage counts ACTIVE over ACTIVE+STALE", () => {
    const cov = assetCoverage([
      {
        id: "1",
        type: "ASSET_TYPE_HOST",
        name: "a",
        status: "ASSET_STATUS_ACTIVE",
      },
      {
        id: "2",
        type: "ASSET_TYPE_HOST",
        name: "b",
        status: "ASSET_STATUS_STALE",
      },
      {
        id: "3",
        type: "ASSET_TYPE_HOST",
        name: "c",
        status: "ASSET_STATUS_RETIRED",
      },
      { id: "4", type: "ASSET_TYPE_HOST", name: "d" },
    ]);
    expect(cov).toEqual({ monitored: 4, active: 1, stale: 1, ratio: 0.5 });
  });

  it("pickAttention caps at five with oldest critical first", () => {
    const items = pickAttention(
      {
        alerts: [
          alert("old", "2026-09-01T00:00:00Z", "SEVERITY_CRITICAL"),
          alert("new", "2026-09-18T00:00:00Z", "SEVERITY_CRITICAL"),
        ],
        assets: [],
        incidents: [],
        results: [],
        components: [],
        policies: [],
      },
      NOW,
    );
    expect(items.length).toBeLessThanOrEqual(5);
    expect(items[0]?.key).toContain("old");
  });

  it("summarizeTrend is honest when empty", () => {
    expect(summarizeTrend([], 0)).toMatch(/not yet enough data/i);
  });
});

afterEach(() => cleanup());

const ALERT = {
  id: "al-1",
  detection_ids: ["det-1"],
  status: "ALERT_STATUS_OPEN",
  severity: "SEVERITY_CRITICAL",
  created_at: "2026-09-10T00:00:00Z",
  updated_at: "2026-09-10T00:00:00Z",
  title: "Critical finding",
};
const ASSET = {
  id: "as-1",
  type: "ASSET_TYPE_HOST",
  name: "host-1",
  status: "ASSET_STATUS_ACTIVE",
};
const FULL = {
  "/api/v1/alerts": { data: [ALERT] },
  "/api/v1/assets": { data: [ASSET] },
  "/api/v1/incidents": { data: [] },
  "/api/v1/validation-results": { data: [] },
  "/api/v1/supply-chain/components": { data: [] },
  "/api/v1/supply-chain/policies": { data: [] },
};

describe("Overview executive", () => {
  it("renders status strip, four cards, trend, attention, and domains", async () => {
    mockApi(FULL);
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText(/needs attention/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /findings/i })).toBeInTheDocument();
    expect(screen.getByText(/30-day trend/i)).toBeInTheDocument();
    expect(screen.getByText("Attack Surface")).toBeInTheDocument();
  });

  it("every stat number links to a pre-filtered workspace", async () => {
    mockApi(FULL);
    render(<Overview />);
    await waitFor(() =>
      expect(screen.getByText(/needs attention/i)).toBeInTheDocument(),
    );
    const links = screen.getAllByRole("link");
    for (const l of links) {
      expect(l.getAttribute("href")).toMatch(/^#\//);
    }
    expect(
      links.some((l) => (l.getAttribute("href") ?? "").includes("?")),
    ).toBe(true);
  });

  it("is honest when empty", async () => {
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
});
