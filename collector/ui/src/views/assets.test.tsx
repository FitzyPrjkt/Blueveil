import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import assetFullJson from "../../../../contracts/fixtures/asset/valid_full.json";
import assetLegacyJson from "../../../../contracts/fixtures/asset/valid.json";
import { Assets } from "../views/Assets";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const ASSETS = { data: [assetFullJson, assetLegacyJson] };

describe("Assets", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders populated inventory with all columns", async () => {
    mockApi({ "/api/v1/assets": ASSETS });
    render(<Assets />);
    await waitFor(() =>
      expect(
        screen.getByText("https://seed-lab.example/app"),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText("waf-sim lab host")).toBeInTheDocument();
    expect(screen.getByText("Environment")).toBeInTheDocument();
  });

  it("searches and filters by type and status", async () => {
    const user = userEvent.setup();
    mockApi({ "/api/v1/assets": ASSETS });
    render(<Assets />);
    await waitFor(() =>
      expect(
        screen.getByText("https://seed-lab.example/app"),
      ).toBeInTheDocument(),
    );
    await user.type(screen.getByLabelText("Search assets"), "waf-sim");
    expect(
      screen.queryByText("https://seed-lab.example/app"),
    ).not.toBeInTheDocument();
    await user.clear(screen.getByLabelText("Search assets"));
    await user.selectOptions(screen.getByLabelText("Type"), "ASSET_TYPE_URL");
    expect(screen.queryByText("waf-sim lab host")).not.toBeInTheDocument();
    expect(
      screen.getByText("https://seed-lab.example/app"),
    ).toBeInTheDocument();
  });

  it("stale-only toggle and empty states are honest", async () => {
    const user = userEvent.setup();
    mockApi({ "/api/v1/assets": ASSETS });
    render(<Assets />);
    await waitFor(() =>
      expect(
        screen.getByText("https://seed-lab.example/app"),
      ).toBeInTheDocument(),
    );
    // Neither fixture asset is STALE → honest empty, not hidden rows.
    await user.click(screen.getByText(/Stale only/));
    await waitFor(() =>
      expect(screen.getByText("No matching assets")).toBeInTheDocument(),
    );
  });

  it("shows empty copy on empty inventory", async () => {
    mockApi({ "/api/v1/assets": { data: [] } });
    render(<Assets />);
    await waitFor(() =>
      expect(screen.getByText("No assets")).toBeInTheDocument(),
    );
  });

  it("opens detail with identity, lifecycle, and relationships", async () => {
    const user = userEvent.setup();
    const id = (assetFullJson as { id: string }).id;
    mockApi({
      "/api/v1/assets": ASSETS,
      [`/api/v1/assets/${id}`]: { data: assetFullJson },
      [`/api/v1/assets/${id}/relationships`]: {
        data: { parents: [], children: [] },
      },
      [`/api/v1/assets/${id}/telemetry`]: { data: [] },
      [`/api/v1/assets/${id}/findings`]: {
        data: { alerts: [], incidents: [], detections: [] },
      },
    });
    render(<Assets />);
    await waitFor(() =>
      expect(
        screen.getByText("https://seed-lab.example/app"),
      ).toBeInTheDocument(),
    );
    const table = await screen.findByRole("table");
    const row = within(table).getByText("https://seed-lab.example/app");
    await user.click(row);
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(
        within(dialog).getByRole("heading", { name: "Lifecycle" }),
      ).toBeInTheDocument(),
    );
    // Legacy record renders unknown status honestly.
    expect(within(dialog).getByText("ACTIVE")).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        "Nothing linked — absence of findings proves nothing about this asset.",
      ),
    ).toBeInTheDocument();
  });
});
