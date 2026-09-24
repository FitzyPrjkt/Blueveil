import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { Identity } from "./Identity";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const IDENTITY = {
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

const AUTH = {
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

const DATA = {
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

function mockAll() {
  mockApi({
    "/api/v1/identity/observations": IDENTITY,
    "/api/v1/authentication/observations": AUTH,
    "/api/v1/data/observations": DATA,
    "/api/v1/identity/relationships": { data: [] },
    "/api/v1/assets": { data: [] },
  });
}

describe("Identity", () => {
  it("renders identity rows with key columns", async () => {
    mockAll();
    render(<Identity />);
    await waitFor(() => expect(screen.getAllByText("alice").length).toBe(2));
    // The Action select now also lists role_change: scope the row check to
    // the table.
    expect(screen.getByRole("table").textContent).toContain("role_change");
    expect(screen.getByText("DETECTED")).toBeInTheDocument();
  });

  it("switches to authentication tab and filters", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Identity />);
    await user.click(screen.getByRole("button", { name: "Authentication" }));
    await waitFor(() => expect(screen.getByText("carol")).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Outcome"), "failure");
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
    expect(screen.getByText("carol")).toBeInTheDocument();
  });

  it("switches to data tab and searches", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Identity />);
    await user.click(screen.getByRole("button", { name: "Data" }));
    await waitFor(() =>
      expect(screen.getByText("customers")).toBeInTheDocument(),
    );
    await user.type(screen.getByLabelText("Search identity"), "customers");
    expect(screen.queryByText("blog")).not.toBeInTheDocument();
  });

  it("shows honest empty state, never threat claims", async () => {
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
    expect(screen.queryByText(/No attacks detected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No threats detected/)).not.toBeInTheDocument();
  });

  it("opens detail drawer with provenance", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Identity />);
    await waitFor(() =>
      expect(screen.getByText("role_change")).toBeInTheDocument(),
    );
    const table = await screen.findByRole("table");
    await user.click(within(table).getByText("role_change"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("Detection")).toBeInTheDocument(),
    );
    expect(within(dialog).getByText("admin-role")).toBeInTheDocument();
  });
});
