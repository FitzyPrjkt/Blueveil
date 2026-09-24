import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { Monitoring } from "./Monitoring";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const EVENTS = {
  data: [
    {
      id: "evt-seed-mon-auth-001",
      occurred_at: "2026-09-12T09:50:00Z",
      source: "seed-lab-monitoring",
      asset_id: "seed-mon-01",
      event_type: "auth.activity",
      severity: "SEVERITY_INFO",
      attributes: { "auth.principal": "erin", "auth.outcome": "failure" },
    },
    {
      id: "evt-seed-mon-net-001",
      occurred_at: "2026-09-12T09:53:00Z",
      source: "seed-lab-monitoring",
      asset_id: "seed-mon-01",
      event_type: "net.connection",
      severity: "SEVERITY_INFO",
      attributes: { "net.dst_ip": "203.0.113.7" },
    },
  ],
};

const CORRS = {
  data: [
    {
      id: "corr-aaa",
      type: "auth-to-identity-change",
      event_ids: ["evt-seed-mon-auth-001", "evt-seed-mon-auth-002"],
      principal: "erin",
      asset_id: "",
      observed_at: "2026-09-12T09:52:00Z",
      status: "CORRELATED",
    },
  ],
};

const RULES = {
  data: [
    {
      id: "waf-block-high-severity",
      version: "1",
      title: "High-severity blocked request",
      description: "d",
      domain: "waf",
      event_types: ["waf.request_blocked"],
      severity_basis: "source",
      confidence_basis: "boolean-condition-unmeasured",
      stateful: false,
      enabled: true,
    },
  ],
};

const HEALTH = {
  status: "ok",
  data: [
    {
      rule_id: "waf-block-high-severity",
      version: "1",
      name: "High-severity blocked request",
      enabled: true,
      evaluated: 4,
      detections: 1,
      errors: 0,
    },
  ],
};

const HEALTH_ABSENT = {
  status: "unavailable",
  reason: "no live engine",
  data: [],
};

const IOCS = {
  status: "ok",
  set_id: "lab-ioc-set",
  set_version: "v1",
  data: [
    {
      kind: "ip",
      value: "203.0.113.7",
      source: "lab-ioc-v1",
      set_id: "lab-ioc-set",
      set_version: "v1",
    },
  ],
};

const MATCHES = {
  status: "ok",
  data: [
    {
      id: "iocm-bbb",
      event_id: "evt-seed-mon-net-001",
      occurred_at: "2026-09-12T09:53:00Z",
      asset_id: "seed-mon-01",
      kind: "ip",
      indicator: "203.0.113.7",
      matched_field: "attributes.net.dst_ip",
      set_id: "lab-ioc-set",
      set_version: "v1",
      list_source: "lab-ioc-v1",
    },
  ],
};

function mockAll(health: unknown = HEALTH) {
  mockApi({
    "/api/v1/monitoring/events": EVENTS,
    "/api/v1/monitoring/correlations": CORRS,
    "/api/v1/detection-rules": RULES,
    "/api/v1/detection-rules/health": health,
    "/api/v1/threat-intelligence/iocs": IOCS,
    "/api/v1/threat-intelligence/matches": MATCHES,
  });
}

describe("Monitoring", () => {
  it("renders event monitor rows", async () => {
    mockAll();
    render(<Monitoring />);
    await waitFor(() =>
      expect(screen.getByText("evt-seed-mon-auth-001")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("auth.activity").length).toBeGreaterThan(0);
  });

  it("filters events by type and shows honest empty", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Monitoring />);
    await waitFor(() =>
      expect(screen.getByText("evt-seed-mon-auth-001")).toBeInTheDocument(),
    );
    await user.selectOptions(
      screen.getByLabelText("Event type"),
      "http.request",
    );
    await waitFor(() =>
      expect(screen.getByText("No monitoring events")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/No threats detected/)).not.toBeInTheDocument();
  });

  it("shows correlations with CORRELATED status", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Monitoring />);
    await user.click(screen.getByRole("button", { name: "Correlations" }));
    await waitFor(() =>
      expect(screen.getByText("auth-to-identity-change")).toBeInTheDocument(),
    );
    expect(screen.getByText("CORRELATED")).toBeInTheDocument();
    expect(screen.queryByText(/Attack confirmed/)).not.toBeInTheDocument();
  });

  it("shows rule catalog and live health", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Monitoring />);
    await user.click(screen.getByRole("button", { name: "Rules" }));
    await waitFor(() =>
      expect(
        screen.getByText("High-severity blocked request"),
      ).toBeInTheDocument(),
    );
    await user.click(screen.getByRole("button", { name: "Health" }));
    await waitFor(() =>
      expect(screen.getByText("waf-block-high-severity")).toBeInTheDocument(),
    );
    expect(screen.getByText("4")).toBeInTheDocument();
  });

  it("reports honest health absence", async () => {
    const user = userEvent.setup();
    mockAll(HEALTH_ABSENT);
    render(<Monitoring />);
    await user.click(screen.getByRole("button", { name: "Health" }));
    await waitFor(() =>
      expect(screen.getByText(/not available/i)).toBeInTheDocument(),
    );
  });

  it("shows IOC matches as observations, not verdicts", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Monitoring />);
    await user.click(screen.getByRole("button", { name: "Threat Intel" }));
    await waitFor(() =>
      expect(screen.getByText("203.0.113.7")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/Malware confirmed/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Malware detected/)).not.toBeInTheDocument();
  });

  it("opens correlation drawer with provenance", async () => {
    const user = userEvent.setup();
    mockAll();
    render(<Monitoring />);
    await user.click(screen.getByRole("button", { name: "Correlations" }));
    await waitFor(() =>
      expect(screen.getByText("auth-to-identity-change")).toBeInTheDocument(),
    );
    const table = await screen.findByRole("table");
    await user.click(within(table).getByText("auth-to-identity-change"));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(within(dialog).getByText("erin")).toBeInTheDocument(),
    );
  });
});
