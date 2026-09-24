import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import alertJson from "../../../../contracts/fixtures/alert/valid.json";
import { Findings } from "./Findings";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

describe("hash initial filters", () => {
  it("Findings preselects severity and status from initial props", async () => {
    mockApi({
      "/api/v1/alerts": { data: [alertJson] },
      "/api/v1/detections": { data: [] },
      "/api/v1/telemetry": { data: [] },
    });
    render(
      <Findings
        onOpenIncident={() => {}}
        initialSeverity="SEVERITY_CRITICAL"
        initialStatus="ALERT_STATUS_OPEN"
      />,
    );
    await waitFor(() =>
      expect(screen.getByText("Findings")).toBeInTheDocument(),
    );
    expect((screen.getByLabelText("Severity") as HTMLSelectElement).value).toBe(
      "SEVERITY_CRITICAL",
    );
    expect((screen.getByLabelText("Status") as HTMLSelectElement).value).toBe(
      "ALERT_STATUS_OPEN",
    );
  });
});
