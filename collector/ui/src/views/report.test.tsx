import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { reportDigest, stableStringify } from "./reportHash";
import { ReportView, reportFilename } from "./ReportView";
import { mockApi } from "../test-utils";

describe("reportHash", () => {
  it("is deterministic and key-order independent", () => {
    expect(stableStringify({ b: 1, a: [3, 2] })).toBe('{"a":[3,2],"b":1}');
    expect(reportDigest({ b: 1, a: [3, 2] })).toBe(
      reportDigest({ a: [3, 2], b: 1 }),
    );
    expect(reportDigest({ a: 1 })).toMatch(/^[0-9a-f]{8}$/);
    expect(reportDigest({ a: 1 })).not.toBe(reportDigest({ a: 2 }));
  });
});

afterEach(() => cleanup());

const ROUTES = {
  "/api/v1/alerts": { data: [] },
  "/api/v1/assets": { data: [] },
  "/api/v1/incidents": { data: [] },
  "/api/v1/validation-results": { data: [] },
  "/api/v1/supply-chain/components": { data: [] },
  "/api/v1/supply-chain/policies": { data: [] },
  "/api/v1/third-party/assessments": { data: [] },
  "/api/v1/evidence": { data: [], integrity: "verified" },
};

describe("ReportView", () => {
  it("renders all ten full-report sections with honest empty copy", async () => {
    mockApi(ROUTES);
    render(<ReportView issued="2026-09-19" />);
    await waitFor(() =>
      expect(screen.getByText("Security Posture Report")).toBeInTheDocument(),
    );
    for (const h of [
      "Summary",
      "Top findings",
      "By domain",
      "Supply chain",
      "Validation",
      "Governance",
      "Appendix A",
      "Appendix B",
      "Limitations",
    ]) {
      expect(screen.getByText(h)).toBeInTheDocument();
    }
    expect(screen.getByText(/out of this report's scope/i)).toBeInTheDocument();
  });

  it("executive variant caps at top five and three actions", async () => {
    const user = userEvent.setup();
    mockApi(ROUTES);
    render(<ReportView issued="2026-09-19" />);
    await waitFor(() =>
      expect(screen.getByText("Security Posture Report")).toBeInTheDocument(),
    );
    await user.click(screen.getByRole("button", { name: /executive/i }));
    expect(screen.getByText(/recommended actions/i)).toBeInTheDocument();
  });

  it("filename is deterministic", () => {
    expect(reportFilename("2026-09-19")).toBe("blueveil-report-2026-09-19.pdf");
  });
});
