import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { SupplyChain } from "./SupplyChain";
import { mockApi } from "../test-utils";

afterEach(() => cleanup());

const COMPONENTS = {
  data: [
    {
      id: "comp-aaa",
      type: "LIBRARY",
      ecosystem: "npm",
      namespace: "",
      name: "left-pad",
      version: "1.0.0",
      requested_version: "",
      resolved_version: "",
      digest: "",
      source_revision: "",
      license: "MIT",
      license_source: "declared",
      provenance: "LOCKFILE",
      source: "seed-lab-supply-chain",
      observed_at: "2026-09-12T10:00:00Z",
      status: "OBSERVED",
      status_basis: "",
    },
    {
      id: "comp-bbb",
      type: "LIBRARY",
      ecosystem: "pypi",
      namespace: "",
      name: "requests",
      version: "2.31.0",
      requested_version: "",
      resolved_version: "",
      digest: "",
      source_revision: "",
      license: "Apache-2.0",
      license_source: "declared",
      provenance: "MANIFEST",
      source: "seed-lab-supply-chain",
      observed_at: "2026-09-12T10:00:00Z",
      status: "VERIFIED",
      status_basis: "lockfile digest recorded",
    },
  ],
};

const EDGES = {
  data: [
    {
      parent_id: "comp-bbb",
      parent_kind: "component",
      child_id: "comp-aaa",
      kind: "DEPENDS_ON",
      source: "seed-lab-supply-chain",
      observed_at: "2026-09-12T10:00:00Z",
    },
  ],
};

const SBOMS = {
  data: [
    {
      id: "sbom-1",
      format: "CycloneDX",
      format_version: "1.5",
      component_ids: ["comp-aaa"],
      generated_at: "2026-09-12T10:00:00Z",
      source: "seed-lab-supply-chain",
      digest: "",
    },
  ],
};

const POLICIES = {
  data: [
    {
      id: "pol-npm-only",
      name: "npm only",
      source: "seed-lab-supply-chain",
      allowed_ecosystems: ["npm"],
      allowed_licenses: [],
      allowed_provenance: [],
      require_digest: false,
      min_versions: {},
      prohibited: [],
      require_sbom: false,
      approved_repos: [],
    },
  ],
};

const VENDORS = {
  data: [
    {
      id: "vend-1",
      name: "Example CDN",
      service: "edge cache",
      category: "hosting",
      environment: "lab",
      status: "ACTIVE",
      source: "seed-lab-supply-chain",
      observed_at: "2026-09-12T10:00:00Z",
    },
  ],
};

const ASSESSMENTS = {
  data: [
    {
      id: "vass-1",
      vendor_id: "vend-1",
      status: "REVIEWED",
      assessor: "seed-lab-supply-chain",
      observed_at: "2026-09-12T10:00:00Z",
      evidence_ids: ["ev-1"],
      note: "",
    },
  ],
};

const LINKS = {
  data: [
    {
      id: "slink-1",
      control_id: "SC-1",
      subject_kind: "component",
      subject_id: "comp-aaa",
      basis: "component observed in lab manifest",
    },
  ],
};

const CHECKS = {
  data: [
    {
      rule_id: "supply-missing-sbom",
      version: "1",
      subject_id: "comp-aaa",
      outcome: "NOT_APPLICABLE",
      basis: "SBOM coverage not required by configuration",
    },
  ],
};

const HISTORY = {
  data: [
    {
      id: "shist-1",
      occurred_at: "2026-09-12T10:00:00Z",
      kind: "component",
      subject_id: "comp-aaa",
      summary: "npm/left-pad@1.0.0 OBSERVED",
    },
  ],
};

function mockAll() {
  mockApi({
    "/api/v1/supply-chain/components": COMPONENTS,
    "/api/v1/supply-chain/dependencies": EDGES,
    "/api/v1/supply-chain/sboms": SBOMS,
    "/api/v1/supply-chain/policies": POLICIES,
    "/api/v1/supply-chain/links": LINKS,
    "/api/v1/third-party/vendors": VENDORS,
    "/api/v1/third-party/assessments": ASSESSMENTS,
    "/api/v1/continuous-security/checks": CHECKS,
    "/api/v1/continuous-security/history": HISTORY,
  });
}

describe("SupplyChain view", () => {
  it("lists components with verbatim licenses", async () => {
    mockAll();
    render(<SupplyChain />);
    expect(await screen.findByText("left-pad")).toBeInTheDocument();
    expect(screen.getByText("requests")).toBeInTheDocument();
    // License renders exactly as declared.
    expect(screen.getByText("MIT")).toBeInTheDocument();
  });

  it("filters components by status and shows dependency edges in detail", async () => {
    mockAll();
    const user = userEvent.setup();
    render(<SupplyChain />);
    await screen.findByText("left-pad");
    const status = screen.getByLabelText("Status");
    await user.selectOptions(status, "OBSERVED");
    await waitFor(() => {
      expect(screen.queryByText("requests")).not.toBeInTheDocument();
    });
    expect(screen.getByText("left-pad")).toBeInTheDocument();
    // Detail drawer cites explicit edges, never inferred links: left-pad
    // is used by requests via a declared DEPENDS_ON edge.
    await user.click(screen.getByText("left-pad"));
    expect(await screen.findByText("Used by")).toBeInTheDocument();
    expect(screen.getByText("comp-bbb")).toBeInTheDocument();
    expect(screen.getAllByText("DEPENDS_ON").length).toBeGreaterThan(0);
  });

  it("shows third-party vendors without trust states", async () => {
    mockAll();
    const user = userEvent.setup();
    render(<SupplyChain />);
    await screen.findByText("left-pad");
    await user.click(screen.getByRole("tab", { name: "Third Party" }));
    expect(await screen.findByText("Example CDN")).toBeInTheDocument();
    expect(screen.getByText("REVIEWED")).toBeInTheDocument();
    expect(screen.queryByText(/trusted/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secure/i)).not.toBeInTheDocument();
  });

  it("shows continuous checks and derived history", async () => {
    mockAll();
    const user = userEvent.setup();
    render(<SupplyChain />);
    await screen.findByText("left-pad");
    await user.click(screen.getByRole("tab", { name: "Continuous" }));
    expect(await screen.findByText("supply-missing-sbom")).toBeInTheDocument();
    expect(screen.getByText("NOT_APPLICABLE")).toBeInTheDocument();
    expect(
      screen.getByText(/npm\/left-pad@1\.0\.0 OBSERVED/),
    ).toBeInTheDocument();
  });

  it("shows SBOM, policy, and link tabs", async () => {
    mockAll();
    const user = userEvent.setup();
    render(<SupplyChain />);
    await screen.findByText("left-pad");
    await user.click(screen.getByRole("tab", { name: "SBOMs" }));
    expect(await screen.findByText("CycloneDX")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Policies" }));
    expect(await screen.findByText("pol-npm-only")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Links" }));
    expect(await screen.findByText("SC-1")).toBeInTheDocument();
  });
});
