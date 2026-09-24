import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StatusBadge } from "./StatusBadge";
import { StatCard } from "./StatCard";
import { EmptyState } from "./States";
import { SummaryStrip } from "./SummaryStrip";

afterEach(() => cleanup());

describe("shared chrome", () => {
  it("renders outline status badge without severity colors", () => {
    render(<StatusBadge value="ALERT_STATUS_OPEN" tone="info" outline />);
    const el = screen.getByText("OPEN");
    expect(el.className).toContain("outline");
    expect(el.className).not.toContain("critical");
  });

  it("renders linked stat card with delta", async () => {
    const user = userEvent.setup();
    render(
      <StatCard
        label="Findings"
        value={12}
        caption="3 critical"
        delta="▲ +2 vs last week"
        deltaTone="bad"
        href="#/findings"
      />,
    );
    expect(screen.getByText("▲ +2 vs last week")).toBeInTheDocument();
    const link = screen.getByRole("link");
    expect(link.getAttribute("href")).toBe("#/findings");
    await user.click(link);
  });

  it("renders empty state with action button", async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    render(
      <EmptyState
        icon="shield"
        title="No assets"
        description="Nothing observed yet."
        action={{ label: "Seed the lab", onClick }}
      />,
    );
    await user.click(screen.getByRole("button", { name: "Seed the lab" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("renders summary strip with statement, stats, and viz", () => {
    render(
      <SummaryStrip
        statement="2 outdated dependencies raise supply-chain risk."
        stats={[
          { label: "Components", value: "8", href: "#/supply-chain" },
          { label: "Policies failing", value: "1" },
        ]}
        viz={<span data-testid="viz">viz</span>}
      />,
    );
    expect(
      screen.getByText("2 outdated dependencies raise supply-chain risk."),
    ).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByTestId("viz")).toBeInTheDocument();
  });
});
