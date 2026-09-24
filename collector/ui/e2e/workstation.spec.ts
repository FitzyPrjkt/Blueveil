import { expect, test } from "@playwright/test";

const errors: string[] = [];
test.beforeEach(({ page }) => {
  errors.length = 0;
  page.on("console", (msg) => {
    // Intentionally-failing requests (backend-error states under test)
    // surface as resource-load noise; real JS errors still fail the test.
    if (
      msg.type() === "error" &&
      !msg.text().startsWith("Failed to load resource")
    )
      errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(String(err)));
});

test.afterEach(() => {
  expect(errors, `console errors: ${errors.join(" | ")}`).toEqual([]);
});

test("workstation shell loads with navigation", async ({ page }) => {
  await page.goto("/#/overview");
  await expect(page.getByText("Blueveil", { exact: true })).toBeVisible();
  for (const label of [
    "Overview",
    "Findings",
    "Incidents",
    "Assets",
    "Network",
    "Application",
    "Infrastructure",
    "Identity",
    "Monitoring",
    "Investigations",
    "Governance",
    "Evidence",
    "Validation",
    "Responses",
  ]) {
    await expect(
      page.getByRole("button", { name: label }).first(),
    ).toBeVisible();
  }
});

test("overview shows real counts", async ({ page }) => {
  await page.goto("/#/overview", { waitUntil: "networkidle" });
  await expect(page.getByText("Telemetry Events")).toBeVisible();
  await expect(page.getByText("Open Incidents")).toBeVisible();
  await expect(page.locator(".stat-value")).toHaveCount(7);
  // Seeded: 72 telemetry, 32 detections, 32 alerts, 23 incidents,
  // 36 assets, 135 evidence, 11 validation results (3 pre-campaign + 8 campaign).
  await expect
    .poll(
      async () =>
        (await page.locator(".stat-value").allTextContents()).map((v) =>
          v.trim(),
        ),
      { timeout: 7000 },
    )
    .toEqual(["72", "32", "32", "23", "36", "135", "11"]);
});

test("findings search and filter narrow rows", async ({ page }) => {
  await page.goto("/#/findings");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(32);
  await page.getByLabel("Search findings").fill("burst");
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await page.getByLabel("Search findings").fill("");
  // Filter to a severity with no rows — seeded findings cover HIGH, MEDIUM, LOW;
  // CRITICAL has no rows, so the empty state is honest.
  await page
    .getByLabel("Severity", { exact: true })
    .selectOption("SEVERITY_CRITICAL");
  await expect(page.getByText("No matching findings")).toBeVisible();
});

test("assets inventory: search, filter, detail, relationships", async ({
  page,
}) => {
  await page.goto("/#/assets");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(36);
  // Search narrows to the domain and URLs.
  await page.getByLabel("Search assets").fill("seed-lab.example");
  await expect(page.locator("tbody tr")).toHaveCount(8);
  await page.getByLabel("Search assets").fill("");
  // Type filter isolates the single domain.
  await page
    .getByLabel("Type", { exact: true })
    .selectOption("ASSET_TYPE_DOMAIN");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Type", { exact: true }).selectOption("ALL");
  // Stale-only toggle: seeded assets are all DISCOVERED → honest empty.
  await page.getByText("Stale only", { exact: false }).click();
  await expect(page.getByText("No matching assets")).toBeVisible();
  await page.getByText("Stale only", { exact: false }).click();
  // Detail drawer: identity, lifecycle, relationships.
  await page
    .getByLabel("Type", { exact: true })
    .selectOption("ASSET_TYPE_DOMAIN");
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Lifecycle" })).toBeVisible();
  await expect(page.getByText("Contains", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("network workspace: observations, filters, detail, relationships", async ({
  page,
}) => {
  await page.goto("/#/network");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(11);
  // Search narrows to the disallowed destination.
  await page.getByLabel("Search network").fill("203.0.113.7");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Search network").fill("");
  // Protocol filter
  await page.getByLabel("Protocol").selectOption("TCP");
  await expect(page.locator("tbody tr")).toHaveCount(8);
  // Detected-only narrows to the 7 detected observations (normal is the only undetected).
  await page.getByLabel("Detected only").check();
  await expect(page.locator("tbody tr")).toHaveCount(7);
  await page.getByLabel("Detected only").uncheck();
  // Detail drawer: source, verdict, asset correlation, detection provenance.
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Asset correlation")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Detection" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("application workspace: observations, filters, detail, relationships", async ({
  page,
}) => {
  await page.goto("/#/application");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(12);
  await page.getByLabel("Search application").fill("seed-lab.example");
  await expect(page.locator("tbody tr")).toHaveCount(11);
  await page.getByLabel("Search application").fill("/admin");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Search application").fill("");
  await page.getByLabel("Method").selectOption("TRACE");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Method").selectOption("ALL");
  await page.getByLabel("Detected only").check();
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await page.getByLabel("Detected only").uncheck();
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Asset" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Detection" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("infrastructure workspace: endpoint, server, container, cloud", async ({
  page,
}) => {
  await page.goto("/#/infrastructure");
  await expect(page.getByRole("button", { name: "Endpoint" })).toBeVisible();
  // Endpoint tab: 5 observations (3 lab + 2 monitoring)
  await page.getByRole("button", { name: "Endpoint" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(6);
  await page.getByRole("button", { name: "Server" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.getByRole("button", { name: "Container" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByLabel("Search container").fill("cnt-002");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Search container").fill("");
  await page.getByRole("button", { name: "Cloud" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.getByLabel("Search cloud").fill("user-02");
  await expect(page.locator("tbody tr")).toHaveCount(3);
  await page.getByLabel("Search cloud").fill("");
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("identity workspace: identity, authentication, data", async ({ page }) => {
  await page.goto("/#/identity");
  await expect(
    page.getByRole("button", { name: "Identity" }).first(),
  ).toBeVisible();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.getByRole("button", { name: "Authentication" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(14);
  await page.getByLabel("Outcome").selectOption("failure");
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await page.getByLabel("Outcome").selectOption("ALL");
  await page.getByRole("button", { name: "Data" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.getByLabel("Search identity").fill("customers");
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByLabel("Search identity").fill("");
  await page.getByLabel("Detected only").check();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Detection" })).toBeVisible();
  await expect(page.getByRole("dialog").getByText("customers")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("monitoring workspace: events, correlations, rules, threat intel", async ({
  page,
}) => {
  await page.goto("/#/monitoring");
  await expect(page.getByRole("button", { name: "Events" })).toBeVisible();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(72);
  await page.getByLabel("Event type").selectOption("auth.activity");
  await expect(page.locator("tbody tr")).toHaveCount(14);
  await page.getByLabel("Event type").selectOption("ALL");
  await page.getByRole("button", { name: "Correlations" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(5);
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provenance" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await page.getByRole("button", { name: "Rules" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(23);
  await page.getByRole("button", { name: "Health" }).click();
  await expect(page.getByText("Rule health not available")).toBeVisible();
  await page.getByRole("button", { name: "Threat Intel" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(3);
  await page.getByLabel("Search matches").fill("203.0.113.7");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Search matches").fill("");
});

test("investigations workspace: hunting, timeline, forensics", async ({
  page,
}) => {
  await page.goto("/#/investigations");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(72);
  await page.getByLabel("Search hunting").fill("seed-lab-investigation");
  await expect(page.locator("tbody tr")).toHaveCount(8);
  await page.getByLabel("Search hunting").fill("zzz-no-such");
  await expect(page.getByText("No hunting results")).toBeVisible();
  await page.getByLabel("Search hunting").fill("");
  await page.getByRole("button", { name: "Timeline" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provenance" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await page.getByRole("button", { name: "Forensics" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  const workspace = page.locator("main");
  await workspace.getByRole("button", { name: "Network", exact: true }).click();
  await expect(page.getByText("evt-seed-inv-net-001")).toBeVisible();
  await workspace
    .getByRole("button", { name: "Identity", exact: true })
    .click();
  await expect(page.getByText("evt-seed-inv-auth-001")).toBeVisible();
});

test("governance workspace: controls, assessments, architecture, resilience", async ({
  page,
}) => {
  await page.goto("/#/governance");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(8);
  await expect(page.getByText("Authentication required")).toBeVisible();
  await page.getByRole("tab", { name: "Assessments" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(6);
  const table = page.locator("table");
  await expect(table.getByText("COMPLIANT", { exact: true })).toBeVisible();
  await page.getByLabel("Status").selectOption("NON_COMPLIANT");
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.getByLabel("Status").selectOption("ALL");
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provenance" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await page.getByRole("tab", { name: "Architecture" }).click();
  await expect(page.getByText("web01")).toBeVisible();
  await page.getByRole("tab", { name: "Resilience" }).click();
  await expect(page.getByText("READY")).toBeVisible();
  await expect(page.getByText("NOT_ASSESSED")).toBeVisible();
  await expect(page.getByText(/100% secure/i)).toHaveCount(0);
  await expect(page.getByText("SECURE", { exact: true })).toHaveCount(0);
});

test("incident drawer shows the relationship chain", async ({ page }) => {
  await page.goto("/#/incidents");
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByText("Incident → Alert → Detection → Telemetry"),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Lifecycle" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
});

test("evidence renders plain-text content with integrity", async ({ page }) => {
  await page.goto("/#/evidence");
  await expect(page.getByText("VERIFIED").first()).toBeVisible();
  await page.locator("tbody tr").first().click();
  const pre = page.locator("pre.evidence-content");
  await expect(pre).toBeVisible();
  // Content is text, never executed HTML: no script elements inside.
  expect(await pre.locator("script").count()).toBe(0);
});

test("validation verdicts verbatim incl NOT_TESTED and UNKNOWN", async ({
  page,
}) => {
  await page.goto("/#/validation");
  for (const v of [
    "PREVENTED",
    "DETECTED",
    "ALLOWED AND NOT DETECTED",
    "UNKNOWN",
    "NOT TESTED",
    "RATE LIMITED",
  ]) {
    await expect(page.getByText(v).first()).toBeVisible();
  }
  await expect(page.getByText("NOT TESTED").first()).toBeVisible();
  await page.locator("tbody tr", { hasText: "NOT TESTED" }).first().click();
  await expect(
    page.getByRole("heading", { name: "Validation was not performed" }),
  ).toBeVisible();
  await expect(page.getByText("SECURE", { exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape");
});

test("validation campaigns and purple team read honestly", async ({ page }) => {
  await page.goto("/#/validation");
  await page.getByRole("tab", { name: "Campaigns" }).click();
  await expect(page.getByText("seed-lab-validation")).toBeVisible();
  await expect(page.getByText("COMPLETED")).toBeVisible();
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Provider errors")).toBeVisible();
  // Counts only: no pass rates or scores anywhere.
  await expect(page.getByText(/pass rate/i)).toHaveCount(0);
  await expect(page.getByText(/coverage/i)).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.getByRole("tab", { name: "Purple Team" }).click();
  await expect(page.getByText("seed-lab-validation exercise")).toBeVisible();
  await page.locator("tbody tr").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("DETECTED", { exact: true })).toBeVisible();
  await expect(page.getByText(/COMPROMISED/)).toHaveCount(0);
  await expect(page.getByText(/BREACHED/)).toHaveCount(0);
  await page.keyboard.press("Escape");
});

test("responses show gated timeline, read-only", async ({ page }) => {
  await page.goto("/#/responses");
  await page.locator("tbody tr").first().click();
  await expect(page.locator(".timeline")).toBeVisible();
  const buttons = await page.locator("button").allTextContents();
  for (const label of ["block", "isolate", "delete", "execute"]) {
    expect(buttons.some((t) => t.toLowerCase().includes(label))).toBe(false);
  }
});

test("command palette jumps between views", async ({ page }) => {
  await page.goto("/#/overview");
  await page.keyboard.press("Control+k");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page
    .getByLabel("Search commands, findings, incidents")
    .fill("incidents");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#\/incidents/);
});

test("theme toggle switches data-theme", async ({ page }) => {
  await page.goto("/#/overview");
  const html = page.locator("html");
  const before = await html.getAttribute("data-theme");
  await page.getByLabel(/dark mode|light mode/).click();
  const after = await html.getAttribute("data-theme");
  expect(after).not.toBe(before);
  await expect
    .poll(async () =>
      page.evaluate(() => localStorage.getItem("blueveil-theme")),
    )
    .toBe(after);
});
