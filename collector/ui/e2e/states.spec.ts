import { expect, test } from "@playwright/test";

// Runs against a FRESH database (port 18081): every view must render its
// honest empty state — never a blank page, never fake rows.
const EMPTY = "http://127.0.0.1:18081";
// Runs against a CORRUPTED database (port 18082): evidence digest mismatch
// must surface as an integrity error, never an empty table.
const CORRUPT = "http://127.0.0.1:18082";

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

test("empty database renders honest empty states", async ({ page }) => {
  await page.goto(`${EMPTY}/#/overview`);
  await expect(page.getByText("No data yet")).toBeVisible();
  await page.goto(`${EMPTY}/#/incidents`);
  await expect(page.getByText("No incidents")).toBeVisible();
  await page.goto(`${EMPTY}/#/evidence`);
  await expect(page.getByText("No evidence")).toBeVisible();
  await page.goto(`${EMPTY}/#/validation`);
  await expect(page.getByText("No validation results")).toBeVisible();
  await page.goto(`${EMPTY}/#/responses`);
  await expect(page.getByText("No responses")).toBeVisible();
});

test("corrupted evidence surfaces integrity failure, not empty", async ({
  page,
}) => {
  await page.goto(`${CORRUPT}/#/evidence`);
  await expect(page.getByText("Integrity check failed")).toBeVisible();
  await expect(page.getByText("No evidence")).toHaveCount(0);
});
