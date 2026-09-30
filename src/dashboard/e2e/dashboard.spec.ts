import { expect, test } from "@playwright/test";

test.describe("Dashboard shell", () => {
  test("page loads with brand title", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".brand strong")).toHaveText("AgentGuardian");
  });

  test("status bar shows three indicators", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".status-pill")).toHaveCount(3);
  });

  test("status bar shows session chip", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".session-chip")).toBeVisible();
  });
});

test.describe("Metrics grid", () => {
  test("four metric cards rendered", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".metric-card")).toHaveCount(4);
  });

  test("metric cards show default values", async ({ page }) => {
    await page.goto("/");
    const values = page.locator(".metric-card strong");
    await expect(values.nth(0)).toContainText("ms");
    await expect(values.nth(3)).toHaveText("0");
  });
});

test.describe("Workspace panels", () => {
  test("call chain panel shows empty state", async ({ page }) => {
    await page.goto("/");
    const chain = page.locator(".call-chain .empty-state");
    await expect(chain).toHaveText("No tool calls yet");
  });

  test("taint panel shows empty state", async ({ page }) => {
    await page.goto("/");
    const taint = page.locator(".taint-panel .empty-state");
    await expect(taint).toHaveText("No taint tags detected");
  });

  test("event stream shows waiting message", async ({ page }) => {
    await page.goto("/");
    const stream = page.locator(".event-stream .empty-state");
    await expect(stream).toHaveText("Waiting for /ws/events");
  });

  test("config panel shows textarea", async ({ page }) => {
    await page.goto("/");
    const editor = page.locator(".config-editor textarea");
    await expect(editor).toBeVisible();
  });
});

test.describe("Alert banner", () => {
  test("shows quiet state on load", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".alert-banner.quiet")).toBeVisible();
    await expect(page.locator(".alert-banner.quiet span")).toContainText(
      "没有高优先级阻断告警",
    );
  });
});

test.describe("Responsive layout", () => {
  test("renders without error at mobile width", async ({ page }) => {
    await page.setViewportSize({ width: 480, height: 800 });
    await page.goto("/");
    await expect(page.locator(".brand strong")).toBeVisible();
  });

  test("renders at tablet width", async ({ page }) => {
    await page.setViewportSize({ width: 900, height: 700 });
    await page.goto("/");
    await expect(page.locator(".metrics-grid")).toBeVisible();
  });
});
