import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { webkit } from "playwright";
import { startFixture } from "./preview.mjs";

let fixture, browser, page;
const errors = [];
before(async () => {
  fixture = await startFixture(0);
  browser = await webkit.launch();
  await mkdir("test-results", { recursive: true });
});
after(async () => {
  await browser?.close();
  await fixture?.close();
});
beforeEach(async () => {
  await page?.close();
  fixture.reset();
  errors.length = 0;
  page = await browser.newPage({ viewport: { width: 1280, height: 840 } });
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(fixture.url);
  await page.locator(".secret-row").first().waitFor();
});
const click = (action) =>
  page.locator(`[data-action="${action}"]`).first().click();
const choose = (name) =>
  page.locator(`.secret-row[data-name="${name}"]`).click();
const submit = () => page.locator('dialog button[type="submit"]').click();
const closed = () => page.locator("dialog").waitFor({ state: "hidden" });
const nativeAction = async (action) => {
  await Promise.all([
    page.waitForResponse(
      (res) => res.url().endsWith("/ui-api/" + action) && res.status() === (action === "download" ? 200 : 204),
    ),
    click(action),
  ]);
};

test("malformed server metadata cannot inject HTML or expose stale secret details", async () => {
  await choose("personal/github/token");
  for (const versions of [['<span id="metadata-injection">marker</span>'], [0], [-1], [4294967296], ['1'], [1, 1]]) {
    await page.route('**/ui-api/list', async route => {
      const response = await route.fetch();
      const data = await response.json();
      data[0].Versions = versions;
      await route.fulfill({ response, json: data });
    });
    await click('refresh');
    await page.getByText('Setec returned invalid secret metadata.', { exact: true }).waitFor();
    assert.equal(await page.locator('#metadata-injection').count(), 0);
    assert.equal(await page.locator('.secret-row').count(), 0);
    assert.equal(await page.locator('.version-row').count(), 0);
    await page.unroute('**/ui-api/list');
    await click('refresh');
    await page.locator('.secret-row').first().waitFor();
    await choose("personal/github/token");
  }
  assert.equal(errors.length, 0);
});

test("only metadata loads initially; reveal, mask, search, paths, keyboard, and responsive layout", async () => {
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  await choose("platform/production/database-url");
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  await page.screenshot({
    path: "test-results/vault-desktop.png",
    fullPage: true,
  });
  await click("reveal");
  await page.getByText("sample-rotated-value", { exact: true }).waitFor();
  await click("reveal");
  assert.match(await page.locator("#secret-value").textContent(), /•/);
  const reads = fixture.calls.filter((c) => c.op === "get").length;
  await nativeAction("copy");
  assert.equal(fixture.clipboard, "sample-rotated-value");
  await nativeAction("copy-path");
  assert.equal(fixture.clipboard, "platform/production/database-url");
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, reads);
  await page.keyboard.press("Control+k");
  assert.equal(
    await page
      .locator("#search")
      .evaluate((el) => el === document.activeElement),
    true,
  );
  await page.locator("#search").fill("cloudflare");
  assert.equal(await page.locator(".secret-row").count(), 1);
  await page.locator('[data-action="path"][data-path="personal"]').click();
  assert.equal(await page.locator(".secret-row").count(), 3);
  const personalChildren = page.locator('[data-action="path"][data-path="personal/github"]');
  await page.getByRole("button", { name: "Collapse personal", exact: true }).click();
  assert.equal(await personalChildren.isVisible(), false);
  await page.getByRole("button", { name: "personal", exact: true }).click();
  assert.equal(await personalChildren.isVisible(), true);
  assert.equal(await page.getByRole("button", { name: "Collapse personal", exact: true }).getAttribute("aria-expanded"), "true");
  await page.getByRole("button", { name: "personal", exact: true }).click();
  assert.equal(await personalChildren.isVisible(), true);
  assert.equal(await page.locator(".secret-row").count(), 3);
  await page.setViewportSize({ width: 860, height: 620 });
  await page.screenshot({
    path: "test-results/vault-compact.png",
    fullPage: true,
  });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    true,
  );
  assert.deepEqual(errors, []);
});

test("create, stage an edit, activate, import a version, and confirm deletion", async () => {
  await click("new");
  assert.equal(await page.getByRole("checkbox", { name: "Activate this version after saving" }).count(), 0);
  await page.locator('input[name="name"]').fill("personal/tests/new-key");
  await page.locator("textarea").fill("first-value");
  await submit();
  await closed();
  assert.equal(fixture.secrets.get("personal/tests/new-key").ActiveVersion, 1);
  assert.equal(fixture.calls.some((c) => c.op === "activate"), false);
  await click("edit");
  assert.equal(await page.getByRole("checkbox", { name: "Activate this version after saving" }).isChecked(), false);
  await page.locator("textarea").fill("second-value");
  await submit();
  await closed();
  assert.equal(fixture.secrets.get("personal/tests/new-key").ActiveVersion, 1);
  assert.deepEqual(
    Object.keys(fixture.secrets.get("personal/tests/new-key").Values),
    ["1", "2"],
  );
  await page.getByRole("tab", { name: /Versions/ }).click();
  await click("activate");
  await submit();
  await closed();
  assert.equal(fixture.secrets.get("personal/tests/new-key").ActiveVersion, 2);
  await click("import");
  assert.equal(await page.getByRole("checkbox", { name: "Activate this version after saving" }).count(), 0);
  await page.locator('input[name="version"]').fill("10");
  await page.locator("textarea").fill("imported");
  await submit();
  await closed();
  assert.equal(fixture.secrets.get("personal/tests/new-key").ActiveVersion, 10);
  await page.getByRole("tab", { name: /Versions/ }).click();
  await click("delete-version");
  await page.locator('input[name="confirm"]').fill("wrong");
  await submit();
  await page.locator("#form-error").waitFor();
  await page.locator('input[name="confirm"]').fill("personal/tests/new-key");
  await submit();
  await closed();
  assert.equal(
    Object.keys(fixture.secrets.get("personal/tests/new-key").Values).length,
    2,
  );
  await click("delete");
  await page.locator('input[name="confirm"]').fill("personal/tests/new-key");
  await submit();
  await closed();
  assert.equal(fixture.secrets.has("personal/tests/new-key"), false);
  assert.deepEqual(errors, []);
});

test("multiple versions can be compared and hidden independently without activation", async () => {
  const name = "platform/production/database-url";
  await choose(name);
  await page.getByRole("tab", { name: /Versions/ }).click();
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  assert.equal(await page.locator(".version-value:visible").count(), 0);
  await page.getByRole("button", { name: "Reveal version 3", exact: true }).click();
  await page.getByText("sample-next-value", { exact: true }).waitFor();
  assert.equal(await page.locator("#version-value-3").textContent(), "sample-next-value");
  await page.getByRole("button", { name: "Reveal version 2", exact: true }).click();
  await page.getByText("sample-rotated-value", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
  await page.getByText("sample-value-for-testing", { exact: true }).waitFor();
  assert.equal(await page.locator("#version-value-3").textContent(), "sample-next-value");
  assert.equal(await page.locator(".version-value:visible").count(), 3);
  assert.equal(fixture.secrets.get(name).ActiveVersion, 2);
  assert.equal(fixture.calls.some((c) => c.op === "activate"), false);
  const screenshotOptions = { fullPage: true, animations: "disabled" };
  await page.screenshot({ path: "test-results/version-reveal-light.png", ...screenshotOptions });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.screenshot({ path: "test-results/version-reveal-dark.png", ...screenshotOptions });
  await page.setViewportSize({ width: 920, height: 620 });
  await page.screenshot({ path: "test-results/version-reveal-compact.png", ...screenshotOptions });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.getByRole("button", { name: "Hide version 1", exact: true }).click();
  assert.equal(await page.locator("#version-value-1").textContent(), "");
  assert.equal(await page.locator("#version-value-3").textContent(), "sample-next-value");
  assert.equal(await page.locator("#version-value-2").textContent(), "sample-rotated-value");
  assert.equal(await page.locator(".version-value:visible").count(), 2);
  await page.getByRole("button", { name: "Hide version 3", exact: true }).click();
  await page.getByRole("button", { name: "Hide version 2", exact: true }).click();
  assert.equal(await page.locator(".version-value:visible").count(), 0);
  assert.deepEqual(fixture.calls.filter((c) => c.op === "get"), [
    { op: "get", Name: name, Version: 3 },
    { op: "get", Name: name, Version: 2 },
    { op: "get", Name: name, Version: 1 },
  ]);
  assert.deepEqual(errors, []);
});

test("version values clear on timeout, blur, navigation, and activation confirmation", async () => {
  await page.clock.install();
  await page.reload();
  await choose("platform/production/database-url");
  await page.getByRole("tab", { name: /Versions/ }).click();
  const reveal = async () => {
    await page.getByRole("button", { name: "Reveal version 3", exact: true }).click();
    await page.getByText("sample-next-value", { exact: true }).waitFor();
    await page.clock.fastForward(10000);
    await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
    await page.getByText("sample-value-for-testing", { exact: true }).waitFor();
  };
  const cleared = async () => {
    assert.equal(await page.locator(".version-value:visible").count(), 0);
    assert.doesNotMatch(await page.locator("#app").textContent(), /sample-next-value|sample-value-for-testing/);
  };
  await reveal();
  await page.clock.fastForward(20001);
  assert.equal(await page.locator("#version-value-3").textContent(), "");
  assert.equal(await page.locator("#version-value-1").textContent(), "sample-value-for-testing");
  await page.clock.fastForward(10000);
  await cleared();
  await reveal();
  await page.evaluate(() => window.dispatchEvent(new Event("blur")));
  await cleared();
  await reveal();
  await page.locator('[data-action="activate"][data-version="3"]').click();
  await page.getByRole("heading", { name: "Activate version 3?" }).waitFor();
  await cleared();
  await click("close-dialog");
  await reveal();
  await page.getByRole("tab", { name: "Overview", exact: true }).click();
  await cleared();
  await page.getByRole("tab", { name: /Versions/ }).click();
  await reveal();
  await click("lock");
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  await cleared();
  assert.equal(fixture.calls.some((c) => c.op === "activate"), false);
  assert.deepEqual(errors, []);
});

test("late version reads cannot reappear after hiding, switching, opening a dialog, or locking", async () => {
  for (const action of ["hide", "secret", "tab", "dialog", "blur", "lock"]) {
    await page.reload();
    await choose("platform/production/database-url");
    await page.getByRole("tab", { name: /Versions/ }).click();
    let release;
    const held = new Promise((resolve) => { release = resolve; });
    await page.route("**/ui-api/get", async (route) => {
      if (route.request().postDataJSON().Version === 3) await held;
      await route.continue();
    });
    await Promise.all([
      page.waitForRequest((req) => req.url().endsWith("/ui-api/get") && req.postDataJSON().Version === 3),
      page.getByRole("button", { name: "Reveal version 3", exact: true }).click(),
    ]);
    switch (action) {
      case "hide":
        await page.getByRole("button", { name: "Hide version 3", exact: true }).click();
        break;
      case "secret": await choose("personal/github/token"); break;
      case "tab": await page.getByRole("tab", { name: "Overview", exact: true }).click(); break;
      case "dialog": await page.locator('[data-action="activate"][data-version="3"]').click(); break;
      case "blur": await page.evaluate(() => window.dispatchEvent(new Event("blur"))); break;
      case "lock":
        await click("lock");
        await page.getByRole("button", { name: "Open vault" }).waitFor();
        break;
    }
    release();
    await page.unrouteAll({ behavior: "wait" });
    await page.waitForLoadState("networkidle");
    assert.doesNotMatch(await page.locator("#app").textContent(), /sample-next-value/, action);
    assert.equal(await page.locator(".version-value:visible").count(), 0, action);
  }
  assert.deepEqual(errors, []);
});

test("concurrent version reads finish independently and canceled reads cannot overwrite a newer reveal", async () => {
  for (const action of ["keep", "hide", "reveal-again"]) {
    fixture.reset();
    await page.reload();
    const name = "platform/production/database-url";
    await choose(name);
    await page.getByRole("tab", { name: /Versions/ }).click();
    let release, captured, first = true;
    const held = new Promise((resolve) => { release = resolve; });
    const ready = new Promise((resolve) => { captured = resolve; });
    await page.route("**/ui-api/get", async (route) => {
      if (route.request().postDataJSON().Version !== 3 || !first)
        return route.continue();
      first = false;
      const response = await route.fetch();
      captured();
      await held;
      await route.fulfill({ response });
    });
    await page.getByRole("button", { name: "Reveal version 3", exact: true }).click();
    await ready;
    assert.match(await page.locator("#version-value-3").textContent(), /^•+$/);
    assert.equal(await page.locator("#version-value-3").getAttribute("aria-busy"), "true");
    await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
    await page.getByText("sample-value-for-testing", { exact: true }).waitFor();
    if (action !== "keep") {
      await page.getByRole("button", { name: "Hide version 3", exact: true }).click();
      assert.equal(await page.locator("#version-value-3").textContent(), "");
    }
    if (action === "reveal-again") {
      fixture.secrets.get(name).Values[3] = Buffer.from("newer-sample-value").toString("base64");
      await page.getByRole("button", { name: "Reveal version 3", exact: true }).click();
      await page.getByText("newer-sample-value", { exact: true }).waitFor();
    }
    release();
    await page.unrouteAll({ behavior: "wait" });
    await page.waitForLoadState("networkidle");
    assert.equal(await page.locator("#version-value-3").textContent(),
      action === "keep" ? "sample-next-value" : action === "hide" ? "" : "newer-sample-value");
    assert.equal(await page.locator("#version-value-1").textContent(), "sample-value-for-testing");
    assert.equal(await page.locator("#version-value-3").getAttribute("aria-busy"), null);
  }
  assert.deepEqual(errors, []);
});

test("overview keeps its dots while fetching and displays the value once it arrives", async () => {
  await choose("platform/production/database-url");
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await page.route("**/ui-api/get", async (route) => {
    await held;
    await route.continue();
  });
  await click("reveal");
  assert.match(await page.locator("#secret-value").textContent(), /^•+$/);
  assert.match(await page.locator("#secret-value").getAttribute("class"), /masked/);
  assert.equal(await page.locator("#secret-value").getAttribute("aria-busy"), "true");
  release();
  await page.getByText("sample-rotated-value", { exact: true }).waitFor();
  assert.doesNotMatch(await page.locator("#secret-value").getAttribute("class"), /masked/);
  assert.equal(await page.locator("#secret-value").getAttribute("aria-busy"), null);
  assert.deepEqual(errors, []);
});

test("version reveals handle denied reads, binary and empty values, and HTML as text", async () => {
  const name = "personal/github/token";
  fixture.secrets.get(name).Values = {
    1: Buffer.from([0, 255, 1]).toString("base64"),
    2: "",
    3: Buffer.from('<img src=x onerror="alert(1)">').toString("base64"),
  };
  const deniedName = "finance/private/password";
  fixture.secrets.set(deniedName, { Name: deniedName, ActiveVersion: 1, Values: { 1: Buffer.from("denied-value").toString("base64") } });
  await click("refresh");
  await choose(name);
  await page.getByRole("tab", { name: /Versions/ }).click();
  await page.getByRole("button", { name: "Reveal version 2", exact: true }).click();
  await page.getByText("(empty value)", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
  await page.getByText("This is a binary secret. Use Download to preserve its bytes.").waitFor();
  assert.equal(await page.locator("#version-value-1").isVisible(), false);
  assert.equal(await page.locator("#version-value-2").textContent(), "(empty value)");
  await page.getByRole("button", { name: "Reveal version 3", exact: true }).click();
  await page.getByText('<img src=x onerror="alert(1)">', { exact: true }).waitFor();
  assert.equal(await page.locator(".version-value img").count(), 0);
  await choose(deniedName);
  await page.getByRole("tab", { name: /Versions/ }).click();
  await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
  await page.locator("#toast").getByText(/permissions/).waitFor();
  assert.equal(await page.locator("#version-value-1").textContent(), "");
  assert.equal(await page.locator(".version-value:visible").count(), 0);
  assert.deepEqual(errors, []);
});

test("uploads and downloads preserve binary bytes", async () => {
  const bytes = Buffer.from([0, 255, 254, 10, 13, 32, 1, 0, 128]);
  await click("new");
  await page.locator('input[name="name"]').fill("personal/tests/binary.key");
  await page.locator('input[type="file"]').setInputFiles({
    name: "binary.key",
    mimeType: "application/octet-stream",
    buffer: bytes,
  });
  await submit();
  await closed();
  assert.deepEqual(
    Buffer.from(
      fixture.secrets.get("personal/tests/binary.key").Values[1],
      "base64",
    ),
    bytes,
  );
  await nativeAction("download");
  assert.deepEqual(fixture.savedFiles, [
    { name: "personal/tests/binary.key", bytes },
  ]);
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  await click("reveal");
  await page
    .getByText("This is a binary secret. Use Download to preserve its bytes.")
    .waitFor();
  assert.match(await page.locator("#secret-value").textContent(), /•/);
  assert.deepEqual(errors, []);
});

test("denied paths and writes surface errors without leaking values or changing secrets", async () => {
  await choose("platform/production/database-url");
  await click("edit");
  await page.locator("textarea").fill("not-saved");
  await submit();
  await page.locator("#form-error").waitFor();
  assert.match(await page.locator("#form-error").textContent(), /permissions/);
  assert.equal(
    Object.keys(fixture.secrets.get("platform/production/database-url").Values)
      .length,
    3,
  );
  await click("close-dialog");
  const deniedName = "finance/private/password";
  fixture.secrets.set(deniedName, {
    Name: deniedName,
    ActiveVersion: 1,
    Values: { 1: Buffer.from("denied-sample-value").toString("base64") },
  });
  await click("refresh");
  await choose(deniedName);
  await click("reveal");
  await page.locator("#toast").waitFor();
  assert.match(await page.locator("#toast").textContent(), /permissions/);
  assert.match(await page.locator("#secret-value").textContent(), /•/);
  await Promise.all([
    page.waitForResponse(
      (res) => res.url().endsWith("/ui-api/download") && res.status() === 403,
    ),
    click("download"),
  ]);
  assert.deepEqual(fixture.savedFiles, []);
  await Promise.all([
    page.waitForResponse(
      (res) => res.url().endsWith("/ui-api/copy") && res.status() === 403,
    ),
    click("copy"),
  ]);
  assert.equal(fixture.clipboard, "");
  assert.deepEqual(errors, []);
});

test("untrusted names render as text; hiding clears data and reopening uses Tailscale", async () => {
  const name = "personal/<img src=x onerror=alert(1)>";
  fixture.secrets.set(name, {
    Name: name,
    ActiveVersion: 1,
    Values: { 1: Buffer.from("sample").toString("base64") },
  });
  await click("refresh");
  await page.getByRole("button", { name: /<img src=x/ }).click();
  assert.equal(await page.locator(".detail img").count(), 0);
  await click("lock");
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  assert.equal(await page.locator(".secret-row").count(), 0);
  assert.equal(await page.locator("dialog").innerHTML(), "");
  await page.screenshot({
    path: "test-results/hidden-vault.png",
    fullPage: true,
  });
  assert.deepEqual(errors, []);
});

test("Tailscale disconnection hides the view and reconnect works without sign-in", async () => {
  fixture.connected = false;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  assert.equal(await page.locator(".secret-row").count(), 0);
  assert.equal(await page.locator("dialog").innerHTML(), "");
  fixture.connected = true;
  await click("open-vault");
  await page.locator(".secret-row").first().waitFor();
  assert.deepEqual(errors, []);
});

test("Open vault responds across the whole button and shows progress during one pending attempt", async () => {
  for (const region of ["label", "arrow", "left", "right", "top", "bottom"]) {
    await click("lock");
    const opening = page.getByRole("button", { name: "Open vault", exact: true });
    await opening.waitFor();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let calls = 0;
    await page.route("**/ui-api/session", async route => {
      calls++;
      await gate;
      await route.continue();
    });
    try {
      const box = await opening.boundingBox();
      const arrow = await opening.locator("svg").boundingBox();
      const points = {
        label: [box.x + 80, box.y + box.height / 2],
        arrow: [arrow.x + arrow.width / 2, arrow.y + arrow.height / 2],
        left: [box.x + 3, box.y + box.height / 2],
        right: [box.x + box.width - 3, box.y + box.height / 2],
        top: [box.x + box.width / 2, box.y + 3],
        bottom: [box.x + box.width / 2, box.y + box.height - 3],
      };
      const [x, y] = points[region];
      assert.equal(await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.closest("button")?.dataset.action, [x, y]), "open-vault", region);
      await page.mouse.click(x, y);
      await page.getByRole("status").getByText("Checking Tailscale…", { exact: true }).waitFor({ timeout: 2000 });
      assert.equal(await page.getByRole("button", { name: "Opening…", exact: true }).isDisabled(), true, region);
      await page.evaluate(() => window.tailvaultAction("open-vault"));
      assert.equal(calls, 1, region);
    } finally {
      release();
    }
    await page.locator(".secret-row").first().waitFor();
    await page.unroute("**/ui-api/session");
  }
  assert.deepEqual(errors, []);
});

test("an unexpected opening abort is shown and the next attempt can succeed", async () => {
  await click("lock");
  await page.evaluate(() => {
    const original = window.fetch;
    window.fetch = (url, options) => {
      if (url === "/ui-api/session") {
        window.fetch = original;
        return Promise.reject(new DOMException("Synthetic native interruption", "AbortError"));
      }
      return original(url, options);
    };
  });
  await click("open-vault");
  await page.getByRole("alert").getByText("Opening the vault was interrupted. Try again.", { exact: true }).waitFor({ timeout: 2000 });
  assert.equal(await page.getByRole("button", { name: "Open vault", exact: true }).isEnabled(), true);
  await click("open-vault");
  await page.locator(".secret-row").first().waitFor();
  assert.deepEqual(errors, []);
});

test("a stalled identity check times out, permits retry, and ignores its late response", async () => {
  await click("lock");
  await page.clock.install();
  await page.evaluate(() => {
    const original = window.fetch;
    window.fetch = (url, options) => {
      if (url === "/ui-api/session") {
        window.fetch = original;
        // Model a native transport that completes even after being canceled.
        return new Promise(resolve => { window.finishStaleOpening = () => resolve(new Response("obsolete identity failure", { status: 401 })); });
      }
      return original(url, options);
    };
  });
  await click("open-vault");
  await page.clock.fastForward(10001);
  await page.getByRole("alert").getByText("Tailscale’s local connection did not respond within 10 seconds. Try again.", { exact: true }).waitFor({ timeout: 2000 });
  assert.equal(await page.getByRole("button", { name: "Open vault", exact: true }).isEnabled(), true);
  await click("open-vault");
  await page.locator(".secret-row").first().waitFor();
  await page.evaluate(async () => {
    window.finishStaleOpening();
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  assert.equal(await page.locator(".secret-row").count(), 10);
  assert.equal(await page.getByText("obsolete identity failure", { exact: true }).count(), 0);
  assert.deepEqual(errors, []);
});

test("opening with Enter or Space surfaces an identity error on every attempt", async () => {
  await click("lock");
  fixture.connected = false;
  for (const key of ["Enter", "Space"]) {
    await page.getByRole("button", { name: "Open vault", exact: true }).focus();
    await page.keyboard.press(key);
    await page.getByRole("alert").getByText("Connect Tailscale to open the vault.", { exact: true }).waitFor();
    assert.equal(await page.getByRole("button", { name: "Open vault", exact: true }).isEnabled(), true);
  }
  assert.deepEqual(errors, []);
});

test("a stalled initial secret list reports a timeout and can be retried", async () => {
  await click("lock");
  await page.clock.install();
  await page.evaluate(() => {
    const original = window.fetch;
    window.fetch = (url, options) => {
      if (url === "/ui-api/list") {
        window.fetch = original;
        return new Promise(() => {});
      }
      return original(url, options);
    };
  });
  await click("open-vault");
  await page.getByText("Loading secrets…", { exact: true }).waitFor();
  await page.clock.fastForward(35001);
  await page.getByText("Loading secrets timed out. Check Tailscale and your server address, then try again.", { exact: true }).waitFor();
  assert.equal(await page.locator(".secret-row").count(), 0);
  await page.getByRole("button", { name: "Try again", exact: true }).click();
  await page.locator(".secret-row").first().waitFor();
  assert.deepEqual(errors, []);
});

test("a stalled settings read on launch reports its stage and Open vault can retry", async () => {
  await page.clock.install();
  await page.addInitScript(() => {
    const original = window.fetch;
    window.fetch = (url, options) => {
      if (url === "/ui-api/settings") {
        window.fetch = original;
        return new Promise(() => {});
      }
      return original(url, options);
    };
  });
  await page.reload();
  await page.getByRole("status").getByText("Loading settings…", { exact: true }).waitFor();
  await page.clock.fastForward(10001);
  await page.getByRole("alert").getByText("TailVault’s settings did not respond within 10 seconds. Try again.", { exact: true }).waitFor();
  await click("open-vault");
  await page.locator(".secret-row").first().waitFor();
  assert.deepEqual(errors, []);
});

test("changing settings cancels a pending opening without showing a cancellation error", async () => {
  await click("lock");
  await page.evaluate(() => {
    const original = window.fetch;
    window.fetch = (url, options) => {
      if (url === "/ui-api/session") {
        window.fetch = original;
        return new Promise((resolve, reject) => options.signal.addEventListener("abort", () => reject(new DOMException("Vault hidden", "AbortError"))));
      }
      return original(url, options);
    };
  });
  await click("open-vault");
  await page.getByRole("status").getByText("Checking Tailscale…", { exact: true }).waitFor();
  await click("settings");
  await page.getByRole("heading", { name: "Settings", exact: true }).waitFor();
  assert.equal(await page.getByRole("alert").count(), 0);
  await click("close-dialog");
  assert.equal(await page.getByText("Opening the vault was interrupted. Try again.", { exact: true }).count(), 0);
  await click("open-vault");
  await page.locator(".secret-row").first().waitFor();
  assert.deepEqual(errors, []);
});

test("curl previews and copies support active and pinned versions without reading values", async () => {
  await choose("platform/production/database-url");
  await nativeAction("copy-curl");
  let command = fixture.clipboard;
  assert.match(command, /^curl --disable --fail/);
  assert.match(command, /"Name":"platform\/production\/database-url"/);
  assert.match(command, /https:\/\/secrets\.example\.ts\.net\/api\/get/);
  assert.doesNotMatch(
    command,
    /"Version"|python3|fixture-view|sample-rotated-value/,
  );
  await page.getByRole("tab", { name: "Use in terminal" }).click();
  await page.locator("#curl-version").selectOption("3");
  await page.locator("#curl-output").selectOption("decoded");
  await nativeAction("copy-curl");
  command = fixture.clipboard;
  assert.equal(command, await page.locator("#curl-command").textContent());
  assert.match(command, /"Version":3/);
  assert.match(command, /python3 -c/);
  await page.getByText(/Requires Python 3/).waitFor();
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  const screenshotOptions = {
    fullPage: true,
    animations: "disabled",
    style: "#toast { visibility: hidden !important; }",
  };
  await page.screenshot({
    path: "test-results/curl-desktop.png",
    ...screenshotOptions,
  });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.screenshot({
    path: "test-results/curl-dark.png",
    ...screenshotOptions,
  });
  await page.setViewportSize({ width: 860, height: 620 });
  await page.screenshot({
    path: "test-results/curl-compact.png",
    ...screenshotOptions,
  });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    true,
  );
  assert.deepEqual(errors, []);
});

test("curl supports quoted secret names and native copying stays on its own route", async () => {
  const name = "personal/tests/it's-a-key";
  fixture.secrets.set(name, {
    Name: name,
    ActiveVersion: 1,
    Values: { 1: Buffer.from("sample-value").toString("base64") },
  });
  await click("refresh");
  await choose(name);
  await page.getByRole("tab", { name: "Use in terminal" }).click();
  assert.equal(await page.locator("#curl-version option").count(), 2);
  await click("copy-curl");
  await page.getByText("curl command copied.", { exact: true }).waitFor();
  assert.deepEqual(
    fixture.calls.filter((c) => c.op === "copy-curl"),
    [
      {
        op: "copy-curl",
        Name: name,
        Version: 0,
        Decode: false,
      },
    ],
  );
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  assert.deepEqual(errors, []);
});

test("late curl previews cannot overwrite a newer selection or reappear after locking", async () => {
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  await choose("platform/production/database-url");
  await page.getByRole("tab", { name: "Use in terminal" }).click();
  await page.route("**/ui-api/curl", async (route) => {
    if (route.request().postDataJSON().Version === 1) await held;
    await route.continue();
  });
  await page.locator("#curl-version").selectOption("1");
  await page.locator("#curl-version").selectOption("3");
  await page.waitForFunction(() =>
    document.querySelector("#curl-command").textContent.includes('"Version":3'),
  );
  release();
  await page.waitForResponse(
    (res) =>
      res.url().endsWith("/ui-api/curl") &&
      res.request().postDataJSON().Version === 1,
  );
  assert.match(
    await page.locator("#curl-command").textContent(),
    /"Version":3/,
  );
  await click("lock");
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  assert.equal(await page.locator("#curl-command").count(), 0);
  assert.deepEqual(errors, []);
});

test("first run saves a server, rejects invalid addresses, and skips onboarding on later launches", async () => {
  fixture.reset();
  fixture.serverURL = "";
  await page.reload();
  await page.getByRole("heading", { name: "Connect to Setec" }).waitFor();
  assert.equal(await page.getByLabel("Setec server").inputValue(), "");
  assert.deepEqual(fixture.calls, []);
  await page.screenshot({ path: "test-results/onboarding-light.png", fullPage: true, animations: "disabled" });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.setViewportSize({ width: 860, height: 620 });
  await page.screenshot({ path: "test-results/onboarding-dark-compact.png", fullPage: true, animations: "disabled" });
  assert.equal(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight), true);
  await page.getByLabel("Setec server").fill("http://secrets.example.ts.net");
  await page.getByRole("button", { name: "Save and open vault" }).click();
  await page.getByRole("alert").getByText(/Enter an HTTPS/).waitFor();
  assert.equal(fixture.serverURL, "");
  await page.getByLabel("Setec server").fill("https://vault.example.ts.net:8443/");
  await page.getByRole("button", { name: "Save and open vault" }).click();
  await page.locator(".secret-row").first().waitFor();
  assert.equal(fixture.serverURL, "https://vault.example.ts.net:8443");
  await page.reload();
  await page.locator(".secret-row").first().waitFor();
  assert.equal(await page.locator("#setup-form").count(), 0);
  assert.equal(await page.locator('input[name="server"]').count(), 0);
  await click("lock");
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  await click("settings");
  assert.equal(await page.getByLabel("Setec server").inputValue(), fixture.serverURL);
  assert.deepEqual(errors, []);
});

test("Settings cancels edits and updates the vault and curl destination only after saving", async () => {
  await choose("platform/production/database-url");
  await page.keyboard.press("Control+,");
  await page.getByRole("heading", { name: "Settings", exact: true }).waitFor();
  await page.screenshot({ path: "test-results/settings-light.png", fullPage: true, animations: "disabled" });
  await page.getByLabel("Setec server").fill("https://unused.example.ts.net");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await closed();
  assert.equal(fixture.serverURL, "https://secrets.example.ts.net");
  assert.equal(await page.locator('.secret-row[aria-pressed="true"]').count(), 1);
  await click("settings");
  await page.getByLabel("Setec server").fill("https://replacement.example.ts.net");
  await page.emulateMedia({ colorScheme: "dark" });
  await page.setViewportSize({ width: 860, height: 620 });
  await page.screenshot({ path: "test-results/settings-dark-compact.png", fullPage: true, animations: "disabled" });
  await submit();
  await closed();
  await page.locator(".secret-row").first().waitFor();
  assert.equal(await page.locator('.secret-row[aria-pressed="true"]').count(), 0);
  assert.equal(await page.locator(".profile-server").textContent(), "replacement.example.ts.net");
  await choose("platform/production/database-url");
  await click("copy-curl");
  await page.getByText("curl command copied.", { exact: true }).waitFor();
  assert.match(fixture.clipboard, /https:\/\/replacement\.example\.ts\.net\/api\/get/);
  assert.equal(fixture.calls.filter((c) => c.op === "get").length, 0);
  assert.deepEqual(errors, []);
});

test("saved configuration and Settings remain available offline and after connection errors", async () => {
  fixture.connected = false;
  await page.reload();
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  assert.equal(await page.locator("#setup-form").count(), 0);
  await click("settings");
  await page.getByLabel("Setec server").fill("https://offline.example.ts.net");
  await submit();
  await closed();
  assert.equal(fixture.serverURL, "https://offline.example.ts.net");
  await page.getByRole("button", { name: "Open vault" }).waitFor();
  fixture.connected = true;
  fixture.listError = "Setec could not be reached. Check Tailscale and your server address.";
  await click("open-vault");
  await page.getByText("Couldn’t load secrets", { exact: true }).waitFor();
  await click("settings");
  assert.equal(await page.getByLabel("Setec server").inputValue(), "https://offline.example.ts.net");
  fixture.listError = "";
  await page.getByLabel("Setec server").fill("https://working.example.ts.net");
  await submit();
  await page.locator(".secret-row").first().waitFor();
  assert.equal(await page.locator("#setup-form").count(), 0);
  assert.deepEqual(errors, []);
});

test("failed persistence keeps the saved server and leaves the Settings draft editable", async () => {
  await click("settings");
  fixture.settingsSaveError = true;
  await page.getByLabel("Setec server").fill("https://unsaved.example.ts.net");
  await submit();
  await page.getByRole("alert").getByText(/could not be saved/).waitFor();
  assert.equal(fixture.serverURL, "https://secrets.example.ts.net");
  assert.equal(await page.getByLabel("Setec server").inputValue(), "https://unsaved.example.ts.net");
  fixture.settingsSaveError = false;
  await submit();
  await closed();
  await page.locator(".secret-row").first().waitFor();
  assert.equal(fixture.serverURL, "https://unsaved.example.ts.net");
  assert.deepEqual(errors, []);
});

test("VIEW-1: canceled activation never reopens a hidden or revoked view", async () => {
  for (const reason of ["hide", "offline", "identity"]) {
    fixture.reset();
    await page.reload();
    await choose("personal/github/token");
    await click("edit");
    await page.locator("textarea").fill("replacement-value");
    await page.locator('input[name="activate"]').check();
    let release;
    const held = new Promise(resolve => { release = resolve; });
    await page.route("**/ui-api/activate", async route => {
      await held;
      if (reason === "identity") await route.fulfill({ status: 401, body: "Identity changed" });
      else await route.continue().catch(() => {});
    });
    const activating = page.waitForRequest(req => req.url().endsWith("/ui-api/activate"));
    await submit();
    await activating;
    const sessionRequests = [];
    const record = req => { if (req.url().endsWith("/ui-api/session")) sessionRequests.push(req); };
    page.on("request", record);
    if (reason === "hide") await page.keyboard.press("Control+Shift+L");
    if (reason === "offline") {
      fixture.connected = false;
      await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    }
    if (reason === "identity") release();
    await page.getByRole("button", { name: "Open vault" }).waitFor();
    release();
    await page.unrouteAll({ behavior: "wait" });
    await page.waitForLoadState("networkidle");
    assert.equal(sessionRequests.length, 0, reason);
    assert.equal(await page.locator(".secret-row").count(), 0, reason);
    page.off("request", record);
  }
  assert.deepEqual(errors, []);
});

test("MENU-1: native commands preserve drafts and cannot replace a saving dialog", async () => {
  await choose("personal/github/token");
  await click("edit");
  await page.locator("textarea").fill("draft-to-preserve");
  for (const action of ["new", "refresh", "search", "settings"]) {
    await page.evaluate(action => window.tailvaultAction(action), action);
    assert.equal(await page.locator("textarea").inputValue(), "draft-to-preserve");
    assert.equal(await page.getByRole("dialog").getAttribute("aria-labelledby"), "modal-title");
  }
  let release;
  const held = new Promise(resolve => { release = resolve; });
  await page.route("**/ui-api/put", async route => { await held; await route.continue(); });
  const putting = page.waitForRequest(req => req.url().endsWith("/ui-api/put"));
  await submit();
  await putting;
  await page.evaluate(() => window.tailvaultAction("new"));
  assert.equal(await page.locator("textarea").inputValue(), "draft-to-preserve");
  assert.equal(await page.locator('dialog button[type="submit"]').isDisabled(), true);
  release();
  await closed();
  await page.unrouteAll({ behavior: "wait" });
  await click("settings");
  await page.getByLabel("Setec server").fill("https://draft.example.ts.net");
  await page.evaluate(() => window.tailvaultAction("new"));
  assert.equal(await page.getByLabel("Setec server").inputValue(), "https://draft.example.ts.net");
  assert.deepEqual(errors, []);
});

test("VALUE-1: a rotation after listing cannot mislabel the revealed bytes", async () => {
  await choose("platform/production/database-url");
  fixture.secrets.get("platform/production/database-url").ActiveVersion = 3;
  await click("reveal");
  await page.getByText("sample-next-value", { exact: true }).waitFor();
  assert.equal(await page.locator(".value-version").textContent(), "Version 3");
  await click("reveal");
  assert.equal(await page.locator(".value-version").textContent(), "Active version");
  await page.getByRole("tab", { name: /Versions/ }).click();
  await page.route("**/ui-api/get", route => route.fulfill({json:{Version:2,Value:"d3JvbmctdmVyc2lvbg=="}}));
  await page.getByRole("button", { name: "Reveal version 1", exact: true }).click();
  await page.getByText("Setec returned an invalid secret version.", {exact:true}).waitFor();
  assert.equal(await page.locator(".version-value:visible").count(), 0);
  assert.deepEqual(errors, []);
});

test("MENU-1: Settings can be canceled while the vault is hidden or offline", async () => {
  await click("lock");
  await page.getByRole("button", {name: "Open vault", exact: true}).waitFor();
  for (const connected of [true, false]) {
    fixture.connected = connected;
    await click("settings");
    await page.getByRole("dialog", {name: "Settings", exact: true}).waitFor();
    await page.locator('input[name="server"]').fill("https://unsaved.example.ts.net");
    await page.getByRole("button", {name: "Cancel", exact: true}).click();
    await closed();
    assert.equal(fixture.serverURL, "https://secrets.example.ts.net");
    assert.equal(await page.locator(".secret-row").count(), 0);
  }
});
