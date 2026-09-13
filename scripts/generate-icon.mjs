// The UI SVG is also the source for the macOS app icon.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { webkit } from "playwright";

const source = new URL("../internal/portal/assets/icon.svg", import.meta.url);
const output = new URL("../build/appicon.png", import.meta.url);
const browser = await webkit.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1024, height: 1024 },
    deviceScaleFactor: 1,
  });
  await page.setContent(`<!doctype html><style>
    html, body { margin: 0; width: 100%; height: 100%; background: transparent; }
    svg { display: block; width: 100%; height: 100%; }
  </style>${await readFile(source, "utf8")}`);
  await page.screenshot({ path: fileURLToPath(output), omitBackground: true });
} finally {
  await browser.close();
}
