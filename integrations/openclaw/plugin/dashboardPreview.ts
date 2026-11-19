/**
 * Local preview of the dashboard for design work: `npm run preview:dashboard`, then http://127.0.0.1:3456/.
 * Not shipped (not in package.json `files`).
 *
 * Every request rebuilds the page from source: edits to dashboardView.js show on reload. The data is the shared
 * fixture log (integrations/fixtures/traffic-log/dashboard), or the log named by SENTROOK_PREVIEW_LOG.
 *   /        the page as the OpenClaw Control UI tab shows it (follows the system light or dark setting)
 *   /hermes  the view on Hermes's default dark theme (Hermes Teal), with the theme's colour variables
 * Binds 127.0.0.1 only; PORT overrides the port.
 */

import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

import { limitOf, renderPage, scansModel } from "./dashboard.ts";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const LOG = process.env.SENTROOK_PREVIEW_LOG || here("../../fixtures/traffic-log/dashboard/traffic.jsonl");
const PORT = Number(process.env.PORT || 3456);

/** Hermes Teal's colour variables (hermes-agent web/src/index.css), so the host-themed view can be judged. */
const HERMES_TEAL = `<style>
html,body{margin:0;background:#041c1c;color:#ffe6cb}
body{--color-foreground:#ffe6cb;--color-card:color-mix(in srgb,#ffe6cb 4%,#041c1c);
--color-muted:color-mix(in srgb,#ffe6cb 8%,#041c1c);--color-muted-foreground:color-mix(in srgb,#ffe6cb 65%,#041c1c);
--color-border:color-mix(in srgb,#ffe6cb 15%,transparent);--color-primary:#ffe6cb;--color-destructive:#fb2c36;
--color-success:#4ade80;--color-warning:#ffbd38;font-family:system-ui,sans-serif}
code{background:#ffe6cb;color:#041c1c}
</style>`;

function model(limit: number): unknown {
  return {
    ...scansModel(LOG, true, limit),
    host: "preview",
    lines: { review_at: 45, block_at: 80 },
    mode: "enforce",
    state: {
      grants: "Grants: 1 in config, 1 by command\n  g-3  destination  session  api.example.com  expires in 23h",
      snooze: "off",
    },
    commands: { history: "/sentrook-history", why: "/sentrook-why <id>", grants: "/sentrook-grants", snooze: "/sentrook-snooze" },
  };
}

createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://preview.invalid");
  if (url.pathname !== "/" && url.pathname !== "/hermes") {
    res.statusCode = 404;
    res.end("Not found");
    return;
  }
  try {
    let html = renderPage(model(limitOf(url.searchParams.get("n"))), "preview", readFileSync(here("./dashboardView.js"), "utf8"));
    if (url.pathname === "/hermes") {
      html = html
        .replace("</head>", `${HERMES_TEAL}</head>`)
        .replace('<div id="sentrook-root">', '<div id="sentrook-root" data-theme="host">');
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(html);
  } catch (err) {
    res.statusCode = 500;
    res.end(String(err));
  }
}).listen(PORT, "127.0.0.1", () => console.log(`dashboard preview on http://127.0.0.1:${PORT}/ and /hermes (log: ${LOG})`));
