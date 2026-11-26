/**
 * Local preview of the dashboard for design work: `npm run preview:dashboard`, then http://127.0.0.1:3456/.
 * Not shipped (not in package.json `files`).
 *
 * Every request rebuilds the page from source: edits to dashboardView.js show on reload. The data is the shared
 * fixture log (integrations/fixtures/traffic-log/dashboard), or the log named by SENTROOK_PREVIEW_LOG.
 *   /        the page as the OpenClaw Control UI tab shows it (follows the system light or dark setting)
 *   /hermes  the view on Hermes's default dark theme (Hermes Teal), with the theme's colour variables
 * Example pending items (an open review, a held call) are added; PREVIEW_PENDING=0 leaves them out.
 * `?holds=N` shows N held calls, the extra ones offering no answer. `?report=<id>` adds that scan's report panel, as the plugins do. `?calls=1` shows each scan's call, as the
 * dashboardShowCalls setting does (SENTROOK_PREVIEW_LOG=.../dashboard/calls.jsonl has calls worth showing).
 * Binds 127.0.0.1 only; PORT overrides the port.
 */

import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

import { COMMANDS, queryOf, queryScans, renderPage } from "./dashboard.ts";
import { parseRef } from "./history.ts";
import * as report from "./report.ts";

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

/** Hermes's command forms, as dashboard.py's COMMANDS has them. */
const HERMES_COMMANDS = {
  prefix: "/sentrook ",
  call_setting: "hermes config set plugins.entries.sentrook.settings.dashboard_show_calls true",
  review_answer: ["Answer in the chat where it was asked, with Hermes's own commands:", "/approve", "/approve session", "/approve always", "/deny"],
};

/**
 * Example pending items (PREVIEW_PENDING=0 leaves them out): a recent open prompt and one held call, with scans.
 * `holds` (from `?holds=N`, 1 to 20) adds held calls from a run with no source, which offer no answer.
 */
async function pending(calls: boolean, holds = 1): Promise<unknown> {
  const empty = { reviews: [], holds: [], holds_readable: true, review_window_s: 300 };
  if (process.env.PREVIEW_PENDING === "0") return empty;
  const recent = await queryScans(LOG, { ...queryOf(new URLSearchParams()), limit: 50 }, undefined, calls);
  const review = recent.scans.find((s: Record<string, any>) => s.bucket === "review");
  const held = recent.scans.find((s: Record<string, any>) => s.bucket === "observed") ?? null;
  return {
    reviews: review ? [{ ...review, review: "no answer", ts: new Date(Date.now() - 60_000).toISOString() }] : [],
    holds: [
      {
        id: "h-3fa2c1",
        request_id: held?.id ?? null,
        tool: "message",
        where: 'cron job "daily-brief" (job 7f3a)',
        held_at: new Date(Date.now() - 4 * 3600_000).toISOString(),
        expires_at: new Date(Date.now() + 20 * 3600_000).toISOString(),
        grant: "destination channel:1234567890",
        scan: held,
      },
      ...Array.from({ length: Math.min(Math.max(holds, 1), 20) - 1 }, (_, i) => ({
        id: `h-${(0xa00000 + i).toString(16)}`,
        request_id: null,
        tool: "terminal",
        where: "a webhook run",
        held_at: new Date(Date.now() - (5 + i) * 3600_000).toISOString(),
        expires_at: new Date(Date.now() + (6 * 24 - i) * 3600_000).toISOString(),
        grant: null,
        scan: null,
        offers: [],
        count: 1,
      })),
    ],
    holds_readable: true,
    review_window_s: 300,
  };
}

function reportPanel(ref: string | null, hermes: boolean): unknown {
  if (!ref) return undefined;
  const match = parseRef(ref);
  const found = match && ref.toLowerCase() !== "last" ? report.find(LOG, match) : null;
  const cmd = (verb: string) => (hermes ? HERMES_COMMANDS.prefix : COMMANDS.prefix) + verb;
  return found ? report.model(found, cmd) : { id: ref, missing: true };
}

async function model(params: URLSearchParams, hermes: boolean): Promise<unknown> {
  const q = queryOf(params);
  return {
    report: reportPanel(params.get("report"), hermes),
    version: 1,
    log: "on",
    limit: q.limit,
    ...(await queryScans(LOG, q, undefined, params.get("calls") === "1")),
    show_calls: params.get("calls") === "1",
    pending: await pending(params.get("calls") === "1", Number(params.get("holds") || 1)),
    commands: hermes ? HERMES_COMMANDS : COMMANDS,
    host: "preview",
    lines: { review_at: 45, block_at: 80 },
    mode: "enforce",
    state: {
      grants: "Grants: 1 in config, 1 by command\n  g-3  destination  session  api.example.com  expires in 23h",
      snooze: "off",
    },
  };
}

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://preview.invalid");
  if (url.pathname !== "/" && url.pathname !== "/hermes") {
    res.statusCode = 404;
    res.end("Not found");
    return;
  }
  try {
    let html = renderPage(await model(url.searchParams, url.pathname === "/hermes"), "preview", readFileSync(here("./dashboardView.js"), "utf8"));
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
