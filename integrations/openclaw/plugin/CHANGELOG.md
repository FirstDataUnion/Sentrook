# @firstdataunion/sentrook-openclaw

## Unreleased

### Minor Changes

- Native Control UI dashboard (OpenClaw ≥ 2026.9.2 with Settings → Labs → Custom plugin UI) uses the same operator layout as the original panel. Writes go through plugin session actions on the signed-in operator session. The iframe Sentrook tab is read-only; `/sentrook` chat and the CLI remain the write path on older hosts.

### Patch Changes

- HTTP `/sentrook` and the Control UI iframe tab are a read-only operator view: mutation buttons are replaced with `/sentrook` and `/approve` commands. Writes belong on the native Sentrook page (OpenClaw ≥ 2026.9.2 with Settings → Labs → Custom plugin UI).
- Session-action replies are JSON-cloned (and dashboard state compacted) so the host's `isPluginJsonValue` check accepts them. Optional `undefined` fields in timeline/session rows were failing every native load and refetch with "plugin session action result must be JSON-compatible".

## 1.1.0-rc.1

### Minor Changes

- OpenClaw 2.0 (2026.8.1): default scan timeout is 14s (OIDC mint shares that budget) so `before_tool_call` stays inside the host's 15s fail-closed wait. Approval waits default to 10 minutes for interactive and unattended reviews and are capped there. Unresolved reviews always deny; `scheduledTimeoutBehavior: allow` is ignored but still accepted. Review-card Shell Preview uses the host's 512-char cap.
- Review cards summarise local pending args when there is no shell command: `process action=log` shows the session and limit instead of "command was not available to summarise". `process` write/submit/start/spawn are scanned as `exec`.
- Manifest sets `activation.onStartup: true`. First-time `npm:` installs document `--force` for noninteractive hosts.
- Owner-only `/sentrook` chat commands. Bare `/sentrook` is a snapshot (policy + pending); `/sentrook help` is the catalog; each verb accepts `help` for options and current state. Status, policy, pending (`all` for every session), history (8 per reply, max 20, `before <id>` for older, `gateway` for cross-session), sessions, log, sensitivity, allow-all/quiet (session, named session, or `all` for the gateway), feedback, scan-error, allowlist. `critical` and scan-error `allow` need a trailing `confirm`. Replies are channel messages: lists stay short; `pending <id>` / `history <id>` reconstruct the review. Cards still resolve with `/approve`. Public rooms can read them — prefer a DM or the dashboard.
- Gateway panel at `/sentrook` (same port as Control UI): tabbed operator UI with Reviews as home (severity + risk, intent, compact episode trail ending on the pending command, dangerous-span highlighting, human-readable policy labels). When scan credentials are missing, Reviews is a first-run form that writes `~/.openclaw/.env` and live-mints; Settings **Test connection** is `openclaw sentrook verify` for UI operators. Timeline is an audit stream of the newest 100 scans (search, per-session layout, expandable command/output/resolution). Settings covers allow-all / quiet (global or per session), sensitivity, `feedback.mode`, `onScanError`, and operator-log retention / purge. The Per session table is OpenClaw’s session store (Control UI rows) with Sentrook flags overlaid. Polls `/api/state` instead of a blind reload. Allow/deny via `plugin.approval.resolve`. The tab is plugin-managed auth with a process token on the Control UI path (no 5-minute gateway cookie, no expiring CSRF session). Sandboxed Control UI fetches (`Origin: null`) stay on the tab pathname (`Accept: application/json` for state, POST `_srk` for saves); `/sentrook` answers OPTIONS and allows that opaque origin. The Control UI tab path is `/sentrook/tab/<token>` because remounts keep pathname and drop query. After a save (or Cmd/Ctrl+R / F5), the panel swaps HTML in place so the iframe is not navigated (a `location.reload()` drops `allow-scripts` in that sandbox). `/approve plugin:…` remains the fallback when OpenClaw has no `plugin:` id.
- Local operator log (`sentrook.operator.log/v1`) on by default at `$OPENCLAW_STATE_DIR/sentrook-operator.jsonl` (`0600`, 14 days / 32 MiB). Secret/PII-scrubbed, no per-field truncation, never auto-uploaded. Hook I/O never fail-closes a tool call.
- After hosted `review` only: global or per-session allow-all, quiet TTL (cap 8h), and persisted attended / unattended `sensitivity` floors `strict` / `info` / `warning` / `critical` (legacy `lenient` = info). The floor includes hard L2 reviews. Never skip block or scan-error. Allow-all/quiet are attended-only and in-memory (cleared on `session_end` / gateway restart) and do not resolve already-open cards.
- Internal: optional local JSONL diagnostic log for maintainers investigating review-card copy and scan decisions (off by default).

## 1.0.5

### Patch Changes

- Keep provider prefixes when redacting secrets (`sk-ant-[REDACTED]`, `Bearer [REDACTED]`, webhook path) so hosted scan can still match secret-shaped rules without receiving key material.

## 1.0.4

### Patch Changes

- Fail closed like Hermes: default onScanError is review, default scan timeout is 60s, plugin exceptions and unknown/missing scan decisions block, and unattended scan errors never proceed. OIDC mint uses its own 30s budget outside the scan abort timer. Blocked and denied tool calls no longer linger in the session pending map.
- 56ed9a8: Rebuild exec review cards from local argv: Command is a structural summary (destination / path / packed excerpt), never a rule id. Shell Preview drops allow-hint and AIRA ids so long commands stay decidable.

## 1.0.3

### Patch Changes

- Auth failures (401/403) honor `onScanError` for interactive `review` (config-error card) and `deny`; `allow` and unattended paths still never fail-open. Agent-facing block reasons distinguish configuration/connectivity from policy denies.
- Configure writes `SENTROOK_OIDC_ISSUER` beside scan credentials (matches pinned `DEFAULT_OIDC_ISSUER` / `SCAN_BASE_URL`).
- 391bf75: Exec review cards show a secret-scrubbed local command excerpt instead of the PlanIR `[TRUNCATED]` placeholder. Hosted `/scan` and `/feedback` still receive length-bounded, secret/PII-scrubbed PlanIR.
- 391bf75: Configure restart hints note that `openclaw-gateway` is OpenClaw's default Compose service name and may differ (`docker compose ps`).
- b150aa3: Pin the scan/feedback origin in plugin code (`SCAN_BASE_URL`) so it cannot be retargeted via openclaw.json or SENTROOK_SCAN_URL.

## 1.0.2

### Patch Changes

- Scrub PII in nested `exec` `env` values (account emails) before scan and feedback egress.
- `onScanError` (`allow` / `deny` / `review`) for scan timeouts, transport errors, 5xx, and exhausted 429s. Existing installs without the key keep fail-open. Hosted configure recommends `review`. HTTP 401/403 always deny. 429 retries once when `Retry-After` fits in `timeoutMs`.

## 1.0.1

### Patch Changes

- Configure no longer offers observe mode or PlanIR sanitization toggles. Installs always use enforce with sanitization on; disabling those via the wizard/CLI flags is removed.
- Default unattended (cron/subagent) review timeout behavior to deny (fail-closed). Opt into `approval.scheduledTimeoutBehavior: "allow"` if jobs must proceed without a human.
- Remove unused `approval.enabled` / `SENTROOK_SCHEDULED_APPROVAL_ENABLED` kill switch. Cron and subagent always use the scheduled timeout policy (tune via `scheduledTimeoutMs` / `scheduledTimeoutBehavior` / `scheduledIntentKinds`).
- Remove `mode` (observe/enforce) and `sanitization.enabled` config options. The plugin always enforces decisions and always scrubs PlanIR before egress. Re-run `openclaw sentrook configure` (or delete leftover `mode` / `sanitization` keys) so older `openclaw.json` entries do not fail schema validation.
- `openclaw sentrook verify` now mints a live `client_credentials` token against FIDU Identity (catches HTTP 401 / invalid client that presence-only checks missed). Token mint errors include a short IdP response body. Docs stress a post-verify tool call + gateway log check for end-to-end scan path.
- Configure secret prompt no longer stores terminal focus/CSI junk (`ESC[I` / `ESC[O`) in `SENTROOK_SCAN_CLIENT_SECRET` when pasting into the raw-mode wizard.

## 1.0.0

First public npmjs line. OpenClaw plugin for hosted Sentrook (`POST /scan` with
PlanIR 1.0). Not published until `release-plugin` (or a one-off bootstrap)
runs.
