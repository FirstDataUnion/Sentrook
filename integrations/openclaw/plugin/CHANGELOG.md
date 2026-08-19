# @firstdataunion/sentrook-openclaw

## 1.0.3

### Patch Changes

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
