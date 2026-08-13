# @firstdataunion/sentrook-openclaw

## 1.0.1-rc.2

### Patch Changes

- Default unattended (cron/subagent) review timeout behavior to deny (fail-closed). Opt into `approval.scheduledTimeoutBehavior: "allow"` if jobs must proceed without a human.
- Remove unused `approval.enabled` / `SENTROOK_SCHEDULED_APPROVAL_ENABLED` kill switch. Cron and subagent always use the scheduled timeout policy (tune via `scheduledTimeoutMs` / `scheduledTimeoutBehavior` / `scheduledIntentKinds`).
- Remove `mode` (observe/enforce) and `sanitization.enabled` config options. The plugin always enforces decisions and always scrubs PlanIR before egress. Re-run `openclaw sentrook configure` (or delete leftover `mode` / `sanitization` keys) so older `openclaw.json` entries do not fail schema validation.

## 1.0.1-rc.1

### Patch Changes

- Configure no longer offers observe mode or PlanIR sanitization toggles. Installs always use enforce with sanitization on; disabling those via the wizard/CLI flags is removed.

## 1.0.0

First public npmjs line. OpenClaw plugin for hosted Sentrook (`POST /scan` with
PlanIR 1.0). Not published until `release-plugin` (or a one-off bootstrap)
runs.
