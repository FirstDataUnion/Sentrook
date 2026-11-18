---
"@firstdataunion/sentrook-openclaw": patch
---

Removed the `approval.scheduledTimeoutMs` and `approval.scheduledTimeoutBehavior` settings and their
`SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_MS` / `SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR` environment variables. A
review in a cron job, heartbeat or subagent is held for the owner, so they never applied; `status` and `verify` no
longer print a line about them.
