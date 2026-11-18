# @firstdataunion/sentrook-openclaw

## 2.0.0-beta.12

The 2.0 line, replacing 1.0.x. Needs OpenClaw 2026.9.5 or newer.

- Each tool call is sent, redacted, to the hosted Sentrook scanner with what the owner asked for in the turn and
  what the session has done, and is allowed, handed to OpenClaw's approval prompt, or blocked.
- Where nobody can answer (cron jobs, subagents), a review holds the call and sends the owner one notice with an id
  to approve within 24 hours; a call blocked there because the scan failed also sends a notice.
- OpenClaw's own skill and memory saves are scanned as self-edits, with the conversation they came from
  (`skillReview`).
- Grants, channel bindings and snooze tell Sentrook what is normal for you; a review names the grant that would
  allow the call next time.
- Observe mode scores and logs every call without blocking or asking.
- Store metadata for ClawHub: the plugin API floor, the build version, the `security` category and the listing
  README.
