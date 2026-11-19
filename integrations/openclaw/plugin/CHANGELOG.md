# @firstdataunion/sentrook-openclaw

## 2.0.0-beta.13

### Patch Changes

- ad41114: An owner message in a group or channel room is sent as the owner's in a group chat (sender basis `group_chat`), so a
  block there is never softened as if you were attending alone. A turn of OpenClaw's own system agent, with its
  `[proposal-resolved]` and `[ui-context]` marker lines, is sent as a system turn with no sender. When the session key
  does not say which kind of chat a message came from (rooms routed into the main session with
  `session.groupScope: "main"`), the plugin no longer claims a direct chat.
- 835f54c: A read-only **Sentrook** tab in the Control UI: recent scans and, for each one, its risk broken down into the scores
  and signals the scanner combined, with the reasons, floors and grants behind them. It uses the Control UI's own
  sign-in (HTTPS or a loopback address); changes stay with the commands.
- 4cdb358: Removed the `approval.scheduledTimeoutMs` and `approval.scheduledTimeoutBehavior` settings and their
  `SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_MS` / `SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR` environment variables. A
  review in a cron job, heartbeat or subagent is held for the owner, so they never applied; `status` and `verify` no
  longer print a line about them.
- 9bacfe0: The approval card is easier to read and always recognisable as Sentrook's: its title is
  `🪶 Sentrook security check · risk 62/100`, and the description says what the call does and why in plain words,
  what "Always allow" would also trust, and ends with `/sentrook-why <id>` for the full detail. Reason codes and scores
  moved to `/sentrook-why`. The card is fitted to OpenClaw's approval limits, so it is never refused; the description
  of the call is shortened first.
- 5c67a7e: `/sentrook-snooze` changes are now safe when the gateway and the command line change snoozes at the same time: a
  snooze set or ended in one is no longer undone by the other. When the snooze file stays locked by another process,
  nothing is changed and the reply says to try again.

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
