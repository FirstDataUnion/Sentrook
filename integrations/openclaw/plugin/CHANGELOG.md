# @firstdataunion/sentrook-openclaw

## 2.0.0-beta.14

### Patch Changes

- 55e5f55: On OpenClaw 2026.11.5 or newer, a background change to an existing skill (a Skill Workshop `patch` of the skill's
  `SKILL.md`) that Sentrook would ask about is no longer lost: the plugin reads the live skill, applies the change the way
  OpenClaw's own patch does (the old text must appear exactly once), and sends the whole changed skill to the Skill
  Workshop drafts, leaving the live skill as it is. OpenClaw also refuses a background patch of a skill the run has not
  viewed first; the draft route does not check that. The draft's note says it was held by Sentrook, names the scan (for
  `/sentrook-why`) and says it is the skill as it stood at that time with one change. The notice for it says where to
  review and apply it, and that applying it replaces the skill with that version, so a later change to the skill would
  be undone (and can be brought back from its history). Each such draft is announced, up to 5 per run in 6 hours; a
  second draft of the same skill says how many drafts of it the run made. A change is still held when it cannot be
  applied that way (the old text missing or found more than once, the file missing, a link, a FIFO or other special
  file, not valid UTF-8, larger than 1 MB, or outside the agent's Skill Workshop folder), when it is to a support file,
  when Sentrook did not judge it as a background save, or on an older OpenClaw. No background save is sent to the drafts
  any more when Sentrook reads a secret in what it saves: before this, a new skill or the agent's own draft carrying one
  was kept as a draft. That check applies when the scan reports what the save adds (the default `skillReview: allow`
  with a scanner that reports it); with an older scanner or `skillReview: review`, drafts of new skills go ahead as
  before and only OpenClaw's own checks apply. A held archive or restore now says where to do it yourself (Plugins → Skill workshop in the Control UI).
- f1bef15: OpenClaw's own background saves (the Skill Workshop review, the memory flush before compaction, the skill collection
  review) are never asked about any more, on any OpenClaw version and whatever `skillReview` or
  `approval.scheduledIntentKinds` say: OpenClaw cancels a plugin's prompt in those runs, or ends the run first, so a
  reviewed save was lost without a word. Now a save Sentrook would ask about is let through when the scanner marks it
  lenient (a complete scan below the block line, of a save declared as a self-edit that carries the content it saves:
  a Skill Workshop create, patch, write_file or draft, or a file write, edit or patch; a restore, archive or file removal
  is never let through this way), runs as a Skill Workshop draft when the agent drafted it itself, is sent to the drafts
  for you to apply when it is a new skill on OpenClaw 2026.11.5 or newer, and is held otherwise (not saved, with no
  approve id: approving could not make it; the agent is told it was not saved and not to retry). Each outcome sends you
  a notice where held-call notices go (`/sentrook-notify here`), at most one of each kind per run every 6 hours; the
  first held retry Sentrook would otherwise block is announced even after other notices, and further ones in the same
  run are not. A draft is announced once OpenClaw reports it kept, as not saved when it does not keep it, or as saved
  live when OpenClaw runs the new skill instead of the draft. A scan failure on one follows the policy for unattended
  runs, with its notice. `status` counts these saves by outcome and, like `verify`, says when their notices cannot be
  delivered. The history marks them `allowed (let through, self-edit)`, `drafted (self-edit)`,
  `not saved (draft refused, self-edit)`, `saved live (draft ignored, self-edit)`, `held (self-edit)` and
  `blocked (self-edit)`; the dashboard counts drafts under review, drafts not kept under blocked, and marks saves let
  through as lenient. Adding `system` to `approval.scheduledIntentKinds` is no longer needed for this.
- 0dee5fd: A Code Mode `exec` (the cell of JavaScript that runs other tools) is sent with OpenClaw's own mark that it is one, so
  Sentrook no longer reads its JavaScript as a shell command: an arrow function such as `f => f.name` looked like a
  command writing a file in the working directory, which in the Skill Workshop review (it works in the agent's skill
  folder) read as the agent changing its own setup and could stop the review before it saved anything. Only OpenClaw's
  mark on the hook event counts, never the call's arguments; a shell `exec` is read as before, and every call the cell
  makes is still scanned on its own.
- daf5a7a: The Sentrook logo: in the corner of the Sentrook tab, drawn in the Control UI's text colour so it fits light and dark
  themes, and as the package icon (`assets/icon.png`) that ClawHub shows on the listing. The README says the name and logo are trademarks, not covered by the MIT
  licence.
- e0accfd: Report a scan that looks wrong. `/sentrook-report [id|last]` (owner only; `openclaw sentrook report` on the command
  line) prints a report to copy and send to Sentrook: what `/sentrook-why` shows, plus the host, plugin and scanner
  versions from the scan's own record, and two lines to fill in (what you expected, what you were doing). It holds no
  call arguments or conversation text. `--github` gives a link that opens a public GitHub issue with the report filled
  in. `--full` adds the full record, the scan's traffic-log lines exactly as written, so Sentrook can replay the scan;
  it can hold conversation text, paths and addresses, so it is only for private sending, never an issue. `--save`
  writes the report and full record to a file only you can read, to email to sentrook@firstdataunion.org (kept for up
  to 30 days, then deleted). In the Sentrook tab, every scan has **Report this scan…**: the report to copy, the GitHub
  button, and the commands and email address for the full record, which the tab never shows.

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
