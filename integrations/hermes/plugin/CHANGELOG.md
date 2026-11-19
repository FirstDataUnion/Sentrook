# sentrook (Hermes plugin)

Each release has an entry here, newest first, under a `## <version>` heading that matches `version` in
`plugin.yaml`. The release workflow refuses to run without one, and the catalog pull request quotes the entries
since the version the catalog pins.

## 2.0.0-beta.15

- Hermes's background skill and memory saves (the self-improvement review after a turn, and the curator) never ask
  for approval any more, on any surface and whatever the approval settings: nobody is there to answer once the turn
  is over, so a question was lost without a word (denied unseen on the local terminal, sent nowhere on a gateway).
  Now an allowed save is saved; a blocked save is blocked and the owner gets a notice; a review Sentrook marks
  lenient (on an ok scan of a save declared as a self-edit) is saved and the owner gets a notice that it was let
  through; any other review is held, so not saved, with a notice. A held background save has nothing to approve
  (approving could not make the save), so it is not kept with the approvable held calls and never pushes them out;
  history shows it as not saved. A scan failure is handled as on any unattended run, with its notice. The new
  notices go to the `owner_channel` home channel, at most one of each kind per session every 6 hours.
- A snooze on the session (or every session) lets a background save through that would otherwise be held, with the
  notice, when the save follows a chat or terminal session the owner attends; never after an unattended run, and
  never a blocked save.
- `status` and `verify` say where background-save notices go, and say plainly when they cannot be delivered and how
  to set a home channel. `status` counts background saves let through.
- History marks Hermes's own background saves "(self-edit)", and shows a save let through as
  "allowed (let through, self-edit)".
- The Sentrook tab shows the Sentrook logo in its corner, drawn in the dashboard theme's text colour. The README
  says the name and logo are trademarks, not covered by the MIT licence.

## 2.0.0-beta.14

- A read-only **Sentrook** tab in `hermes dashboard`: recent scans and, for each one, its risk broken down into
  the scores and signals the scanner combined, with the reasons, floors and grants behind them. Changes stay with the
  commands.
- The approval prompt is easier to read and always recognisable as Sentrook's: it starts with
  `🪶 Sentrook security check · risk 62/100`, says what the call does and why in plain words, says what answering
  Always would also set, and ends with `/sentrook why <id>` for the full detail. Reason codes and scores moved to
  `why`. The prompt fits Discord's 300-character limit; the description of the call is shortened first.
- A block a snooze turned into a question: answering Session or Always now lets the same action through without
  asking until that snooze ends. A call that could not be scanned: Session or Always stops the question in that chat
  until Sentrook scans again; another chat or another kind of failure still asks.
- Snooze changes are safe when the gateway, a `hermes cron run` process and the command line change snoozes at the
  same time: a snooze set or ended in one is no longer undone by another. When the snooze file stays locked by
  another process, nothing is changed and the reply says to try again.
- When the gateway resumes a turn a restart or shutdown interrupted, its note is no longer taken as the owner's
  request: the calls carry the interrupted turn's request, and the note is sent as content.

## 2.0.0-beta.13

The 2.0 line, replacing 0.1.x. Needs Hermes v0.23.0 or newer.

- Each tool call is scanned against what the owner asked for in the turn and what the session has done, and is
  allowed, handed to Hermes's approval prompt, or blocked. Turns Hermes starts with its own text (a finished
  background process, a heartbeat, a `/loop` wakeup) are never taken as the owner's request.
- The scan credentials come only through Hermes (the install prompt or `hermes config set`); the plugin no longer
  reads `.env`. Other settings are read from `plugins.entries.sentrook.settings` in `config.yaml`, then from the
  process environment.
- Owner-only commands, in chat (`/sentrook ...`) and on the command line (`hermes sentrook ...`): `status`,
  `verify`, `history`, `why`, `grants`, `grant`, `revoke`, `bind` and `snooze`.
- Grants (destinations, files, providers) and channel bindings tell Sentrook what is normal for you; a review names
  the grant that would allow the call next time.
- Where nobody can answer a prompt (cron, webhooks, the API server), a review holds the call and sends the owner
  one notice on a home channel (`owner_channel`); a call blocked there because the scan failed sends one notice per
  job every 6 hours at most.
- In a chat the owner attends, a high score with no clear attack signal asks instead of blocking, and review
  prompts can be snoozed. Blocks, enforced reviews and unattended runs are never snoozed.
- Hermes's own background skill and memory saves are declared as such and judged against the redacted recent
  conversation (`skill_review: allow`, the default); `skill_review: review` sends them like any other call.
- More secrets are removed before anything is sent: URL passwords, command-line password flags, whole private
  keys and secrets written in prose.
- Review prompts show the scores behind the decision; the agent's block text names a broad category only.

## 0.1.1-rc.1

- Internal: optional local JSONL diagnostic log for maintainers investigating
  review-card copy and scan decisions (off by default).

## 0.1.0-beta.3

- Keep provider prefixes when redacting secrets (`sk-ant-[REDACTED]`,
  `Bearer [REDACTED]`, webhook path) so hosted scan can still match
  secret-shaped rules without receiving key material.

## 0.1.0-beta.2

- Unexpected `pre_tool_call` errors and HTTP 200 bodies with missing/unknown
  `decision` (or invalid JSON) fail closed instead of allowing the tool.
- OIDC mint uses its own 30s budget; `/scan` then gets the full `timeout_ms`.
- Scan-error `rule_key` fingerprints the pending tool and args so Always Allow
  on a timeout cannot skip later timeouts of unrelated commands.
- Blocked (and denied) tool calls no longer linger in the session pending map.
- `webhook` and `homeassistant` are not treated as attended chat surfaces.
- Operator README: uninstall and privacy; configure wizard is production-only.

## 0.1.0-beta.1

- Closed beta line: hosted `/scan` with Hermes `approve` + `rule_key`,
  `hermes sentrook configure|verify`, PlanIR host-tool aliases, unattended/YOLO
  block, and auth never fail-open on 401/403.
