# sentrook (Hermes plugin)

Each release has an entry here, newest first, under a `## <version>` heading that matches `version` in
`plugin.yaml`. The release workflow refuses to run without one, and the catalog pull request quotes the entries
since the version the catalog pins.

## 2.0.0-beta.18

- New setting `dashboard_show_calls` (off by default): each scan in the Sentrook dashboard tab gets **Show the call**,
  the tool and its arguments as the plugin sent them to the scanner (secrets masked, very long text cut), with a
  patch's old and new text side by side. Off, the tab still shows no call content, and **Show the call** gives the
  setting and the `/sentrook report <id> --save` command.
- The Sentrook dashboard tab draws its hover hints itself, on hover, on keyboard focus (hinted labels can be reached
  with Tab) and on tap. Before, they were the browser's own tooltips, which never show on a touch screen and do not
  show inside OpenClaw's tab frame in some browsers; the tab shares its page script with OpenClaw.
- The Hermes TUI and the Hermes desktop app count as attended, whether or not Hermes has a terminal: a review there
  is asked with Hermes's own approval card, and a snooze reaches Hermes's background saves after a session there.
  Before, both were judged by the terminal test the plain command line uses, and neither has a terminal (the TUI
  talks to Hermes over a pipe, and the desktop app talks to a gateway that may run as a service, on this machine or
  another). So every review from them was held, with its notice sent to the `owner_channel` home channel, and no
  card ever reached the app. The plain command line still needs a terminal, and the API server, cron, sub-agents,
  webhooks and the curator are unchanged.
- With Hermes's `plugins.isolation: host`, the plugin runs in Hermes's plugin host, where it cannot tell Hermes's
  background skill and memory saves from your own calls: they are scanned like any other call, without the
  conversation they follow, and are never held, staged or announced as background saves (a save Sentrook would ask
  about becomes an ordinary approval prompt, or on the local terminal is refused by Hermes's review). The plugin now
  says so: a warning when it starts and a `background saves: not recognised` line in `/sentrook status`, both naming
  the fix (`plugins.isolation: in_process`, Hermes's default). The README also notes that Hermes offers no
  `hermes sentrook` commands in that mode. Nothing changes in-process.
- The chat platforms Hermes 0.23 ships count as attended: Microsoft Teams, Google Chat, IRC, LINE, SimpleX,
  BlueBubbles (iMessage), Photon, Buzz, ntfy, QQ Bot, Weixin and the WhatsApp Cloud API join the platforms already
  listed. Before, a chat on one of them was judged by the terminal test, which a gateway running as a service fails, so
  a review there was held instead of asked, and a snooze never reached a background save after that chat. Raft stays
  unattended (Hermes's Raft adapter sends nothing into the chat, so an approval prompt reaches nobody), as do A2A peers,
  the API server, webhooks, relays, cron, batch runs, sub-agents, the curator and kanban workers. The desktop app's hosted bot
  rooms count as attended (the room shows Hermes's approvals), and an editor connected over ACP (Zed, for example)
  counts as attended like the TUI: Hermes shows its approval in the editor, and it never has a terminal. The compatibility check now fails on a Hermes that adds a
  platform the plugin has not classified as attended or not.
- `/sentrook grant credential NAME@host` ties one of your API keys to the service it is for, such as
  `/sentrook grant credential MY_SERVICE_TOKEN@api.myservice.example`. Sending that key, read from the agent's env
  file, only to that host is then not treated as sensitive data leaving the machine. The name may end in `*` after
  three or more characters, and the host may be `*.example.com`. A credential grant is persistent unless you give
  `--scope session`; a pattern Sentrook would not read is refused when you type it.
- When a review is caused by such a key going to its own service, the prompt suggests the grant, and **Always** sets
  it as it does other suggested grants.

## 2.0.0-beta.17

- Report a scan that looks wrong. `/sentrook report [id|last]` (owner only; `hermes sentrook report` on the command
  line) prints a report to copy and send to Sentrook: what `/sentrook why` shows, plus the host, plugin and scanner
  versions from the scan's own record, and two lines to fill in (what you expected, what you were doing). It holds no
  call arguments or conversation text. `--github` gives a link that opens a public GitHub issue with the report filled
  in. `--full` adds the full record, the scan's traffic-log lines exactly as written, so Sentrook can replay the scan;
  it can hold conversation text, paths and addresses, so it is only for private sending, never an issue. `--save`
  writes the report and full record to a file only you can read, to email to sentrook@firstdataunion.org (kept for up
  to 30 days, then deleted).
- In the Sentrook dashboard tab, every scan has **Report this scan…**: the report to copy, the GitHub button, and the
  commands and email address for the full record, which the tab never shows.

## 2.0.0-beta.16

- A background skill or memory save that Sentrook holds is no longer lost where Hermes can replay it: it is staged in
  Hermes's own pending list, and the owner's notice gives its id and the commands to look at it and approve or reject
  it (`/skills diff <id>`, `/skills approve <id>`, `/skills reject <id>`; `/memory pending`, `/memory approve <id>`,
  `/memory reject <id>`). Hermes's `write_approval` settings do not need to be on. Staged: new skills, skill edits
  and patches, writing or removing a skill's file, and memory additions (alone or in a batch). Still held and lost:
  skill deletes, saves Sentrook finds a secret in, saves too large to scan whole, blocked saves, and every save with
  `skill_review: review`.
- Changing or removing memory entries in Hermes's unattended background review is left to Hermes's own gate, which
  stages it, only on Hermes builds the plugin has verified (0.23.0 to 0.23.2); the notice says what Hermes did. On any
  other build, and for the rest of the process once Hermes saved such a change without the owner, it is held as
  before.
- The plugin writes each pending entry's summary itself (never the saved text), makes the staged file readable by the
  owner only, and keeps at most 20 of its own entries waiting in each list. History shows a staged save as
  "staged ... pending in Hermes", and `status` counts staged saves.

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
