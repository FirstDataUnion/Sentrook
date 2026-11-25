# @firstdataunion/sentrook-openclaw

## 2.0.0-beta.14

### Patch Changes

- 90062c9: The plugin ships two agent skills, which OpenClaw loads while the plugin is enabled: `sentrook-guide` (how Sentrook
  works, so the agent can explain an approval prompt, a block, a held call or a notice, and point you to
  `/sentrook-why` and `/sentrook-report`) and `sentrook-setup` (the agent asks what is routine for you and gives you the
  grant and binding commands to type, one at a time). The agent's system prompt also gets a few short rules from the
  `/sentrook` command: never run the commands that change Sentrook, never edit its settings or folder, never disable
  the plugin, and never retry a blocked call reworded. A read of the plugin's own skill file goes to the scanner as a
  read of the agent's own skills (only when its path resolves to the plugin's own file and it returned the text the
  plugin loaded), so the skill's instructions do not count as content steering the agent; a copy of the text anywhere
  else is read as before. `openclaw sentrook verify` warns when a workspace, project, personal or
  managed skill has the same name as one of these, since OpenClaw would load it instead.
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
- f941490: A call in one of OpenClaw's own background runs (the Skill Workshop review, the memory flush before compaction, the
  skill collection review) that is not a save, such as an exec or a read, is no longer sent to an approval prompt
  when it needs review. Nobody can answer a prompt there: OpenClaw cancelled it at once, or the run ended first, so the
  call was lost without a word and the run could stop before its save. Such a call is now held: it does not run, the run
  is told nobody can approve it and not to retry it, and the owner gets one notice per run where held-call notices go.
  These holds are not kept with the holds `/sentrook-approve` takes. A scan failure there follows the policy for
  unattended runs. Allowed and blocked calls, and the owner's own chats, are unchanged.
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
- c4c9d02: A channel binding or destination grant written `channel:<id>` (or `group:`, `thread:`, or `#<id>`) now reaches the scan of a
  message send that names that channel only by its bare id, as `{channelId: "<id>"}`. Before, the plugin left such a
  binding out of the request, so a send written that way was never relieved by it.
- 0dee5fd: A Code Mode `exec` (the cell of JavaScript that runs other tools) is sent with OpenClaw's own mark that it is one, so
  Sentrook no longer reads its JavaScript as a shell command: an arrow function such as `f => f.name` looked like a
  command writing a file in the working directory, which in the Skill Workshop review (it works in the agent's skill
  folder) read as the agent changing its own setup and could stop the review before it saved anything. Only OpenClaw's
  mark on the hook event counts, never the call's arguments; a shell `exec` is read as before, and every call the cell
  makes is still scanned on its own.
- 627954f: `/sentrook-grant credential NAME@host` ties one of your API keys to the service it is for, such as
  `/sentrook-grant credential MY_SERVICE_TOKEN@api.myservice.example`. Sending that key, read from the agent's env file,
  only to that host is then not treated as sensitive data leaving the machine. The name may end in `*` after three or
  more characters, and the host may be `*.example.com`. A credential grant is persistent unless you give
  `--scope session`; a pattern Sentrook would not read is refused when you type it. When a review is caused by such a
  key going to its own service, the approval card suggests the grant, and **Always allow** sets it as it does other
  suggested grants.
- f8af096: A cron job's own delivery channel counts as yours on that job's run. When a job set up with `--announce --channel
  discord --to <channel id>` has its agent post to that channel with the message tool, the plugin sends that channel
  as a grant for the run, so the post is not treated as going somewhere unfamiliar (what it says is still scanned).
  The plugin reads the job's delivery from OpenClaw's job store (read-only) when the run starts. A channel named in the
  task or in content the run read never counts, nor does a person, a job with no target of its own, or a job changed
  during the run. The dashboard shows that relief as a cron job's delivery target.
- 076e3ff: Cron and heartbeat runs are again sent as runs nobody wrote, whatever requester OpenClaw attaches. Since OpenClaw
  2026.11 a cron run carries its delivery channel as the requester, so the plugin sent it as someone else's message:
  a held call in it never suggested a grant, and a destination the job's own task named got no relief. A run
  flagged as the owner's stays the owner's.
  
  On OpenClaw before 2026.11, a webhook run started in a hook session with trigger `cron` is now sent as a hook run,
  not a scheduled one, so it keeps the sender its requester gives.
- 44dc6bf: The Sentrook tab's explanations now show. Every label, score, signal and badge had a hover hint, but the browser's
  own tooltip does not appear inside the Control UI tab frame in some browsers (Opera GX and DuckDuckGo among them),
  so only the help cursor showed. The tab now draws its hints itself: on hover, on keyboard focus (hinted labels can
  be reached with Tab) and on tap on a touch screen. Escape, moving away or tapping elsewhere hides them.
- 98c7559: The Sentrook tab can show what a call contained. Turn on `dashboardShowCalls` and each scan gets **Show the call**,
  collapsed under its details: the tool and its arguments as the plugin sent them to the scanner (secrets masked, very
  long text cut), with an edit's old and new text side by side. It is off by default, because anyone with gateway
  access can open the tab; with it off, **Show the call** gives the setting and the `/sentrook-report <id> --save`
  command instead.
- 92fd837: A skill the Skill Workshop review (or the skill collection review, or a note the memory flush) saves from the shell,
  with a heredoc, `tee` or `cp` into the skill folder, is now judged as a background save, like one saved with the skill
  or file tools: Sentrook checks it against the conversation the review read, and it is never asked about. It runs when
  the scan allows it, and is otherwise held or blocked, never let through on a review, since a command carries no
  content a draft could keep. The plugin sends each command of these runs with that conversation, and Sentrook treats a
  command as a save only when saving into the run's own skill folder (the day's note for the memory flush) is all it
  does; any other command, including one that saves and also does something else, is scanned as before.
- 837bb3f: Held calls: every answer now does something. Before, `/sentrook-approve <id>` only set the grant Sentrook suggested,
  and on scheduled runs it never suggests one, so approving set nothing and the job was held again on its next run. A
  hold on a cron job now offers, in its notice, only the answers that apply:
  
  - `/sentrook-allow <id>`: the job's next run may make the same call once (`/sentrook-allow <id> later` does the same).
  - `/sentrook-allow <id> always`: the job may make the same call for 30 days, with a use count. Offered only when the
    scan's `owner_pass` says the call may be let through for good and the call names its parties. A scan with no
    `owner_pass` (a scanner that predates it) offers no pass at all: only `/sentrook-deny`.
  - `/sentrook-deny <id>`: the job is refused the same call for 30 days. The agent gets a plain declined result and no
    notice is sent.
  - `/sentrook-approve <id>` stays as `/sentrook-allow` for one release.
  
  "The same call" is matched on the same terms as the Hermes plugin's Session answer: the same tool, the same parties,
  a score no higher, no new warning, nothing enforced and no floor, and the scan's `owner_pass` at or above the pass's
  level. The job is the one OpenClaw's run metadata names on a cron run (`ctx.inputProvenance.jobId`, else `ctx.jobId`),
  never the prompt's `[cron:...]` tag. A call that names nothing is matched on its exact arguments and offered allow once
  only. A hold on a run that is not a cron job offers only allow, bound to the exact arguments, for 7 days. Answering
  never sets the suggested grant: `/sentrook-why <id>` shows its command.
  
  Holds can be answered for 7 days (was 24 hours), and a repeat of a waiting hold updates it without a new notice.
  `holds.json` is version 2 and keeps no raw arguments; older holds stay answerable as before until they expire.
  `/sentrook-passes` lists and revokes the passes and denials (`passes.json`); status, verify and the dashboard show them.
  After allow, the held call's history entry becomes `approved_by_user`, so a retry in the same session is not scored
  as a retry after a review nobody answered. The traffic log records `allowed_by_pass` and `denied_by_owner`.
- d122c22: `openclaw sentrook login` signs in instead of making you copy credentials. It prints a link and a code; open the link
  on any device, sign in or create a free FIDU account, and approve. The command then writes this machine's scan
  credentials to `~/.openclaw/.env` (mode 600, every other line kept) and runs the same checks as `verify`. Signing in
  again from the same machine replaces its credentials (a random id for the machine is kept in the state folder) and
  says when to restart the gateway; `--name` sets how the machine is listed in the account. If credentials are already
  set somewhere that wins over `.env` (plain values in the plugin config, or the gateway's environment), it says where
  and stops before signing in. Ctrl-C ends it at any point with nothing changed. Nothing the identity service
  writes is printed, and never the secret.
  
  Sentrook still stops every tool call while it has no credentials, and now says how to fix it: the block the agent
  reads, the approval card, `/sentrook-status`, `verify` and a warning at startup name `openclaw sentrook login`.
  Credentials the identity service refuses (`invalid_client`: revoked or wrong) say to sign in again.
- daf5a7a: The Sentrook logo: in the corner of the Sentrook tab, drawn in the Control UI's text colour so it fits light and dark
  themes, and as the package icon (`assets/icon.png`) that ClawHub shows on the listing. The README says the name and logo are trademarks, not covered by the MIT
  licence.
- e76bbec: Access codes, PINs, passport numbers and random values under a key or header no longer leave the host raw. A short
  number is redacted after a cue word ("the gate code is …", "Alarm code: …", "collection PIN for order 441 is …",
  "… is your verification code") or under a code or PIN key (`yard_code=`, `client_pin=`, `pin=`, a form's `code=`);
  with no cue it stays, and so do postal, country, status, error and other ordinary codes. A passport number becomes
  `⟦secret:identifier:…⟧`. A random value of 12 or more letters and digits is redacted under any key or header
  (`value: …`, `-H "X-Desk: …"`, a `headers` object), never in prose, and never under a key that names an id, a hash, a
  version, a trace or data; hex values, UUIDs and camelCase words stay. Traffic logs written by earlier versions may
  hold these values.
- 52243a3: A typo in Sentrook's settings no longer gets the plugin disabled. OpenClaw's `doctor --fix`, which the official
  Docker image runs on every start, deleted the settings of a plugin whose config failed its manifest schema and
  disabled the plugin, so a misspelt key or a grant scope such as `"persistant"` left every tool call unscanned with no
  warning. The manifest now accepts any settings and Sentrook checks them itself: a setting it cannot read is ignored or
  replaced, and named in the gateway log at start, on a new `settings` line in `openclaw sentrook verify` (which fails)
  and `/sentrook status`, and in a notice to you at most every 6 hours while it stands.
- a943c3f: The agent gets a second tool, `sentrook_propose_setup` (listed in `contracts.tools`), which the setup skill now uses at
  hand-over instead of giving you commands to paste: it adds up to 20 grants and channel bindings you told the agent
  about, each with a reason of at most 200 characters, to your `/sentrook-setup` list as "proposed by the agent, not seen
  yet". It sets nothing. Each item must be one `/sentrook-grant ... --persistent` or `/sentrook-bind add` would accept,
  and the agent is told which were not added and why; settings, attended platforms and session grants are refused, and a
  key is named, never its value (a key-shaped name is refused); a destination's wildcard may only be `*.` and one
  registrable domain. When the chat had read content no scan had seen yet as the agent proposed, the screen says Sentrook
  could not check what it read just before. Each tool keeps its own markers, and `execute` refuses arguments that changed
  after the hook allowed the call. The agent hears only how many items were added and to ask you to open
  `/sentrook-setup`. A proposal is kept in `proposals.json` for a day, at most three at once. OpenClaw offers it only
  when the sender is the owner, and Sentrook answers only a run started by your own message in a direct chat, with the
  same refusal elsewhere and nothing stored; the call itself is not scanned, its result goes to the next scan, and each
  call is logged as a `setup_proposal` record. The setup report and the proposal share one gate: the one-time marker is
  keyed by the session and the call id, and a call another plugin's tool of the same name answered is logged as
  `foreign_tool`, after which calls of that name are scanned like any call and `status` and `verify` say so.
- c5b5c83: The agent gets a read-only tool, `sentrook_setup_report` (listed in `contracts.tools`), which the setup skill now uses
  at check-in: what is set (counts of grants and bindings by kind, never the grants), the gaps in plain words (a skill
  with the name of one Sentrook ships included), the grants Sentrook suggested on reviews you approved at least twice
  (marked covered when a grant in force already covers one), approved reviews with nothing to suggest by tool, and API
  key names Sentrook saw sent only to their own service, over the last 14 days (`days`, up to 30), saying how far back
  the log actually went. It shows no call's arguments or request text, and every name from a tool call is neutralised.
  OpenClaw offers it only when the sender is the owner, and Sentrook answers only a run started by your own message in a
  direct chat; everywhere else (cron, heartbeat, webhook and event runs, subagents, group rooms, OpenClaw's background
  runs) the whole answer is "Setup needs the owner in a direct chat." The call itself is not scanned, its result goes to
  the next scan, and each call is logged as a `setup_report` record. If another plugin's tool of the same name runs in
  place of Sentrook's, Sentrook records it, scans every later call of that name, and `/sentrook status` and `openclaw
  sentrook verify` say so.
- a5b6fc6: `/sentrook-setup` (owner only; also `openclaw sentrook setup`) lists what would stop Sentrook asking about routine
  work, each item described by Sentrook in its own words with how long it lasts and what to check: a channel binding for
  each cron job's delivery to a room that is not bound yet, a provider grant for each MCP server no grant covers, the
  grant Sentrook suggested on at least two reviews you approved in the last 30 days (from your own message, in a chat
  where the scanner flagged no steering content, and only for exactly that grant: a broader pattern never counts), and
  items the agent proposed, with its reason shown last as a note. Every name and note is shown in a code span, so links,
  mentions and emphasis in them do nothing, and a config entry that is not one plain word is left out and counted. The screen ends with a four-digit code, new each time
  and valid for 15 minutes: `/sentrook-setup apply <code>` sets every item, `apply <code> 1,3` some of them. Grants
  backed by reviews you approved last until revoked, the others 30 days, and channel bindings until removed; `--expires
  90d` or `--until-revoked` changes the grants' lifetime. Applied grants are persistent and say where they came from;
  applying an item twice sets nothing new. `/sentrook-setup discard <id>` drops an agent proposal. OpenClaw keeps a
  command's reply in the chat's transcript, so the agent can read the screen afterwards; everything on it is Sentrook's
  own text, and the code only proves the screen was shown in your chat. The setup skill now sends you to this screen,
  and the agent's rules add `/sentrook-setup apply` to the commands it never runs.
  
  A refused owner command now says where owner commands run: your own direct message to the agent (a sender in
  `commands.ownerAllowFrom`, which your first pairing approval fills), the Control UI, or `openclaw sentrook <command>`
  on the machine. It used to name only the Control UI.
  
  `/sentrook-setup` refuses in a group or channel room, where OpenClaw would still count your message as the owner's
  and the list would be shown to everyone there, and in a chat it cannot tell from one (no session key, or the main
  session while `session.groupScope: "main"` routes rooms into it). The Control UI and the command line are unchanged.
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
