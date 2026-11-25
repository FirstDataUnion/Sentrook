# sentrook (Hermes plugin)

Each release has an entry here, newest first, under a `## <version>` heading that matches `version` in
`plugin.yaml`. The release workflow refuses to run without one, and the catalog pull request quotes the entries
since the version the catalog pins.

## 2.0.0-beta.18

- A credential field's name is no longer redacted as if it were a secret. In text, a value after a password, token
  or API-key key that names such a field or stands in for one (`api_key:api_secret` quoted from an API's docs,
  `password: your_password`, `apiKey=apiSecret`, `token: xxxxxxxx`) or is a short lower-case word
  (`password=changeme`) stays, so a call that quotes documentation is not scored as sending a secret. Values with a
  digit, mixed case or a symbol, vendor shapes such as `sk-live-…` and `ghp_…`, and longer values are redacted as
  before, and so is any value under a credential key in a parsed object.
- **`hermes sentrook login`: sign in instead of copying credentials.** It prints a link and a code; open the link on
  any device, sign in or create a free FIDU account, and approve. Hermes then stores this machine's scan credentials
  with its own writer, and the command runs the same checks as `verify`. Restart Hermes afterwards. Signing in again
  from the same machine replaces its credentials (a random id for the machine is kept in the state folder);
  `--name` sets how the machine is listed in the account. If Hermes does not store the values (managed settings),
  it says so instead of reporting success. Nothing the identity service writes is printed, and never the secret.
- **Install no longer asks for the credentials** (`requires_env` is gone; the two values stay declared as secrets).
  After install, Hermes shows the next step: `hermes sentrook login`.
- **Not signed in, said plainly.** Sentrook still stops every tool call without credentials. The block the agent
  reads, the approval card, `/sentrook status`, `verify` and a warning at startup now say the fix is
  `hermes sentrook login`, or, under `plugins.isolation: host` (no `hermes sentrook` command line), to set the
  credentials in Hermes by hand. Credentials the identity service refuses (`invalid_client`: revoked or wrong) say to
  sign in again.

- The agent gets a second tool, `sentrook_propose_setup` (toolset `sentrook`, declared in `provides_tools`), which
  the setup skill now uses at hand-over instead of giving you commands to paste: it adds up to 20 grants and channel
  bindings you told the agent about, each with a reason of at most 200 characters, to your `/sentrook setup` list as
  "proposed by the agent, not seen yet". It sets nothing. Each item must be one `/sentrook grant ... --persistent` or
  `/sentrook bind add` would accept, and the agent is told which were not added and why; settings, attended platforms
  and session grants are refused, a destination's wildcard may only be `*.` and one registrable domain, and a key is
  named, never its value (a key-shaped name is refused). When the chat had read content no scan had seen yet as the
  agent proposed, the screen says Sentrook could not check what it read just before. The agent hears only how many items were added
  and to ask you to open `/sentrook setup`. A proposal is kept in `proposals.json` for a day, at most three at once.
  It answers only where the setup report does, with the same refusal elsewhere and nothing stored; the call itself is
  not scanned, its result goes to the next scan, and each call is logged as a `setup_proposal` record. The setup
  report and the proposal share one gate: a tool is recognised as the plugin's own only when Hermes's tool registry
  names the plugin's handler, and the one-time marker is keyed by the inputs the handler acts on.
- The agent gets a read-only tool, `sentrook_setup_report` (toolset `sentrook`, declared in `provides_tools`), which
  the setup skill now uses at check-in: what is set (counts of grants and bindings by kind, never the grants), the
  gaps in plain words, the grants Sentrook suggested on reviews you approved at least twice (marked covered when a
  grant in force already covers one), approved reviews with nothing to suggest by tool, and API key names Sentrook saw
  sent only to their own service, over the last 14 days (`days`, up to 30), saying how far back the log actually went.
  It shows no call's arguments or request text, and every name from a tool call is neutralised. Only your own message
  in a direct chat or on the local terminal gets it; everywhere else (group chats, cron, subagents, webhooks, the API
  server, Hermes's background review, the plugin host) the whole answer is "Setup needs the owner in a direct chat."
  `pre_tool_call` decides and leaves a one-time marker the tool needs; the call itself is not scanned, its result goes
  to the next scan, and each call is logged as a `setup_report` record.
- `/sentrook setup` (owner only; also `hermes sentrook setup`) lists what would stop Sentrook asking about routine
  work, each item described by Sentrook in its own words with how long it lasts and what to check: a channel binding
  for each cron job's delivery to a room that is not bound yet, a provider grant for each MCP server no grant covers,
  the grant Sentrook suggested on at least two reviews you approved in the last 30 days (from your own message, in a
  chat where the scanner flagged no steering content, and only for exactly that grant: a broader pattern never counts),
  and items the agent proposed, with its reason shown last as a note. Every name and note is shown in a code span, so
  links, mentions and emphasis in them do nothing, and a config entry that is not one plain word is left out and
  counted. The screen ends with a four-digit code, new
  each time and valid for 15 minutes: `/sentrook setup apply <code>` sets every item, `apply <code> 1,3` some of them.
  Grants backed by reviews you approved last until revoked, the others 30 days, and channel bindings until removed;
  `--expires 90d` or `--until-revoked` changes the grants' lifetime. Applied grants are persistent and say where they
  came from; applying an item twice sets nothing new. `/sentrook setup discard <id>` drops an agent proposal. The
  setup skill now sends the owner to this screen, and the agent's rules add `/sentrook setup apply` to the commands it
  never runs.
- The plugin gives the agent two skills, listed while the plugin is enabled: `sentrook:sentrook-guide` (how Sentrook
  works, so the agent can explain an approval prompt, a block, a held call or a notice, and point the owner to
  `/sentrook why` and `/sentrook report`) and `sentrook:sentrook-setup` (the agent asks the owner what is routine and
  gives the grant and binding commands to type, one at a time). Hermes's system prompt also gets a short section of
  rules: never run the commands that change Sentrook, never edit its settings or folder, never disable the plugin,
  and never retry a blocked call reworded. A Hermes without plugin skills or prompt sections skips them. Viewing one
  of these skills does not count as content steering the agent (the scanner already leaves the agent's installed
  skills out of that check).
  
- **Held calls: every answer now does something.** Before, `/sentrook approve <id>` only set the grant Sentrook
  suggested, and on scheduled runs it never suggests one, so approving set nothing and the job was held again the next
  day. A hold on a cron job now offers, in its notice, only the answers that apply:
  - `/sentrook allow <id>`: the job runs again now and may make the same call once in that run (see below);
    `allow <id> later` lets the job's next scheduled run make it once instead.
  - `/sentrook allow <id> always`: the job may make the same call for 30 days, with a use count. Offered only when
    the scan's `owner_pass` says the call may be let through for good and the call names its parties. A scan with
    no `owner_pass` (a scanner that predates it) offers no pass at all: only `deny`.
  - `/sentrook deny <id>`: the job is refused the same call for 30 days. The agent gets a plain declined result
    ("The owner declined this action for this job, so Sentrook did not run it. Continue without it.") and no
    notice is sent.
  - `/sentrook approve <id>` stays as `allow` for one release.

  "The same call" is matched on the same terms as a Session answer: the same tool, the same parties, a score no
  higher, no new warning, nothing enforced and no floor, and the scan's `owner_pass` at or above the pass's level.
  The job is the one Hermes's run metadata names (`current_cron_execution().job_id`), never prompt text. A call
  that names nothing is matched on its exact arguments and offered `allow` once only. A hold on a run that is not a
  cron job offers only `allow`, bound to the exact arguments, for 7 days. Answering never sets the suggested grant:
  `/sentrook why <id>` shows its command.
- **`allow` runs the job again now.** On a held call of a cron job, `/sentrook allow <id>` sets a one-use pass bound
  to a new run of the job and starts it at once with `hermes cron run <job>` through Hermes's `hermes` launcher (in a
  process of its own; Hermes's `cron.jobs.trigger_job` where the launcher is missing), with no extra prompt. The held
  call is never run by the plugin. The pass serves only that run: the job's first run that starts after the answer,
  other than the held run. When it ends (`on_session_end`, else the job's next scan), the owner gets one line: the
  call went through, the run did not make it, or it made a different call (held as `h-…`); a pass that run did not
  use ends with it. One run per hold. Nothing is started, and the pass waits for the next scheduled run, when the job
  is gone, finished, paused, running, or changed since the hold (a digest of its settings is kept on the hold), or in
  observe mode; the reply says which. When the held run had already sent or written something before the held call,
  plain `allow` waits for the next run and the notice offers `/sentrook allow <id> now`, which starts the whole job
  again with a warning that it repeats what it did. The command's output goes to `run-now.log` in the state folder.
- **Holds** can be answered for 7 days (was 24 hours). A repeat of a waiting hold (same job and call, no higher
  risk, no new warning) updates it and sends no new notice; `status` and `why` say how many times it was held.
  `holds.json` is version 2 and keeps no raw arguments; holds stored before stay answerable as before until they
  expire.
- **`/sentrook passes`** lists the passes and denials your answers set, with use counts and end dates, and
  `/sentrook passes revoke <id>` removes one (`passes.json`, under the same cross-process lock as the holds and
  grants). `status`, `verify` and the dashboard show them; the dashboard's held calls list the answers each offers.
- After `allow`, the held call's history entry becomes `approved_by_user` (after `deny`, `denied_by_user`), so a
  retry in the same session is not scored as a retry after a review nobody answered. The traffic log records calls
  a pass let through as `allowed_by_pass` and calls a denial refused as `denied_by_owner`, with the pass's id.
- **`/sentrook notify here`** sets where Sentrook's notices go (calls held on scheduled jobs and other runs nobody
  watches, scan failures there, Hermes's background saves) without editing the config: the chat you send it in,
  which gets a test notice straight away. When the test notice is not delivered, `notify status`, `status` and
  `verify` say so until a later notice gets through or the target changes. On
  the command line, which has no chat, `hermes sentrook notify <platform>` names a platform with a home channel. When
  Hermes does not say which chat a command came from, `here` uses the platform's home channel and the reply names
  it. A target set this way wins over `owner_channel`, which still works; `notify off` goes back to it, and
  `notify status` says which is in force.
- **`/sentrook attended add|remove|list <platform>`** adds platforms where a person answers Hermes's approval prompts
  (such as an `api_server` behind a UI that shows them) without editing `attended_platforms`. It loosens Sentrook:
  a review there shows an approval prompt instead of holding the call. Only front ends such as the API server,
  webhooks, A2A peers and relays can be added, each with `--confirm` after a warning. Runs Hermes starts itself (cron,
  subagents, batch runs, the curator, kanban workers and the like), Raft and the local terminal can never be added;
  unknown names are refused with the known list.
- Both commands are owner-only and recorded in the traffic log and the Hermes log by platform, never a chat id; kept in
  `settings.json` in the plugin's folder, and blocked when the agent runs them as `hermes sentrook …`. `status`,
  `verify`, `help` and the commands themselves explain where notices go and which platforms are attended in the
  same plain words.
- **Session** on a review now covers the rest of the same job in that chat. Hermes remembers a Session answer under a
  key made of every file and address the call touches, so a job whose steps each wrote a different output file asked
  at every step, and Session did no more than Once. When the owner asked for the work in their own chat, a Session
  answer now also lets a later review in the same chat through without asking, for 12 hours, when it is a call of
  the same tool about the same parties (the entities the review's reasons and its description of the call name),
  scoring no higher, with no warning the answered review lacked, nothing the scanner enforced and no floor. Every
  reason code is a warning except the scanner's scoring and wording notes (the judge's own reasons, relief, a plain
  send to a party new to the library) and the background of what the session has been reading, so a code the
  scanner adds later asks; each answer is matched on its own. Another party, a higher score, another
  tool, another chat, a block, a block the scanner capped to a review, or an answer from another chat asks as before;
  so does any review that names no party. History records such a call as allowed (the owner was not shown it) and the
  scan record says `session_allowed`. **Always** is unchanged.
- **Session** also sets the review's suggested grant for that session only (bound to its `session_ref`), as
  **Always** sets it for 30 days, so the scanner scores later calls with it; with that grant set, Session skips no
  further questions. The prompt says what Session covers: "also covers the same parties at no higher risk", "covers
  only this exact action", or, with a suggested grant, one line for Session and Always.
- Access codes, PINs, passport numbers and random values under a key or header no longer leave the host raw. A short
  number is redacted after a cue word ("the gate code is …", "Alarm code: …", "collection PIN for order 441 is …",
  "… is your verification code") or under a code or PIN key (`yard_code=`, `client_pin=`, `pin=`, a form's `code=`);
  with no cue it stays, and so do postal, country, status, error and other ordinary codes. A passport number becomes
  `⟦secret:identifier:…⟧`. A random value of 12 or more letters and digits is redacted under any key or header
  (`value: …`, `-H "X-Desk: …"`, a `headers` object), never in prose, and never under a key that names an id, a
  hash, a version, a trace or data; hex values, UUIDs and camelCase words stay. Traffic logs written by earlier
  versions may hold these values.
- The plugin's manifest declares its licence as MIT, as the code always was. It said Apache-2.0, which Hermes showed
  as the plugin's licence.
- A call Hermes's own background review or curator makes that is not a skill or memory save, such as a file read or a
  terminal command, is no longer sent to an approval prompt when it needs review. Nobody can answer a prompt there:
  on the terminal Hermes denied it unseen, and on a gateway it reached nobody, so the call was lost without a word and
  the review could stop before its save. Such a call is now held: it does not run, the review is told nobody can
  approve it and not to retry it, and the owner gets one notice per session in the quiet period at the
  `owner_channel` home channel. These holds are not kept with the holds `/sentrook approve` takes. A scan failure
  there follows the policy for unattended runs, and the record says `background_run: true`. Allowed and blocked
  calls, an owner's `/refine` and the owner's own chats are unchanged.
- A turn Hermes builds around skills (a skill's slash command, or a cron job that lists skills) sends the owner's
  words as the request, not the skills' whole text. Hermes puts each invoked skill's text into the message ahead of
  the owner's instruction; sent whole, every host and command a skill names counted as the owner's own words, and on
  a cron job with large skills the scanner's judge could see the skills but not the job's prompt. The request is now
  the instruction after the skills, and for a cron job the cron hint, the run time and the job's prompt, taken from
  the job's own record. Text that is exactly an installed skill's own text is left out, as the agent's standing
  instructions. Anything else that is not the owner's words goes to the scanner as untrusted content, once per turn:
  a cron job's context blocks (its previous output, another job's output, a pre-run script's output), a runtime
  note, text around a skill, and a block that does not match an installed skill (a typed wrapper hides nothing).
  Without the job record, everything after the skills is the request, as before.
- A destination grant or binding written `channel:<id>` (or `group:`, `thread:`, or `#<id>`) is sent with a scan whose call
  names that channel by its bare id, as OpenClaw's message tool writes it in `channelId`. Kept the same as the
  OpenClaw plugin, so both send the same grants for the same call.
- Held-call, scan-failure and background-save notices reach the `owner_channel` home channel again. The plugin sent
  them through Hermes's `send_message` tool, which Hermes 0.23 does not register in any process (the gateway, the
  desktop app's `hermes serve`, the command line or cron), so on Hermes 0.23 every notice failed with "Unknown tool:
  send_message", while the record said it was queued. They now go out with Hermes's own `hermes send` command, from
  the same notice thread, so a cron job's own delivery target still cannot swallow them. The `send_message` tool is used only on a Hermes that registers it and has no `hermes send`. A
  `MEDIA:` path in a notice (a call's target can name one) is never sent as an attachment.
- Where a Hermes process has neither, the plugin says so instead of failing quietly: a warning when it starts,
  and `/sentrook status` and `hermes sentrook verify` say that notices cannot be sent from that process and why.
  A call held there is still held, and its record says the notice is `unsent`, with the reason, not `queued`. The
  same goes for a turn a Hermes process serves for another profile's home: `hermes send` would use the process's own
  profile's platform account, so that notice is not sent with it.
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
