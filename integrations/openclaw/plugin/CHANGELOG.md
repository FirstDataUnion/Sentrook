# @firstdataunion/sentrook-openclaw

## 2.0.0-beta.16

### Minor Changes

- 1891003: Trusted chats can now be a whole Discord server: `/sentrook-trust-chat add discord:server:<server id> --confirm` (or
  the same text in `trustedChats`) covers every channel and thread in it, including ones created later. OpenClaw names a
  room's server on the messages it receives, so a room matches once a message there has named its server (OpenClaw
  2026.11.2 or later; an older OpenClaw refuses the entry). Direct messages from its members are not covered, and a
  channel id is never taken for a server id. `--owner-only` works as for a chat. Only Discord servers for now: a server
  entry on another platform is refused. `list` marks whole servers, `openclaw sentrook verify` has a trusted-chats line
  that says whether a server has been seen yet, and the setup skill and setup list suggest a server only where you know
  every member and who can join.

### Patch Changes

- 35ad866: The agent's setup tools (`sentrook_setup_report` and `sentrook_propose_setup`) are now offered when OpenClaw's config
  sets a tool profile (`tools.profile`, for example `coding`): the plugin manifest lists them for every profile, so the
  agent can help you set Sentrook up. `openclaw sentrook verify` warns when a `tools.allow` or `tools.deny` list (global
  or one agent's) still hides them, with the setting to change; `/sentrook-setup` works either way.

## 2.0.0-beta.15

### Minor Changes

- 751e2c9: Trusted chats and users. `/sentrook-trust-chat add <platform>:<chat id> --confirm` marks a group chat or server
  channel where you know every member as trusted, and `/sentrook-trust-user add <platform>:<user id> --confirm` a person
  you know (`list` and `remove` too; `trustedChats` and `trustedSenders` in the config do the same, and `trustedSenders`
  now takes `<platform>:<user id>` as well as a bare id). Their messages are sent to the scanner as from someone you
  trust, not a stranger, and never as yours: grants, settings and every Sentrook command stay yours, a trusted turn never
  sets a grant when its review is approved, and the scanner's floors apply as before. A thread or topic in a trusted chat
  is covered; a direct chat is never a trusted chat. Each command warns first and needs `--confirm`, runs only where the
  other owner commands run (never in a group or channel), and is logged by platform only.
  
  Reviews in a trusted chat are answered as OpenClaw allows there. A chat added with `--owner-only` (or `owner_only:
  true` in the config) holds a review on anyone's turn but yours for you instead: the agent says in the chat that it is
  waiting, you get a notice where `/sentrook-notify here` sends them, and `/sentrook-allow <id>` lets that exact call
  through once.
  
  The agent's setup proposals can now include a trusted chat or user, shown on `/sentrook-setup` with its warning and
  set from there; the setup report counts the trusted chats and users and lists the group chats the agent was used in.

### Patch Changes

- 8ba56c8: Held calls: `/sentrook-allow <id>` on a held call of a cron job now runs the job again straight away, instead of
  waiting for its next scheduled run. The plugin sets a one-use pass bound to the new run and starts it with
  `openclaw cron run <job> --json` as a child process (the gateway's own OpenClaw, else `openclaw` on the PATH), with no
  extra prompt; it never runs the held call itself. The pass serves only the run that command returns, as the job's
  running receipt in OpenClaw's job store names it. When that run ends (`agent_end`, else the job's next scan), you get
  one line on where notices go: the call went through, the run did not make it, or it made a different call (held as
  `h-…`); a pass that run did not use ends with it. One run per held call.
  
  Nothing is started, and the pass waits for the job's next scheduled run, when the job is gone, finished, disabled,
  running, or changed since the hold (a digest of its definition is kept on the hold), when OpenClaw refuses the run, or
  in observe mode; the reply says which. When the held run had already sent or written something before the held call,
  plain `allow` waits for the next run and the notice offers `/sentrook-allow <id> now`, which starts the whole job again
  with a warning that it repeats what it already did. `/sentrook-allow <id> later` keeps the wait-for-the-next-run answer.
  The notice, the replies and the outcome line are the same text as the Hermes plugin's.
- 4f4f096: **Allow always** is now offered on a review of an MCP tool call you asked for yourself, even when no grant would cover
  it, and it covers that tool on that server for 30 days, in any session: a later call of the same tool on the same
  server (its configured address or package), whatever page or file it writes, at most 10 points higher and below the
  block line, with no new warning, goes through without asking. Before, the card offered only **Allow once** there, so
  every call of an MCP write tool asked again. Another tool, another server, a host, recipient or channel the answered
  call did not name, a floor, a rule that always asks or a block still asks; a group chat is offered no **Allow
  always**. The card says so, `/sentrook-grants` lists these answers and `/sentrook-revoke <id>` removes one.
- 2c4fcf9: If you withdraw consent on the FIDU portal, the identity service stops accepting this machine's scan credentials.
  Sentrook then tells you once, where notices go and in observe mode too, that scans stopped and how to connect again
  (`openclaw sentrook login`), switch to observe mode or uninstall, instead of a scan-failure notice per job. It is sent once for
  these credentials, also across restarts; signing in again or setting new credentials resets it. Calls are handled
  as for any credential problem: asked where you can answer, blocked where nobody can (and with `onScanError: allow` too), run
  in observe mode; the prompt, the agent's message and `verify` say consent was withdrawn.
  
  `openclaw sentrook login` now prints what each check sends and to whom, the privacy policy, the terms and how to stop, with the
  terms version you accepted (and when) if the identity service gives it.
- c837463: A destination grant over a whole public suffix is refused. A destination may use a wildcard on a host or a mail domain
  only as `*.` and one registrable domain (`*.example.com`, `*.example.co.uk`, `*.myname.github.io`), or as `*.` and a
  name that never resolves on the public internet (`*.lan`, `*.local`, `*.internal`, `*.test`, `*.example` and the
  like). `/sentrook-grant destination *.com` is refused with the reason, and so is a wildcard over another top-level
  domain or a common shared suffix where anyone can get a name (`*.co.uk`, `*.ne.jp`, `*.github.io`, `*.vercel.app`,
  `*.amazonaws.com`; the common ones, not every one), or inside a name (`api*.example.com`), as Sentrook ignores such a
  grant: it would let calls reach sites run by strangers. A wildcard in a channel's name (`discord:#daily-*`) or before
  an `@` (`*@example.com`) is still taken. Such a grant in `openclaw.json`, or one already in the grants file, is never
  sent: `/sentrook-grants`, `/sentrook status` and `openclaw sentrook verify` list it as too broad, and the other grants
  still apply. A channel binding like it is listed as too broad and never sent. A credential grant's host follows the
  same list of shared suffixes. A wildcard address such as `192.168.1.*` is refused too, and one already in the config
  is listed as too broad and never sent: write the exact hosts instead. A bare name with a wildcard such as `daily-*` is
  refused as a destination, as it would match hosts too: write `#daily-*` or `discord:#daily-*` for channel names.
- ea1ddde: The `sentrook-guide` skill's "Working well with Sentrook" section adds one habit: when the agent asks you to confirm
  something, it writes out in that message what it will do (the service or place, and what it will send, write or
  change), since Sentrook reads the agent's last message beside a short reply such as "yes" to see what you agreed to.
- ea9d9d6: `/sentrook-dismiss <id>` (or `/sentrook-dismiss all`) takes a held call off the waiting list without answering it, as
  if it had expired now. It works on any hold, including one that offers no answer (a run with no source, or a hold
  from an earlier version) and one you would rather not deny for 30 days. The call never runs and nothing is set: no
  pass, denial or grant, and a call like it is held again with a notice. Each dismissed call is recorded in the traffic
  log with the resolution `hold_dismissed`, and `/sentrook-history` shows its review as `dismissed`. Like the other
  answers, it is for the owner only and the agent is told never to run it.
  
  The dashboard's **Waiting for you** section now folds: click its heading to fold it away, and the tab remembers that
  in your browser until something newer is waiting. It shows the first three items with the rest behind **Show more**,
  and names `/sentrook-dismiss` on each held call and `/sentrook-dismiss all` when more than one is waiting.
- c03ff84: An unattended run keeps the scanner's `cap.local_code` ceiling, as it keeps the ceiling on a retry of a review nobody
  answered, so both plugins decide the same from the same response. The scanner sets it only for Hermes `execute_code`
  programs today.
- 1842c1b: Held calls on runs that are not cron jobs now bind to where the run came from. A heartbeat's hold is bound to its
  agent (`ctx.agentId`), and a subagent's to its parent session (the requester session the spawn hooks report). Such a
  hold offers `/sentrook-allow <id>` (a one-use pass for the next matching call from the same source within 7 days;
  nothing is started), `/sentrook-allow <id> always` where offered, and `/sentrook-deny <id>`, each bound to that
  source; the notice and the replies name it, and `/sentrook-passes` lists each pass by its source. The same call from
  another agent's heartbeat or another parent session is held again. A webhook or event run keeps allow alone, bound
  to the exact arguments: OpenClaw gives plugins no hook or mapping id, and the run's ids are new for every request.
  Sources are never read from the prompt or the call, and the stored ref is a hash. The texts are the same as the
  Hermes plugin's.
- d5ce557: With no notify target set, a held call's notice (and a run's end line, and the line on how a started run went) no
  longer goes nowhere: it goes to the chat the cron job delivers its own output to (an `announce` delivery that names
  its `channel` and `to`), else to your direct message when `commands.ownerAllowFrom` names exactly one owner on a
  channel OpenClaw has configured. It never goes to a chat the job does not deliver to, and it ends with a line saying
  where it went and how to set a target. While calls are held with no target set, `/sentrook status` warns, `verify`
  fails its held-call notices check and the setup report lists it as its first gap. The setup skill now asks for
  `/sentrook-notify here` right after checking the install.
- 349f915: On OpenClaw 2026.11.3 or newer, where tool search's dispatcher is named `dispatch_action` (it was `tool_call`, which
  OpenClaw still accepts), the dispatcher is again not scanned itself: only the call it runs is, once, as before. Until
  now each such call was scanned twice, once as a `dispatch_action` call of unknown kind and once as itself, the plugin's
  own setup tools got a scan of their dispatcher that could raise a review, and the history sent with a scan showed the
  bare dispatcher instead of the call it ran. A dispatcher beside the call being scanned is shown as the call it runs,
  under either name. Both names are handled on every supported OpenClaw (2026.9.5 or newer). A call by either name
  is skipped only when it names a tool the way the dispatcher takes it; any other call by that name (another plugin's
  or a client's tool of the same name) is scanned like any call.
- dc7a53b: A read of the plugin's own `sentrook-setup` or `sentrook-guide` skill now counts as a read of the agent's own skills
  again on OpenClaw 2026.11, which runs plugin code from a copy of the installed folder: the plugin also accepts the
  folder OpenClaw installed it in (where `~/.openclaw/plugin-skills/` points), with the same checks as before (the text
  the plugin loaded, a regular file, no link leading elsewhere). Before, the skill's instructions counted as content
  steering the agent, so a setup chat asked about calls it should not have. The `sentrook-setup` skill also tells the
  agent never to read Sentrook's folder or traffic log and to call the `sentrook_setup_report` tool instead.
- 746b64d: Every owner command (`/sentrook-history`, `/sentrook-why`, `/sentrook-report`, `/sentrook-grants`, `/sentrook-grant`,
  `/sentrook-revoke`, `/sentrook-bind`, `/sentrook-snooze`, `/sentrook-allow`, `/sentrook-deny`, `/sentrook-approve`,
  `/sentrook-passes`, `/sentrook-notify` and `/sentrook-setup`) now refuses in a group or channel room, even from the
  owner. OpenClaw decides the owner by the sender, not the room, and keeps a command and its reply in the room's
  transcript, so recent scans, hosts, file paths, reasons and grants were shown to everyone there. As `/sentrook-setup`
  already did, they also refuse in a chat the plugin cannot tell from a room (a chat channel with no session key), and
  in the agent's main session while `session.groupScope` routes rooms into it, from the Control UI too, since that
  transcript is the rooms'. A thread or topic counts as the chat it is in, so one in your own DM still works. The reply
  says to run the command in your own direct message to the agent or the Control UI, in a session no room shares, or as
  `openclaw sentrook <command>` on the machine; each refusal is recorded in the traffic log with the reason
  `group_chat` or `unknown_chat`.
- e519487: An owner command sent in a group or channel room now gets a shorter reply that starts with where it does run (your
  own direct message with the agent, the Control UI or the machine) and says a private server channel counts as a room
  too. The refusal for someone who is not the owner also says a group chat or server channel,
  even a private one, never runs an owner command.
- 6a60455: A channel binding or a cron job's delivery grant written with its platform (`discord:<channel id>`) now applies to a
  send that names only the account it posts as (`{action: send, target: "channel:<id>", accountId: <a Discord
  account>}`), as OpenClaw's message tool often writes one. Until now such a grant was sent only when the call named the
  platform in its own `channel` argument, so a scheduled job announcing to its own channel was still held. The plugin
  takes the platform from the account (`channels.<platform>.accounts.<id>` in OpenClaw's config, ids compared without
  case; an account on two platforms gives none), else, with no account or the implicit `default` one, from the session's
  own chat platform, and sends it to the scanner as `pending_call.send_platform`. It counts only for the platform-prefix
  form: a bare id is then sent only as a channel target (`channel:<id>`, `group:`, `thread:`) or a whole argument, never
  for a direct message (`user:<id>`, `dm:<id>`), also when the send names its platform. `openclaw sentrook verify` lists
  the channel bindings no message send in the traffic log would carry, the setup report counts them as a gap, and the
  setup skill says which form to write on OpenClaw.
- 8ecc06e: A Google Drive, Docs or Sheets file or folder id is no longer redacted as a secret where the call names Google. Since a
  value that looks random under a key is redacted, an id in a Drive query (`parents='<id>'`) or in a script that works on
  documents (`const PLAN = "<id>"` beside `documentId`, `textRun`, a Google API host or client library, or a Drive or Docs
  tool such as `drive_files_list` or `docs_get`) became a placeholder: the scanner could not see which document or folder
  the call reads or writes, and counted the id as a secret being sent. Such an id now stays when its own text, or for a
  value in a call's arguments its own object, names Google. A value of that shape with nothing naming Google, any value
  under a credential key, a key with a secret word in it (`SESSION_KEY`, `Authorization`, `connect.sid`, `cookie`, `hmac`) or a custom `X-`
  header, and every other random value are redacted as before.
- 6f1672c: A credential field's name is no longer redacted as if it were a secret. In text, a value after a password, token or
  API-key key that names such a field or stands in for one (`api_key:api_secret` quoted from an API's docs,
  `password: your_password`, `apiKey=apiSecret`, `token: xxxxxxxx`) or is a short lower-case word (`password=changeme`)
  stays, so a call that quotes documentation is not scored as sending a secret. Values with a digit, mixed case or a
  symbol, vendor shapes such as `sk-live-…` and `ghp_…`, and longer values are redacted as before, and so is any value
  under a credential key in a parsed object.
- 52eff45: A command piped from, substituted or run straight after a password or token is no longer hidden inside its
  placeholder. An unquoted value after a key or in a sentence (`TOKEN=<value>|curl …|sh`, `TOKEN=<value>$(…)`,
  `TOKEN=<value>;curl$IFS/x|sh`, `password: <value>;curl …`) used to run on through the `|`, `$(`, `;` or `&` and the
  command after it, so the scanner never saw that command. A value now ends at `$(`, and at a `|` followed by a command:
  a word with more after it on its line (`|curl …`, `|7z x`), a word before `;` or `&&` and
  another command (`|reboot;echo …`), or a command led by a symbol (`|$(…)`, `|$SHELL`, `|(…)`, `|{curl,…}`,
  `|./run.sh`, `|/bin/sh`). A value written `key: <value>` or in a sentence now ends where one written `key=<value>`
  does. Anywhere else `|` and `$` stay part of the value (`password=<value>|<rest>`, `pa$sword`), and so do a `|` after
  an opening quote and a lone word after a `|` at the end of a line (`TOKEN=<value>|sh`), as a password's tail would be,
  and so does a word with a glob or a `$@`-style parameter inside it after a `|` (`|c*rl …`, `|cu$@rl …`).
  Backticks, `<` and `>` already ended a value.
- 59f3e83: A quoted example value that only stands in for a secret is no longer redacted as if it were one, so docs and notes
  that show a token file's shape can be saved into a skill or memory without being scored as saving a secret. Kept under
  any key: the word `REDACTED` and a mask of `*`, `•` or `·` (`"••••••••"`). Kept only in a quoted value under a token
  or key that does not name a password: a token cut short with an ellipsis after at most ten token characters
  (`"access_token": "ya29.a0..."`, `"refresh_token": "1//0g..."`), and a short phrase that says what it is
  (`"short-lived token"`, `"your api key"`). Still redacted as before: a full token, with or without an ellipsis;
  anything under a password (`"password": "<short value>..."`, a passphrase); a phrase that does not say what the value
  is; a value after a command-line flag, `mysql -p` or `sshpass -p`; an unquoted value before an ellipsis; and any value
  under a credential key in a parsed object.
- 1409602: A password or token with `&`, `,` or `;` in it is now redacted whole. After a key in an assignment, an `.env` line or
  a quoted value (`password=<value>&<rest>`, `export DB_PASSWORD=…`, `password='…'`) the value used to end at the first
  of these characters, so the rest of it left the machine as written, and the same password written `password: …` got
  another placeholder. What follows a value is still kept where it is something else: another parameter in a link's
  query or a form body (`?password=…&page=2`, `user=a&password=…&remember=1`), the next key of a list or a connection
  string (`a=1,b=2`, `;Initial Catalog=…`), an HTML entity (`&quot;`), and a command or statement after the value (`…;
  echo ok`, `…;npm publish`, `…&&next`, `…;$(…)`, `…;./run.sh`, `…;return x`), so the scanner still sees it; in double
  quotes a value ends where `$(` starts. A lone command word at the end of a line after a value (`TOKEN=…;make`) is read
  as part of the value, as a password's tail would be.
- 6443f9e: The `sentrook-guide` skill has a new section, "Working well with Sentrook", on shaping work so Sentrook can judge it
  clearly: fetch web pages and APIs with OpenClaw's own web tools rather than HTTP in code; keep code local (a code or
  shell call that reads local files does not also reach the network); install packages once, early, in a chat with the
  owner, not in cron jobs, heartbeats or subagents; keep a task's files in one work directory; refer to keys by name;
  and when a call is held or blocked, tell the owner and point to `/sentrook-why` rather than try it again in a new
  shape. It says plainly that this is about clear scans, never about getting past a check.
- 57b2c43: `/sentrook-setup` and the setup report count a chat as having read content that tried to steer the agent only when
  one of its scans gave an `exposure.*` reason: the scanner's own line for it, and every later call of a chat it judged
  tainted carries one. The exposure scores alone no longer count, since almost any content scores a little, so the
  screen warned about nearly every proposal from the agent and left out reviews you approved in ordinary chats.
- fbcd2d1: The setup skill now starts by making sure approval cards reach your chat apps: it reads `commands.ownerAllowFrom` and
  each app's `execApprovals` and gives you the `openclaw config set` commands to run in a terminal (Discord needs its
  cards switched on, WhatsApp and Signal need `approvals.plugin` forwarding to the chat the request came from). It never changes those settings
  itself. It suggests doing the first setup in the Control UI or `openclaw tui`, works out what is routine from the
  agent's own cron jobs, skills, MCP servers and the setup report instead of asking you a list of questions, shows a
  short list to keep or drop, and ends with how to get help when regular work is blocked later. The install guide has a
  new section, "Approval cards in chat apps".
- 3e43c07: When you answer the agent with a short message (300 characters or less, such as "yes", "go with A" or "try again"),
  each call of that run also sends the agent's last message before it, so the scanner can see what you agreed to
  instead of reading your reply alone. It is sent as the agent's words, never as your request, redacted and cut to 2,000
  characters (start and end), and only with `allowConversationAccess`. It is not sent with a longer message, someone
  else's message, a scheduled run or a sub-agent.
- 3061552: `/sentrook-why` now shows the call itself (the tool's arguments as sent to the scanner: secrets masked, long text
  cut), and a background-save notice shows the save it is about, marked as data, so you can judge it without opening the
  dashboard. The dashboard shows each scan's call by default too. One new setting, `hideToolCalls`, hides calls in all
  three places; `dashboardShowCalls` is no longer needed and does nothing. A report's summary never carries the call.
- a5463ce: Beta: while a snooze is on, a block in a chat you attend asks you instead of stopping, whatever caused it: a floor, a
  strong signal or a rule that always blocks included. Until now only a block Sentrook marks as having no clear attack
  signal asked, so a false alarm with a floor left no way past but switching Sentrook to observe. That prompt keeps its
  wording ("Would be blocked, but a snooze is on."). Any other block gets a stronger warning: it names why it would be
  blocked and says "A snooze is on: allow only if you asked for exactly this call." Both are at critical severity, offer
  **Allow once** and **Deny** only, and ask again on the next call; the stronger one suggests no grant, and while the
  snooze lasts an action asked about either way asks with the stronger warning again even when it is scored later as an
  ordinary review. The stronger one needs a complete scan: when one of Sentrook's checks failed, the block stays a
  block. A change to Sentrook itself (its files, settings or log, turning the plugin off, stopping the gateway, a
  Sentrook command only you should run, loosening the host's approvals), and any block that may be one, stays a block
  during a snooze; so does a block with a floor or a strong signal on email, SMS, IRC or ntfy, where anyone can claim a
  sender. Nothing changes on unattended runs, for other senders, in group rooms, in observe mode, on
  scan errors or without a snooze. The snooze reply, `/sentrook-snooze status`, the guide and the agent skill say so.
  The traffic log marks such a prompt with `relaxed_strong: true`.
  
  A turn OpenClaw starts with trigger `user` whose input came from another session (`sessions_send` from another agent)
  or from the host itself is no longer read as your own message, even with an owner-flagged requester: it never reaches
  a snooze prompt, a snoozed review there asks, and approving never sets a suggested grant. Cron runs are unchanged.
- 178a6c3: A subagent's run is now sent as a subagent's. OpenClaw starts a subagent's run (session `agent:<id>:subagent:<uuid>`)
  with trigger `user` and no provenance, so the plugin sent it as the owner's message and asked: under a cron job too,
  and the prompt never reached anyone, because OpenClaw refuses a plugin's approval request from a subagent's run (its
  gateway identity has no approvals scope) and the call was blocked with no notice. Such a run is now sent as trigger
  `subagent`, and a review in it is held for the owner, bound to the parent session, with the usual notice: whether
  the subagent was started by a cron job, a heartbeat, an event run, someone else's message or the owner's own chat,
  and whatever `approval.scheduledIntentKinds` says. Blocks stay blocks.
- 9c1b91b: The local traffic log keeps records for 30 days. As it writes (at most once an hour), the plugin deletes older records
  from `traffic.jsonl` and its rotated copy `traffic.jsonl.1`: a file holding only older records is deleted, and one that
  holds both is rewritten without them. `/sentrook-history`, `/sentrook-why`, `/sentrook-report` and the dashboard show
  what is inside those 30 days.
- 8de3436: Trusted folders: `/sentrook-grant folder <dir>` trusts a folder you write and maintain, such as the repository your
  jobs' instructions live in. A file the agent reads from it with the `read` tool, unchanged since you set the grant, is
  sent with `trusted_by`, and Sentrook reads it as your own words: it no longer makes the chat count as exposed to
  untrusted content. Nothing else is relieved. The plugin records the folder when you set the grant (in a git repository
  the commit checked out; elsewhere each file's sha256); an edited, new or untracked file, or one reached through a
  symlink out of the folder, is not trusted. `--follow origin/main` follows that branch's tip on the remote, asked of the
  remote itself. The grant refuses `/`, the home folder and above, wildcards and the agent's and Sentrook's own folders;
  it is persistent by default, set only by command or from `/sentrook-setup` (never from the settings or a suggestion),
  and `/sentrook-grants` shows what each is pinned to. The setup skill now asks which repositories you maintain and can
  propose folder items (`sentrook_propose_setup` takes `kind: folder` and `follow`).
- 0f82ac6: `/sentrook-why` says what your grants did to a scan: which grants matched, the risk without them and the parts they
  lowered, or that they matched but changed nothing, then the largest parts of the score no grant covers (for example
  "the request does not clearly ask for this call"). Shown when the scanner sends it.

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
