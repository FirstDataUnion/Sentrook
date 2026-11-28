# sentrook (Hermes plugin)

Each release has an entry here, newest first, under a `## <version>` heading that matches `version` in
`plugin.yaml`. The release workflow refuses to run without one, and the catalog pull request quotes the entries
since the version the catalog pins.

## 2.0.0-beta.18

- **Always** on an MCP tool call now means always. Answered on your own turn, it also covers that tool on that
  server for 30 days, in any session: a later call of the same tool on the same server (its configured address or
  package), whatever page or file it writes, at most 10 points higher and below the block line, with no new warning,
  goes through without asking. Before, an MCP write tool's arguments changed on every call, so Hermes's own Always
  never matched again and every call asked. Another tool, another server, a host, recipient or channel the answered
  call did not name, a floor, a rule that always asks or a block still asks; a group chat keeps nothing. The prompt
  says so, `/sentrook grants` lists these answers and `/sentrook revoke <id>` removes one.
- `/sentrook why` says what your grants did to a scan: which grants matched, the risk without them and the parts they
  lowered, or that they matched but changed nothing, then the largest parts of the score no grant covers (for example
  "the request does not clearly ask for this call"). Shown when the scanner sends it.
- `hermes sentrook verify` lists the channel bindings no message send in the traffic log would carry (a binding is sent
  only with a send that shows its channel, so one written another way relieves nothing), and the setup report counts
  them as a gap. A `<platform>:<id>` binding is no longer sent for a send to a person whose id is the same
  (`user:<id>`, `dm:<id>`). The setup skill says to write a binding with its platform, as `send_message` names the
  target.
- When you answer the agent with a short message (300 characters or less, such as "yes", "go with A" or "try
  again"), each call of that turn also sends the agent's last message before it, so the scanner can see what you
  agreed to instead of reading your reply alone. It is sent as the agent's words, never as your request, redacted and
  cut to 2,000 characters (start and end). It is not sent with a longer message, someone else's message, a turn Hermes
  starts itself or the background review.
- Your own message in a group chat or server channel now counts as yours when you are listed individually in
  `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`, as the OpenClaw plugin already does: routine work you ask for
  from a private channel is scored like a direct message instead of as someone else's request. Other members still
  count as someone else, and the recent channel messages Hermes puts in front of your message are sent as content the
  agent read, never as your words. Reviews there still ask in the channel; because anyone the bot admits can answer
  there, a snooze, remembered Session answers, grants set by approving and a subagent's prompts stay for a direct
  message or the terminal, and owner commands are still refused in channels.
- **Session** on a review now also covers a later call of the same tool about the same parties that scores up to 10
  points higher than the call you answered (never at or above the block line), and one that newly carries only the
  session's rising consequence trend. A score moves a few points between near-identical calls of one job, so the
  same job asked again. Every other new warning, a retry after a refusal included, still asks. The 10 points count
  from your answer, not from a call Session let through. The prompt now says "also covers the same parties at a
  similar risk". Passes on held calls are unchanged: no higher score and no new warning.
- The setup skill does the looking itself: it works out what is routine from the agent's own scheduled jobs, skills,
  MCP servers and the setup report, shows you a short list to keep or drop, and asks once whether anything else
  should not need approval, instead of asking you a list of questions. It suggests doing the first setup in the
  terminal, TUI or desktop app, keeps its messages short with commands on their own lines, and ends with how to get
  help when regular work is blocked later.
- `/sentrook why` now shows the call itself (the tool's arguments as sent to the scanner: secrets masked, long text
  cut), and a background-save notice shows the save it is about, so you can judge it without opening the dashboard.
  The dashboard shows each scan's call by default too. One new setting, `hide_tool_calls`, hides calls in all three
  places; `dashboard_show_calls` is no longer needed and does nothing. A report's summary never carries the call.
- A held change to the agent's own skills or memory no longer reads "Changes the agent's or host's configuration a
  destination" when it names no destination.
- Each scan names the plugin build that ran, as `host.plugin_build` in the traffic log: a hash of the plugin's files
  (with the Git revision Hermes installed, when it recorded one), taken when the process started. The version label
  stays the same across many changes, so it could not tell builds apart. `/sentrook status` shows it as
  `plugin build`.
- After an install or update of the plugin, a Hermes process that was already running keeps the old plugin until it
  restarts. `hermes sentrook verify` now fails a `running build` line, and `/sentrook status` says `restart needed`,
  naming each process (hermes-serve, the gateway, the dashboard) still on another build; such a process also logs a
  warning on its scans (the files are read at most once a minute). Each process records its build in
  `~/.hermes/sentrook/processes/` while it runs. The guide's "Updating" section and the setup skill say to restart all
  of them.
- An owner command sent in a group chat or a server channel, a private one included, now says why it was refused:
  the chat, not your account, since anyone there could see or change your security settings. It tells you to open a
  direct message with the bot or use the machine (`hermes chat`, the desktop app or `hermes sentrook <command>`). A
  refusal for someone not on the platform's allowed users says the same places plainly.
- Trusted folders: `/sentrook grant folder <dir>` trusts a folder you write and maintain, such as the repository your
  jobs' instructions live in. A file the agent reads from it with `read_file`, unchanged since you set the grant, is
  sent with `trusted_by`, and Sentrook reads it as your own words: it no longer makes the chat count as exposed to
  untrusted content. Nothing else is relieved. The plugin records the folder when you set the grant (in a git
  repository the commit checked out; elsewhere each file's sha256); an edited, new or untracked file, one reached
  through a symlink out of the folder, a read by a relative path, and a read whose text is not the file's are not
  trusted. `--follow origin/main` follows that branch's tip on the remote,
  asked of the remote itself. The grant refuses `/`, the home folder and above, wildcards and the agent's and
  Sentrook's own folders; it is persistent by default, set only by command or from `/sentrook setup` (never from the
  settings or a suggestion), and `grants` shows what each is pinned to. The setup skill now asks which repositories
  you maintain and can propose folder items (`sentrook_propose_setup` takes `kind: folder` and `follow`).
- Beta: while a snooze is on, a block in a chat you attend asks you instead of stopping, whatever caused it: a floor,
  a strong signal or a rule that always blocks included. Until now only a block Sentrook marks as having no clear
  attack signal asked, so a false alarm with a floor left no way past but switching Sentrook to observe. That prompt
  keeps its wording ("Would be blocked, but a snooze is on."). Any other block gets a stronger warning: it names why
  it would be blocked and says "A snooze is on: allow only if you asked for exactly this call." It suggests no grant,
  and since Hermes cannot leave buttons out, **Session** and **Always** allow that one call only, like **Once**: the
  next call asks again, and while the snooze lasts so does the same action (after either kind of prompt) scored
  later as an ordinary review. It needs a complete scan: when one of Sentrook's checks failed, the block stays a
  block. A change to Sentrook itself (its files, settings or log, turning the plugin off, stopping the gateway, a
  Sentrook command only you should run, loosening the host's approvals), and any block that may be one, stays a
  block during a snooze; so does such a block on email, SMS, IRC or ntfy, where anyone can claim a sender, and in a
  session switched to YOLO (read from Hermes's approval module; when it cannot be read, the block stays). Nothing
  changes on unattended runs, for other senders, in group chats, in observe mode, on scan errors or without a
  snooze. The snooze reply, `snooze status`, the guide and the
  agent skill say so. The traffic log marks such a prompt with `relaxed_strong: true`. Known side effect: Hermes saves
  each **Always** answer in `command_allowlist`, so **Always** on such a prompt leaves an entry there that never
  matches another call.
- A `hermes -z` turn, and a single-query run (`hermes chat -q`, or a finite turn through the gateway) where
  `approvals.single_query_mode` is `approve`, count as runs where Hermes approves prompts by itself, like approvals
  off or `HERMES_YOLO_MODE`: a review there is held for you rather than asked, since Hermes would approve it with
  nobody asked, and a snooze never turns a block there into a question.
- If you withdraw consent on the FIDU portal, the identity service stops accepting this machine's scan credentials.
  Sentrook then tells you once, where notices go and in observe mode too, that scans stopped and how to connect again
  (`hermes sentrook login`), switch to observe mode or uninstall, instead of a scan-failure notice per job. It is sent once for
  these credentials, also across restarts; signing in again or setting new credentials resets it. Calls are handled
  as for any credential problem: asked where you can answer, blocked where nobody can (and with `on_scan_error: allow` too), run
  in observe mode; the prompt, the agent's message and `verify` say consent was withdrawn.
- `hermes sentrook login` now prints what each check sends and to whom, the privacy policy, the terms and how to stop, with the
  terms version you accepted (and when) if the identity service gives it.
- The local traffic log keeps records for 30 days. As it writes (at most once an hour), the plugin deletes older
  records from `traffic.jsonl` and its rotated copy `traffic.jsonl.1`: a file holding only older records is deleted,
  and one that holds both is rewritten without them. `/sentrook history`, `/sentrook why`, `/sentrook report` and the
  dashboard show what is inside those 30 days.
- `/sentrook dismiss <id>` (or `/sentrook dismiss all`) takes a held call off the waiting list without answering it,
  as if it had expired now. It works on any hold, including one that offers no answer (a run with no source, or a
  hold from an earlier version) and one you would rather not deny for 30 days. The call never runs and nothing is set:
  no pass, denial or grant, and a call like it is held again with a notice. Each dismissed call is recorded in the
  traffic log with the resolution `hold_dismissed`, and `/sentrook history` shows its review as `dismissed`. Like the
  other answers, it is for the owner only and the agent is told never to run it.
- The dashboard's **Waiting for you** section now folds: click its heading to fold it away, and the tab remembers that
  in your browser until something newer is waiting. It shows the first three items with the rest behind **Show
  more**, and names `/sentrook dismiss` on each held call and `/sentrook dismiss all` when more than one is waiting.
- A notice to the chat set with `/sentrook notify here` that Hermes cannot reach yet is sent again instead of being
  lost. On platforms such as Mattermost, `hermes send` reaches a new chat only once Hermes has listed it, a few
  minutes after the chat starts, so the test notice and the first held-call notices failed with "Could not
  resolve". Such a notice is now tried again in the background by the gateway (or the app's `hermes serve`) for up
  to 10 minutes (after 30 seconds, then 1, 2 and 3 minutes, then every 3 minutes), and when it still fails it goes to
  the platform's home channel if one is set, with a line saying why. A notice kept by another process, such as the
  worker a managed gateway runs a cron job in, is found by the gateway within 30 seconds and keeps its 10 minutes
  from when it was kept; one whose chat is no longer where notices go is dropped. While it is tried again it counts as
  sent, so further scan failures or background saves of the same kind are not announced again in their usual quiet
  period. If the process that kept it also settles it as finally not delivered, the next one of that kind is
  announced again; otherwise the quiet period simply runs out. `/sentrook notify status`, `status` and `verify` say while it is being tried, when it
  went to the home channel, or that it was not delivered, until a notice gets through. The `notify here` reply says
  the first notice may take a few minutes. Other send failures, notices to a home channel and Telegram chats are
  unchanged.
- An `execute_code` program that calls nothing on the network, and that the scanner can follow, is held for the owner
  on an unattended run instead of blocked when only the URLs or quoted commands in its strings take it to a block
  (the scanner's `cap.local_code` ceiling). A program that does call the network is scored and blocked as before.

- The `sentrook-setup` skill tells the agent never to read Sentrook's folder or traffic log to work out what is
  routine, and to call the `sentrook_setup_report` tool instead: the log holds content from earlier tool calls, so
  reading it made the rest of the chat count as exposed to it.
- A password or token with `&`, `,` or `;` in it is now redacted whole. After a key in an assignment, an `.env` line
  or a quoted value (`password=<value>&<rest>`, `export DB_PASSWORD=…`, `password='…'`) the value used to end at the
  first of these characters, so the rest of it left the machine as written, and the same password written `password:
  …` got another placeholder. What follows a value is still kept where it is something else: another parameter in a
  link's query or a form body (`?password=…&page=2`, `user=a&password=…&remember=1`), the next key of a list or a
  connection string (`a=1,b=2`, `;Initial Catalog=…`), an HTML entity (`&quot;`), and a command or statement after the
  value (`…; echo ok`, `…;npm publish`, `…&&next`, `…;$(…)`, `…;./run.sh`, `…;return x`), so the scanner still sees
  it; in double quotes a value ends where `$(` starts. A lone command word at the end of a line after a value
  (`TOKEN=…;make`) is read as part of the value, as a password's tail would be.
- A command piped from, substituted or run straight after a password or token is no longer hidden inside its
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
- A quoted example value that only stands in for a secret is no longer redacted as if it were one, so docs and notes
  that show a token file's shape can be saved into a skill or memory without being scored as saving a secret. Kept
  under any key: the word `REDACTED` and a mask of `*`, `•` or `·` (`"••••••••"`). Kept only in a quoted value under a
  token or key that does not name a password: a token cut short with an ellipsis after at most ten token characters
  (`"access_token": "ya29.a0..."`, `"refresh_token": "1//0g..."`), and a short phrase that says what it is
  (`"short-lived token"`, `"your api key"`). Still redacted as before: a full token, with or without an ellipsis;
  anything under a password (`"password": "<short value>..."`, a passphrase); a phrase that does not say what the
  value is; a value after a command-line flag, `mysql -p` or `sshpass -p`; an unquoted value before an ellipsis; and
  any value under a credential key in a parsed object.
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
- **A cron job's sub-agents belong to the job.** Hermes gives a delegated child no cron identity of its own, so its
  held calls were bound to its parent session, which is new every run: `allow always` and `deny` never reached the
  job's next run, and `allow` could not start the job. The plugin now keeps the cron run on the run's own session, and
  a child whose parent Hermes names as that session (or a child of such a child) takes it: its holds are the job's
  holds, the notice says "a sub-agent of cron job …", `allow` starts the job again, and the job's passes and
  denials cover the same call from any of its runs' sub-agents. A sub-agent of a chat or another run is unchanged.
- **One notice per cron run.** The run's first held call sends the notice. A later held call of another action in
  the same run (a sub-agent's included) joins it and sends nothing then; when the run ends, one line lists those
  calls by tool and description, with their ids. `/sentrook allow <id> all`, on the id that line names, answers it
  and lets every listed call through once in the same started run, each still checked against its own scan; a listed
  call that itself sends or writes is left for its own answer, and before the line has gone out `all` covers the
  first call alone. A call held after the line went out gets its own notice, and a run whose end the plugin did not
  see gets its line when the job's next run first holds a call.
- **Holds on runs that are not cron jobs bind to where the run came from.** A subagent's hold is bound to its parent
  session (the `parent_session_id` Hermes gives each turn of a delegated child), and a webhook run's to its route (the
  `webhook:<route>` user id Hermes's webhook platform binds for an authenticated route; the delivery id is not used).
  Such a hold offers `allow` (a one-use pass for the next matching call from the same source within 7 days; nothing
  is started), `allow always` where offered, and `deny`, each bound to that source; the notice and the replies name
  it, and `/sentrook passes` lists each pass by its source. A subagent of another parent session, or another route,
  is held again. A run with no source Hermes names, an API-server run among them (Hermes 0.23 checks one shared key
  and gives the run no key name), keeps `allow` alone, bound to the exact arguments. Sources are never read from the
  prompt or the call, and the stored ref is a hash.
- **A subagent of your own chat asks you in that chat.** A subagent started from your direct message on a chat
  platform, the TUI or the desktop app is attended: its review is Hermes's approval prompt, shown in the chat that
  started it (Hermes keeps the parent chat's session for a delegated child, so the prompt joins that chat's approval
  queue, also after the turn ends), with the same card and answers. A prompt nobody answers in time, one Hermes cannot
  show or withdraws, or one the subagent's own thread answered because no chat could show it, holds the call instead,
  bound to the parent session, with the usual notice; an `allow` or `deny` you gave for subagents of that session
  settles the next matching call without asking. A subagent of the local terminal or ACP (where Hermes answers a
  subagent's prompt itself), a cron job, a webhook, the API server, a group chat, someone else's message, or a held
  subagent is still held, and so is every subagent while `delegation.subagent_auto_approve` is on. Blocks stay
  blocks. Previously every subagent was held.
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
- The `sentrook-guide` skill has a new section, "Working well with Sentrook", on shaping work so Sentrook can judge
  it clearly: fetch web pages and APIs with Hermes's own web tools rather than HTTP in code; keep code local (a code
  or shell call that reads local files does not also reach the network); install packages once, early, in a chat with
  you, not in cron jobs or subagents; keep a task's files in one work directory; refer to keys by name; and when a
  call is held or blocked, tell you and point to `/sentrook why` rather than try it again in a new shape. It says
  plainly that this is about clear scans, never about getting past a check.
- **A destination grant over a whole public suffix is refused.** A destination may use a wildcard on a host or a mail
  domain only as `*.` and one registrable domain (`*.example.com`, `*.example.co.uk`, `*.myname.github.io`), or as
  `*.` and a name that never resolves on the public internet (`*.lan`, `*.local`, `*.internal`, `*.test`,
  `*.example` and the like). `/sentrook grant destination *.com` is refused with the reason, and so is a wildcard
  over another top-level domain or a common shared suffix where anyone can get a name (`*.co.uk`, `*.ne.jp`,
  `*.github.io`, `*.vercel.app`, `*.amazonaws.com`; the common ones, not every one), or inside a name
  (`api*.example.com`), as Sentrook ignores such a grant: it would let calls reach sites run by strangers. A
  wildcard in a channel's name (`discord:#daily-*`) or before an `@` (`*@example.com`) is still taken. Such a grant
  in `config.yaml`, or one already in the grants file, is never sent: `/sentrook grants`, `/sentrook status` and
  `hermes sentrook verify` list it as too broad, and the other grants still apply. A channel binding like it is
  listed as too broad and never sent. A credential grant's host follows the same list of shared suffixes. A wildcard
  address such as `192.168.1.*` is refused too, and one already in the config is listed as too broad and never sent:
  write the exact hosts instead. A bare name with a wildcard such as `daily-*` is refused as a destination, as it
  would match hosts too: write `#daily-*` or `discord:#daily-*` for channel names.
- `/sentrook setup` and the setup report count a chat as having read content that tried to steer the agent only
  when one of its scans gave an `exposure.*` reason: the scanner's own line for it, and every later call of a chat
  it judged tainted carries one. The exposure scores alone no longer count, since almost any content scores a little,
  so the screen warned about nearly every proposal from the agent and left out reviews you approved in ordinary
  chats.

- A Google Drive, Docs or Sheets file or folder id is no longer redacted as a secret where the call names Google.
  Since a value that looks random under a key is redacted, an id in a Drive query (`parents='<id>'`) or in a script
  that works on documents (`const PLAN = "<id>"` beside `documentId`, `textRun`, a Google API host or client library,
  or a Drive or Docs tool such as `drive_files_list` or `docs_get`) became a placeholder: the scanner could not see
  which document or folder the call reads or writes, and counted the id as a secret being sent. Such an id now stays
  when its own text, or for a value in a call's arguments its own object, names Google. A value of that shape with
  nothing naming Google, any value under a credential key, a key with a secret word in it (`SESSION_KEY`, `Authorization`,
  `connect.sid`, `cookie`, `hmac`) or a custom `X-` header, and every other random value are redacted as before.

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
