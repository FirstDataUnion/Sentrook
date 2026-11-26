---
name: sentrook-guide
description: How the Sentrook security plugin works, for explaining it to the owner. Use when asked what Sentrook is, why a call was blocked or held, what a Sentrook approval prompt or notice means, or what a Sentrook command does.
user-invocable: false
---

# Sentrook: how it works

Sentrook is the security plugin installed in OpenClaw. Use this to explain it to your owner in plain words. To help
the owner set it up, read the `sentrook-setup` skill instead.

## What it does

Before each of your tool calls runs, the plugin sends it to the hosted Sentrook scan service with the request that led
to it, a short history of the session and the tool results since the last scan. The service scores the risk and the
plugin then allows the call, asks the owner, or blocks it. Secrets the plugin recognises (keys, tokens, passwords,
access codes) are replaced with placeholders before anything leaves the machine; hosts, addresses and file paths are
kept, because they are what the scan judges. A local copy of each scan stays in the traffic log on this machine. In
observe mode Sentrook only scores and records, and never asks or blocks.

## What the owner sees

- **An approval prompt** (risk 45 or more by default). It starts with a feather and "Sentrook security check · risk
  N/100" ("Safety rule" for a rule that always asks), says what the call does and why in plain words, and ends with
  `Details: /sentrook-why <id>`. OpenClaw shows its own buttons: **Allow once** runs this call; **Allow always** appears only when a grant would cover calls like this and the owner asked for the work, and also sets that grant for 30 days; **Deny** stops it. Unanswered, a prompt in a chat denies the call after 5 minutes.
- **A block** (risk 80 or more, or a rule that always blocks). The call does not run. You are told only a broad
  category, such as "it reads or sends sensitive data", not which checks fired or the score; the owner sees those
  with `/sentrook-why last`.
- **A block a snooze turned into a prompt** (beta). While the owner has snoozed with `/sentrook-snooze`, a block in the
  owner's own chat asks instead of stopping. The prompt warns that the call would be blocked; one with a floor or a
  strong signal names why, says to allow it only if the owner asked for exactly that call, and asks again every time.
  A block from an incomplete scan, and a change to Sentrook itself (its files, settings or log, turning it off,
  stopping the gateway, a Sentrook command, loosening approvals), still blocks during a snooze. Never press the owner
  to allow one.
- **A held call.** Where nobody can answer a prompt (cron jobs, heartbeats, subagents, webhooks), a call that needs review does not run, and
  you must not retry it in that run. The owner answers within 7 days, with only the answers the notice offers:
  `/sentrook-allow <id>` runs the job again now and lets the same call through once in that run (`later`: on the job's
  next scheduled run instead; when the held run had already sent or written something, only `now` runs it again);
  `/sentrook-allow <id> always` lets the job make it for 30 days; `/sentrook-deny <id>` refuses the job the same call for 30 days; `/sentrook-dismiss <id>` (or `all`) only takes it off the list, as if it had expired, on any hold. Off a cron job, the answers bind to where the run came from (a heartbeat's agent, a subagent's parent session) and nothing is started; a run with no such source (a webhook) offers only `/sentrook-allow`, for the exact call. "The same call" is the same tool
  about the same parties, scoring no higher; the held call itself never runs. Answering sets no grant:
  `/sentrook-why <id>` shows the grant Sentrook suggests, and `/sentrook-passes` lists what the answers set. A hold nobody
  answers expires after 7 days. A cron job's sub-agents belong to the job: their held calls are the job's, and the
  job's answers cover them. The owner gets one notice per run: the run's first held call sends it, and when the run
  ends one line lists the run's other held calls; `/sentrook-allow <id> all`, on the id that line names, lets the listed
  calls through once too in one new run, except calls that send or write, which are answered on their own.
  The owner gets one notice as a direct message on the chat where they ran `/sentrook-notify here`; until then, nothing is sent and the call is still held.
- **A declined call.** When the owner has denied a held call for a job, that job's same call is refused with "The
  owner declined this action for this job". Continue without it; do not retry it another way.
- **A background-save notice.** OpenClaw saves skills and memory on its own (the Skill Workshop review, the memory flush, the skill collection review), with nobody there to answer a prompt, so Sentrook never asks about these saves. It judges each one against the conversation: a save it would review is let through, saved as a Skill Workshop draft for the owner, or held; a blocked one is not saved. A notice where held-call notices go says which.
- **A scan failure.** When the scan service cannot answer, the owner is asked whether to run the call unscanned where
  someone is there to answer; on an unattended run the call is blocked and the owner gets one notice. This is a
  service problem, not a security block.

Grants and channel bindings tell Sentrook what is routine (a host the agent always sends to, a folder it works in, the
channel a daily report goes to). They never lower Sentrook's floors: reading secrets and sending them somewhere is
still blocked whatever is granted.

## The owner's commands

`/sentrook status` and `/sentrook help` are open to anyone. The dashed commands are for the owner only: from a direct message by the owner, the Control UI, or `openclaw sentrook <command>` on the machine. They refuse in a group or channel room, even from the owner, since everyone there would see the reply. When you run one, Sentrook refuses it. Never try: explain what the command does and let the
owner type it.

- `/sentrook status`: plugin version, mode and thresholds, scan host, whether credentials are set, how many grants and bindings, snooze, held calls and where notices go. Anyone may run it.
- `/sentrook help`: lists the commands.
- `/sentrook-history [n]`: the last n scans (default 10, at most 50): time, session, tool, risk, what Sentrook did, the review.
- `/sentrook-why [request_id|last]`: one scan in detail: risk, reasons, the hosts and files found, and the grant that would let calls like it through; with a held call's id, also the hold, the answers it offers and the grant Sentrook suggests.
- `/sentrook-report [request_id|last] [--full|--github|--save]`: a report of a scan that looks wrong, to send to the Sentrook team: `--full` adds the exact request (send it privately), `--github` opens a public issue with the summary filled in, `--save` writes the report and the full record to a file to email.
- `/sentrook-grants`: every grant in force, from config (read-only) and set by command.
- `/sentrook-grant <kind> <pattern> [flags]`: adds a grant: destination, file, provider, repo or credential; for this session only (not cron jobs, subagents or other chats) unless `--persistent`; `--session <ref>` binds it to a session from history, `--allows read,write` (files only), `--expires 12h`.
- `/sentrook-revoke <id>`: removes a grant set by command.
- `/sentrook-bind add|remove|list [channel]`: lists, adds or removes a channel binding: a channel this deployment normally delivers to.
- `/sentrook-snooze [duration|off|status] [--all]`: lets review prompts through without asking in this session (`--all`: every session) for a while, default 1h, at most 24h; in beta, a block in the owner's own chat asks instead, with a warning, except a change to Sentrook itself; never reviews Sentrook enforces or unattended runs; `off` ends it.
- `/sentrook-allow <id> [now|later|always|all]`: answers a call held on an unattended run, by the id in Sentrook's notice, within 7 days: runs the cron job again now and lets the call through once in that run (`now`: even when the held run had already sent or written something; `later`: on the job's next scheduled run instead), or with `always` for 30 days on that job, where the notice offers it; `all`, on the id a run's end line names, also lets the calls that line listed through once in that run; Sentrook never runs the held call itself.
- `/sentrook-deny <id>`: refuses a call held on a cron job, or on another run with a source, by the id in Sentrook's notice: that job or source is refused the same call for 30 days, with no more notices.
- `/sentrook-dismiss <id>|all`: takes a held call (or all of them) off the waiting list without answering it, as if it had expired now: the call never runs and nothing is set, so a call like it is held again.
- `/sentrook-approve <id>`: the same as allow (kept for one release).
- `/sentrook-passes [revoke <id>]`: the passes and denials the owner's answers to held calls set, with their use counts; `revoke <id>` removes one.
- `/sentrook-notify here|off|status`: where notices go: `here`, sent as a direct message to the agent, sends them to that chat; `off` stops them.
- `/sentrook-setup [apply <code> [1,3] | discard <id>]`: lists what would stop Sentrook asking about routine work (channels the cron jobs deliver to, MCP servers, grants Sentrook suggested on reviews the owner approved), each described by Sentrook; the owner sets them with `apply` and the code the list ends with.
- `openclaw sentrook verify` (on the machine): checks the endpoints, the credentials, the scan service and the token.

## A scan that looks wrong

Point the owner to `/sentrook-history` to find the scan and `/sentrook-why <id>` to see the score, the reasons, the hosts
and files Sentrook found, and the grant that would let calls like it through. If the owner thinks Sentrook got it
wrong, `/sentrook-report <id>` prints a report to send to the Sentrook team: `--github` opens a public issue with it
filled in, and `--save` writes the full record to a private file to email (the command gives the address).

## Working well with Sentrook

Sentrook judges each call by what it can see: what the call reads, where it sends, and what the owner asked for. A
call that does one clear thing is easy to judge; code that gathers local data and reaches many hosts at once looks
like data being collected and sent out, whatever it is for. These habits let the scan see your work clearly. They are
never about getting past a check: a call that needs the owner's review should still get it.

- **Fetch with OpenClaw's own web or fetch tools.** To read a web page or an API, use those tools rather than HTTP
  requests written into code or a shell command.
- **Keep code local.** A code or shell call that reads local files should not also reach the network, and one that
  reaches the network should not read local files. Fetch with the web tools, save what you need in the work
  directory, then process it there. This is for fetching: when the task is to send local data out, send it plainly,
  in one call the owner can review.
- **Set up first, in a chat with the owner.** Install packages and tools once, early, where the owner can answer a
  review. Not on an unattended run (cron jobs, heartbeats, subagents, webhooks), where nobody can answer and the call is held.
- **Use one work directory** for a task's files and outputs.
- **Refer to keys by name.** Keep secret values out of arguments and code; read each key from the environment by its
  name.
- **When a call is held or blocked, leave that call.** Do not try it again in a new shape. Tell the owner what
  happened and point them to `/sentrook-why`.

## What you never do

- Never run `/sentrook-grant`, `/sentrook-revoke`, `/sentrook-bind`, `/sentrook-snooze`, `/sentrook-allow`, `/sentrook-deny`, `/sentrook-dismiss`, `/sentrook-approve`, `/sentrook-passes revoke`, `/sentrook-notify`, `/sentrook-setup apply`, or their `openclaw sentrook` forms. Only the owner runs them.
- Never edit Sentrook's settings (`plugins.entries.sentrook` in `openclaw.json`) or its folder (`sentrook/` in the OpenClaw state folder, such as `~/.openclaw/sentrook/`), and never disable, remove or
  reinstall the plugin.
- Never retry a blocked, held or denied call reworded, split up or with another tool. Tell the owner what happened and
  point them to `/sentrook-why`.
