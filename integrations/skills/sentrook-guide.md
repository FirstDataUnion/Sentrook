---
name: sentrook-guide
description: How the Sentrook security plugin works, for explaining it to the owner. Use when asked what Sentrook is, why a call was blocked or held, what a Sentrook approval prompt or notice means, or what a Sentrook command does.
user-invocable: false
---

# Sentrook: how it works

Sentrook is the security plugin installed in {{host}}. Use this to explain it to your owner in plain words. To help
the owner set it up, read the {{setup_skill}} skill instead.

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
  `Details: {{cmd why}} <id>`. {{approval_choices}}
- **A block** (risk 80 or more, or a rule that always blocks). The call does not run. You are told only a broad
  category, such as "it reads or sends sensitive data", not which checks fired or the score; the owner sees those
  with `{{cmd why}} last`.
- **A held call.** Where nobody can answer a prompt ({{unattended_runs}}), a call that needs review does not run, and
  you must not retry it in that run. The owner answers within 7 days, with only the answers the notice offers:
  `{{cmd allow}} <id>` runs the job again now and lets the same call through once in that run (`later`: on the job's
  next scheduled run instead; when the held run had already sent or written something, only `now` runs it again);
  `{{cmd allow}} <id> always` lets the job make it for 30 days; `{{cmd deny}} <id>` refuses the job the same call for 30 days. "The same call" is the same tool
  about the same parties, scoring no higher; the held call itself never runs. Answering sets no grant:
  `{{cmd why}} <id>` shows the grant Sentrook suggests, and `{{cmd passes}}` lists what the answers set. A hold nobody
  answers expires after 7 days. {{held_notice}}
- **A declined call.** When the owner has denied a held call for a job, that job's same call is refused with "The
  owner declined this action for this job". Continue without it; do not retry it another way.
- **A background-save notice.** {{background_saves}}
- **A scan failure.** When the scan service cannot answer, the owner is asked whether to run the call unscanned where
  someone is there to answer; on an unattended run the call is blocked and the owner gets one notice. This is a
  service problem, not a security block.

Grants and channel bindings tell Sentrook what is routine (a host the agent always sends to, a folder it works in, the
channel a daily report goes to). They never lower Sentrook's floors: reading secrets and sending them somewhere is
still blocked whatever is granted.

## The owner's commands

{{owner_commands_where}} When you run one, Sentrook refuses it. Never try: explain what the command does and let the
owner type it.

{{commands}}
- `{{cli verify}}` (on the machine): checks the endpoints, the credentials, the scan service and the token.

## A scan that looks wrong

Point the owner to `{{cmd history}}` to find the scan and `{{cmd why}} <id>` to see the score, the reasons, the hosts
and files Sentrook found, and the grant that would let calls like it through. If the owner thinks Sentrook got it
wrong, `{{cmd report}} <id>` prints a report to send to the Sentrook team: `--github` opens a public issue with it
filled in, and `--save` writes the full record to a private file to email (the command gives the address).

## Working well with Sentrook

Sentrook judges each call by what it can see: what the call reads, where it sends, and what the owner asked for. A
call that does one clear thing is easy to judge; code that gathers local data and reaches many hosts at once looks
like data being collected and sent out, whatever it is for. These habits let the scan see your work clearly. They are
never about getting past a check: a call that needs the owner's review should still get it.

- **Fetch with {{host}}'s own web or fetch tools.** To read a web page or an API, use those tools rather than HTTP
  requests written into code or a shell command.
- **Keep code local.** A code or shell call that reads local files should not also reach the network, and one that
  reaches the network should not read local files. Fetch with the web tools, save what you need in the work
  directory, then process it there.
- **Set up first, in a chat with the owner.** Install packages and tools once, early, where the owner can answer a
  review. Not on an unattended run ({{unattended_runs}}), where nobody can answer and the call is held.
- **Use one work directory** for a task's files and outputs.
- **Refer to keys by name.** Keep secret values out of arguments and code; read each key from the environment by its
  name.
- **When a call is held or blocked, stop.** Do not try it again in a new shape. Tell the owner what happened and point
  them to `{{cmd why}}`.

## What you never do

- Never run {{change_commands}}, or their `{{cli_prefix}}` forms. Only the owner runs them.
- Never edit Sentrook's settings ({{settings_place}}) or its folder ({{state_dir}}), and never disable, remove or
  reinstall the plugin.
- Never retry a blocked, held or denied call reworded, split up or with another tool. Tell the owner what happened and
  point them to `{{cmd why}}`.
