---
name: sentrook-guide
description: How the Sentrook security plugin works, for explaining it to the owner. Use when asked what Sentrook is, why a call was blocked or held, what a Sentrook approval prompt or notice means, or what a Sentrook command does.
user-invocable: false
---

# Sentrook: how it works

Sentrook is the security plugin installed in Hermes. Use this to explain it to your owner in plain words. To help
the owner set it up, read the `sentrook:sentrook-setup` skill instead.

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
  `Details: /sentrook why <id>`. Hermes shows its own buttons: **Once** runs this call; **Session** also lets the same action through for the rest of this session; **Always** lets it through from now on; **Deny** stops it. Where a grant would cover calls like this, the prompt says what Session and Always also set.
- **A block** (risk 80 or more, or a rule that always blocks). The call does not run. You are told only a broad
  category, such as "it reads or sends sensitive data", not which checks fired or the score; the owner sees those
  with `/sentrook why last`.
- **A held call.** Where nobody can answer a prompt (cron jobs, subagents, webhooks, the API server), a call that needs review does not run. It
  waits up to 24 hours for the owner's `/sentrook approve <id>`, which sets the grant Sentrook suggested (if any) so the
  job's next run passes; the held call itself never runs. The owner gets one notice on the home channel of the platform set in Sentrook's `owner_channel` setting; until it is set, nothing is sent and the call is still held.
- **A background-save notice.** Hermes saves skills and memory in the background after a turn, with nobody there to answer a prompt, so Sentrook never asks about these saves. It judges each one against the conversation: a save it would review is let through, staged in Hermes's pending list (`/skills pending`, `/memory pending`) or held; a blocked one is not saved. A notice on the `owner_channel` home channel says which.
- **A scan failure.** When the scan service cannot answer, the owner is asked whether to run the call unscanned where
  someone is there to answer; on an unattended run the call is blocked and the owner gets one notice. This is a
  service problem, not a security block.

Grants and channel bindings tell Sentrook what is routine (a host the agent always sends to, a folder it works in, the
channel a daily report goes to). They never lower Sentrook's floors: reading secrets and sending them somewhere is
still blocked whatever is granted.

## The owner's commands

Only the owner can run the commands below except `/sentrook status` and `/sentrook help`: in a direct message from an allowed user, or on the local terminal (`hermes chat`, or `hermes sentrook <command>` on the machine). Group chats are refused. When you run one, Sentrook refuses it. Never try: explain what the command does and let the
owner type it.

- `/sentrook status`: plugin version, mode, scan host, whether credentials are set, how many grants and bindings, held calls and where notices go. Anyone may run it.
- `/sentrook help`: lists the commands.
- `/sentrook history [n]`: the last n scans: time, session, tool, risk, what Sentrook did, the review.
- `/sentrook why [id|last]`: one scan in detail: risk, reasons, the hosts and files found, and the grant that would let calls like it through; with a held call's id, also the hold.
- `/sentrook report [id|last] [--github|--save]`: a report of a scan that looks wrong, to send to the Sentrook team.
- `/sentrook grants`: every grant in force, from config and set by command.
- `/sentrook grant <kind> <pattern> [flags]`: adds a grant: destination, file, provider, repo or credential; for this session only unless `--persistent`; `--allows read,write` for files, `--expires 12h`.
- `/sentrook revoke <id>`: removes a grant set by command.
- `/sentrook bind add|remove|list [channel]`: the channels this deployment normally delivers to.
- `/sentrook snooze [duration|off|status] [--all]`: for up to 24 hours, a block with no clear attack signal asks instead; never lets a block through and never applies to unattended runs.
- `/sentrook approve <id>`: approves a held call within 24 hours: sets the grant Sentrook suggested, if any; the held call is not run again.
- `hermes sentrook verify` (on the machine): checks the endpoints, the credentials, the scan service and the token.

## A scan that looks wrong

Point the owner to `/sentrook history` to find the scan and `/sentrook why <id>` to see the score, the reasons, the hosts
and files Sentrook found, and the grant that would let calls like it through. If the owner thinks Sentrook got it
wrong, `/sentrook report <id>` prints a report to send to the Sentrook team: `--github` opens a public issue with it
filled in, and `--save` writes the full record to a private file to email (the command gives the address).

## What you never do

- Never run `/sentrook grant`, `/sentrook revoke`, `/sentrook bind`, `/sentrook snooze`, `/sentrook approve`, or their `hermes sentrook` forms. Only the owner runs them.
- Never edit Sentrook's settings (`plugins.entries.sentrook` in Hermes's `config.yaml`) or its folder (`sentrook/` in the Hermes home, such as `~/.hermes/sentrook/`), and never disable, remove or
  reinstall the plugin.
- Never retry a blocked, held or denied call reworded, split up or with another tool. Tell the owner what happened and
  point them to `/sentrook why`.
