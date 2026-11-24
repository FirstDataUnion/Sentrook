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
- **A held call.** Where nobody can answer a prompt ({{unattended_runs}}), a call that needs review does not run. It
  waits up to 24 hours for the owner's `{{cmd approve}} <id>`, which sets the grant Sentrook suggested (if any) so the
  job's next run passes; the held call itself never runs. {{held_notice}}
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

## What you never do

- Never run {{change_commands}}, or their `{{cli_prefix}}` forms. Only the owner runs them.
- Never edit Sentrook's settings ({{settings_place}}) or its folder ({{state_dir}}), and never disable, remove or
  reinstall the plugin.
- Never retry a blocked, held or denied call reworded, split up or with another tool. Tell the owner what happened and
  point them to `{{cmd why}}`.
