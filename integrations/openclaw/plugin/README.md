# Sentrook for OpenClaw

Sentrook is a security plugin. Before each tool call your OpenClaw agent makes (shell commands, file reads and writes,
web fetches, messages and so on), it sends the call, redacted, to the hosted Sentrook scanner, which scores it against
what you asked for and what the agent did on the way. Depending on the score the plugin allows the call, asks you to
approve it, or blocks it.

This is a beta (2.0.0-beta). It needs OpenClaw 2026.9.5 or newer and a free FIDU account for scan credentials.

**Set-up guide:** <https://github.com/FirstDataUnion/Sentrook/tree/main/integrations/openclaw> takes you from
credentials to the first scan, and covers grants, channel bindings, commands and settings. Report problems at
<https://github.com/FirstDataUnion/Sentrook/issues>.

## What the plugin does on your machine

In short, for anyone deciding whether to install it:

- **Network:** it calls two services run by First Data Union: the scan service (`sentrook.firstdataunion.org`), once
  per tool call, and the identity service (`identity.firstdataunion.org`), to exchange your scan credentials for a
  short-lived token. Each scan carries the pending call and its arguments, the request you gave the agent this turn,
  the tool results since the last scan (capped at 256 KB), a short history of the session's earlier calls, and host
  facts (platform, versions, home and workspace paths, how OpenClaw is set to run commands). Secrets the plugin
  recognises (API keys, tokens, passwords, private keys) are replaced with placeholders before anything is sent, so
  what leaves the machine is redacted; other content, including personal data in files and messages, is sent as it
  is. No telemetry beyond the scans themselves.
- **OpenClaw's own saves:** with `skillReview: allow` (the default), the skill and memory saves OpenClaw makes on its
  own (the Skill Workshop review, the memory flush) are sent with the redacted part of the conversation they came
  from, and the plugin keeps that conversation, redacted, on disk for up to 7 days to send with them. Set `skillReview`
  to `review` to stop both.
- **What it can do to a call:** allow it, block it, or ask you through OpenClaw's own approval prompt. It never
  approves a call on your behalf. Where nobody can answer (cron jobs, subagents), a review holds the call: it does not
  run, and you get one notice as a direct message, on the chat you chose with `/sentrook-notify here`, with an id to
  answer within 7 days: `/sentrook-allow` lets the job's next run make that call once (`always`: for 30 days, where
  offered), and `/sentrook-deny` refuses it on that job for 30 days with no more notices. A call blocked there because the scan failed sends you a notice on
  the same chat, at most once per job (per session for other runs) every 6 hours.
- **Background skill and memory saves:** OpenClaw's own saves (the Skill Workshop review, the memory flush, the skill
  collection review) are never asked about, because nobody can answer a prompt in those runs. A save Sentrook would
  ask about is let through when it can be, saved as a Skill Workshop draft for you to apply (a new skill, or a change
  to a skill's `SKILL.md` applied to the live skill, OpenClaw 2026.11.5 or newer), or held; a blocked or reviewed save
  sends you a notice on the same chat, at most one of each
  kind per run every 6 hours. Turning a save into a draft is the only change the plugin makes to a call, and these
  notices are the only messages it sends.
- **Files:** it writes only to its own folder, `~/.openclaw/sentrook/` (a local traffic log of the redacted scans,
  rotated at 50 MB; grants and channel bindings set by command; snooze state; held calls, the passes and denials your answers set, and where their notices go; when each job or run last had a notice with a quiet period; the conversations
  above), or to the paths
  you set for them. It reads OpenClaw's live config for how commands are run and which memory writers are on; on a
  cron run, that job's definition from OpenClaw's job store (read-only), for the channel the job delivers to; and, to
  turn a reviewed background change to a skill into a draft, that skill's `SKILL.md`. To tell a read of its own skill
  files from any other read, it resolves the path a `read` call named; `verify` also lists the skill folders OpenClaw
  loads for a skill with the name of one of its own. It runs no shell commands and starts no background processes.
- **Agent skills:** it ships two skills, `sentrook-guide` (how Sentrook works, for the agent to explain it) and
  `sentrook-setup` (the agent asks what is routine for you and gives you the commands to type), and a few rules in the
  agent's system prompt: never run the commands that change Sentrook, never edit its settings, never disable it.
- **Credentials:** the scan credentials (`SENTROOK_SCAN_CLIENT_ID`, `SENTROOK_SCAN_CLIENT_SECRET`) belong in
  OpenClaw's `~/.openclaw/.env`, referenced from the plugin's config as env SecretRefs. The plugin also reads
  `~/.openclaw/.env` itself, at each scan and command, whether or not the references are set: it uses only its own
  `SENTROOK_*` entries from it, and only where its config and OpenClaw's environment do not already set them (the
  credentials, and settings such as `SENTROOK_MODE`). It reads no other credential file.
- **Turning it down or off:** observe mode (`openclaw config set plugins.entries.sentrook.config.mode observe`) scores
  and logs every call without ever blocking or asking, and `openclaw plugins disable sentrook` stops it sending
  anything.

## Quick start

1. Create scan credentials on the **Sentrook** tab at <https://identity.firstdataunion.org>.
2. Add them to `~/.openclaw/.env` and point the plugin at them (guide, step 2).
3. Let it read what you asked the agent for (without this, more routine work asks for approval):

   ```bash
   openclaw config set plugins.entries.sentrook.hooks.allowConversationAccess true
   ```

4. Install it with the command in the guide (step 4), then enable it and restart the gateway:

   ```bash
   openclaw plugins enable sentrook && openclaw gateway restart
   ```

5. Check: `openclaw sentrook verify`. Every line should start with `ok`.

License: MIT. The Sentrook name and logo, including the package icon, are trademarks of First International Data
Union Ltd and are not covered by the licence: see [TRADEMARKS.md](https://github.com/FirstDataUnion/Sentrook/blob/main/TRADEMARKS.md).
