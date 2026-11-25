---
"@firstdataunion/sentrook-openclaw": patch
---

A subagent of your own direct chat asks you in that chat. OpenClaw starts a subagent's run with trigger `user` on the
parent chat's route; the plugin now sends such a run (session `agent:<id>:subagent:<uuid>`) as trigger `subagent`,
and decides whether it is attended from its parent session: a subagent started by the owner's own message in a chat
they attend (not a group room), or by a subagent that asks there, gets the usual approval prompt, which OpenClaw sends
to that chat. When the prompt times out, or OpenClaw cancels it (no approval route), the call is held instead, bound
to the parent session, with the usual notice; an allow or deny given for subagents of that session settles the next
matching call without asking. A subagent of a cron job, a heartbeat, an event run, a group room, someone else's
message, a held subagent, or one whose spawn OpenClaw has not reported is held. Previously such child runs were sent
as the owner's message and always asked, also under a cron job. Removing `subagent` from
`approval.scheduledIntentKinds` still asks in every subagent.
