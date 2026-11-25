---
"@firstdataunion/sentrook-openclaw": patch
---

A subagent's run is now sent as a subagent's. OpenClaw starts a subagent's run (session `agent:<id>:subagent:<uuid>`)
with trigger `user` and no provenance, so the plugin sent it as the owner's message and asked: under a cron job too,
and the prompt never reached anyone, because OpenClaw refuses a plugin's approval request from a subagent's run (its
gateway identity has no approvals scope) and the call was blocked with no notice. Such a run is now sent as trigger
`subagent`, and a review in it is held for the owner, bound to the parent session, with the usual notice: whether
the subagent was started by a cron job, a heartbeat, an event run, someone else's message or the owner's own chat.
Blocks stay blocks.
