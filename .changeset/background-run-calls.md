---
"@firstdataunion/sentrook-openclaw": patch
---

A call in one of OpenClaw's own background runs (the Skill Workshop review, the memory flush before compaction, the
skill collection review) that is not a save, such as an exec or a read, is no longer sent to an approval prompt
when it needs review. Nobody can answer a prompt there: OpenClaw cancelled it at once, or the run ended first, so the
call was lost without a word and the run could stop before its save. Such a call is now held: it does not run, the run
is told nobody can approve it and not to retry it, and the owner gets one notice per run where held-call notices go.
These holds are not kept with the holds `/sentrook-approve` takes. A scan failure there follows the policy for
unattended runs. Allowed and blocked calls, and the owner's own chats, are unchanged.
