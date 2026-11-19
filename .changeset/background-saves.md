---
"@firstdataunion/sentrook-openclaw": patch
---

OpenClaw's own background saves (the Skill Workshop review, the memory flush before compaction, the skill collection
review) are never asked about any more, on any OpenClaw version and whatever `skillReview` or
`approval.scheduledIntentKinds` say: OpenClaw cancels a plugin's prompt in those runs, or ends the run first, so a
reviewed save was lost without a word. Now a save Sentrook would ask about is let through when the scanner marks it
lenient (a complete scan below the block line, of a save declared as a self-edit), sent to the Skill Workshop drafts
for you to apply when it is a new skill on OpenClaw 2026.11.5 or newer, and held otherwise (not saved, with no approve
id: approving could not make it). Each outcome sends you a notice where held-call notices go (`/sentrook-notify
here`), at most one of each kind per run every 6 hours, except a held retry Sentrook would otherwise block, which is
always announced; a draft is announced once OpenClaw reports it kept, or as not saved when it does not keep it. A scan
failure on one follows the policy for unattended runs, with its notice. `status` counts these saves by outcome and,
like `verify`, says when their notices cannot be delivered. The history marks them `allowed (let through,
self-edit)`, `drafted (self-edit)`, `not saved (draft refused, self-edit)`, `held (self-edit)` and
`blocked (self-edit)`. Adding `system` to `approval.scheduledIntentKinds` is no longer needed
for this.
