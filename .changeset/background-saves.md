---
"@firstdataunion/sentrook-openclaw": patch
---

OpenClaw's own background saves (the Skill Workshop review, the memory flush before compaction, the skill collection
review) are never asked about any more, on any OpenClaw version and whatever `skillReview` or
`approval.scheduledIntentKinds` say: OpenClaw cancels a plugin's prompt in those runs, or ends the run first, so a
reviewed save was lost without a word. Now a save Sentrook would ask about is let through when the scanner marks it
lenient, saved as a Skill Workshop draft for you to apply when it is a new skill on OpenClaw 2026.11.5 or newer, and
held otherwise. A blocked save, one let through and one saved as a draft each send you a notice where held-call
notices go (`/sentrook-notify here`), at most one of each kind per run every 6 hours; a scan failure on one follows
the policy for unattended runs, with its notice. `status` counts these saves by outcome and, like `verify`, says when
their notices cannot be delivered. The history marks them `allowed (lenient, self-edit)`, `drafted (self-edit)`,
`held (self-edit)` and `blocked (self-edit)`. Adding `system` to `approval.scheduledIntentKinds` is no longer needed
for this.
