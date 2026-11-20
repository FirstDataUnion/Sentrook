---
"@firstdataunion/sentrook-openclaw": patch
---

On OpenClaw 2026.11.5 or newer, a background change to an existing skill (a Skill Workshop `patch` of the skill's
`SKILL.md`) that Sentrook would ask about is no longer lost: the plugin reads the live skill, applies the change the way
OpenClaw's own patch does (the old text must appear exactly once), and sends the whole changed skill to the Skill
Workshop drafts, leaving the live skill as it is. OpenClaw also refuses a background patch of a skill the run has not
viewed first; the draft route does not check that. The draft's note says it was held by Sentrook, names the scan (for
`/sentrook-why`) and says it is the skill as it stood at that time with one change. The notice for it says where to
review and apply it, and that applying it replaces the skill with that version, so a later change to the skill would
be undone (and can be brought back from its history). Each such draft is announced, up to 5 per run in 6 hours; a
second draft of the same skill says how many drafts of it the run made. A change is still held when it cannot be
applied that way (the old text missing or found more than once, the file missing, a link, a FIFO or other special
file, not valid UTF-8, larger than 1 MB, or outside the agent's Skill Workshop folder), when it is to a support file,
when Sentrook did not judge it as a background save, or on an older OpenClaw. No background save is sent to the drafts
any more when Sentrook reads a secret in what it saves: before this, a new skill or the agent's own draft carrying one
was kept as a draft. That check applies when the scan reports what the save adds (the default `skillReview: allow`
with a scanner that reports it); with an older scanner or `skillReview: review`, drafts of new skills go ahead as
before and only OpenClaw's own checks apply. A held archive or restore now says where to do it yourself (Plugins → Skill workshop in the Control UI).
