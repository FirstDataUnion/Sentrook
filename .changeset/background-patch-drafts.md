---
"@firstdataunion/sentrook-openclaw": patch
---

On OpenClaw 2026.11.5 or newer, a background change to an existing skill (a Skill Workshop `patch` of the skill's
`SKILL.md`) that Sentrook would ask about is no longer lost: the plugin reads the live skill, applies the change exactly
as OpenClaw would (the old text must appear exactly once), and sends the whole changed skill to the Skill Workshop
drafts, leaving the live skill as it is. The draft's note says it was held by Sentrook and is the skill as it stood at
that time with one change. The notice for it says where to review and apply it, and that applying it replaces the
skill with that version, so a later change to the skill would be undone (and can be brought back from its history). A
change is still held when it cannot be applied that way (the old text missing or found more than once, the file
missing, a link, larger than 1 MB, or outside the agent's Skill Workshop folder), when it is to a support file, when
Sentrook did not judge it as a background save, or on an older OpenClaw. No background save is sent to the drafts any
more when Sentrook reads a secret in what it saves: before this, a new skill or the agent's own draft carrying one was
kept as a draft. A held archive or restore now says where to do it yourself (Plugins → Skill workshop in the Control UI).
