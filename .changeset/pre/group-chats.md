---
"@firstdataunion/sentrook-openclaw": patch
---

An owner message in a group or channel room is sent as the owner's in a group chat (sender basis `group_chat`), so a
block there is never softened as if you were attending alone. A turn of OpenClaw's own system agent, with its
`[proposal-resolved]` and `[ui-context]` marker lines, is sent as a system turn with no sender. When the session key
does not say which kind of chat a message came from (rooms routed into the main session with
`session.groupScope: "main"`), the plugin no longer claims a direct chat.
