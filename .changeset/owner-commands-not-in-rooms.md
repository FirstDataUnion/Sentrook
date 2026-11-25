---
"@firstdataunion/sentrook-openclaw": patch
---

Every owner command (`/sentrook-history`, `/sentrook-why`, `/sentrook-report`, `/sentrook-grants`, `/sentrook-grant`,
`/sentrook-revoke`, `/sentrook-bind`, `/sentrook-snooze`, `/sentrook-allow`, `/sentrook-deny`, `/sentrook-approve`,
`/sentrook-passes`, `/sentrook-notify` and `/sentrook-setup`) now refuses in a group or channel room, even from the
owner. OpenClaw decides the owner by the sender, not the room, and keeps a command and its reply in the room's
transcript, so recent scans, hosts, file paths, reasons and grants were shown to everyone there. As `/sentrook-setup`
already did, they also refuse in a chat the plugin cannot tell from a room: a chat channel with no session key, or the
agent's main session while `session.groupScope` routes rooms into it. The reply says to run the command in your own
direct message to the agent, in the Control UI or as `openclaw sentrook <command>` on the machine; each refusal is
recorded in the traffic log with the reason `group_chat` or `unknown_chat`.
