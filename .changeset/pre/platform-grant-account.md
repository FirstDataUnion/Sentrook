---
"@firstdataunion/sentrook-openclaw": patch
---

A channel binding or a cron job's delivery grant written with its platform (`discord:<channel id>`) now applies to a
send that names only the account it posts as (`{action: send, target: "channel:<id>", accountId: <a Discord
account>}`), as OpenClaw's message tool often writes one. Until now such a grant was sent only when the call named the
platform in its own `channel` argument, so a scheduled job announcing to its own channel was still held. The plugin
takes the platform from the account (`channels.<platform>.accounts.<id>` in OpenClaw's config, ids compared without
case; an account on two platforms gives none), else, with no account or the implicit `default` one, from the session's
own chat platform, and sends it to the scanner as `pending_call.send_platform`. It counts only for the platform-prefix
form: a bare id is then sent only as a channel target (`channel:<id>`, `group:`, `thread:`) or a whole argument, never
for a direct message (`user:<id>`, `dm:<id>`), also when the send names its platform. `openclaw sentrook verify` lists
the channel bindings no message send in the traffic log would carry, the setup report counts them as a gap, and the
setup skill says which form to write on OpenClaw.
