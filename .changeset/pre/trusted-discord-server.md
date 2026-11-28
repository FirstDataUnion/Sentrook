---
"@firstdataunion/sentrook-openclaw": minor
---

Trusted chats can now be a whole Discord server: `/sentrook-trust-chat add discord:server:<server id> --confirm` (or
the same text in `trustedChats`) covers every channel and thread in it, including ones created later. OpenClaw names a
room's server on the messages it receives, so a room matches once a message there has named its server (OpenClaw
2026.11.2 or later; an older OpenClaw refuses the entry). Direct messages from its members are not covered, and a
channel id is never taken for a server id. `--owner-only` works as for a chat. Only Discord servers for now: a server
entry on another platform is refused. `list` marks whole servers, `openclaw sentrook verify` has a trusted-chats line
that says whether a server has been seen yet, and the setup skill and setup list suggest a server only where you know
every member and who can join.
