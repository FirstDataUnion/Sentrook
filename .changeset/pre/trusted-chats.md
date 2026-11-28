---
"@firstdataunion/sentrook-openclaw": minor
---

Trusted chats and users. `/sentrook-trust-chat add <platform>:<chat id> --confirm` marks a group chat or server
channel where you know every member as trusted, and `/sentrook-trust-user add <platform>:<user id> --confirm` a person
you know (`list` and `remove` too; `trustedChats` and `trustedSenders` in the config do the same, and `trustedSenders`
now takes `<platform>:<user id>` as well as a bare id). Their messages are sent to the scanner as from someone you
trust, not a stranger, and never as yours: grants, settings and every Sentrook command stay yours, a trusted turn never
sets a grant when its review is approved, and the scanner's floors apply as before. A thread or topic in a trusted chat
is covered; a direct chat is never a trusted chat. Each command warns first and needs `--confirm`, runs only where the
other owner commands run (never in a group or channel), and is logged by platform only.

Reviews in a trusted chat are answered as OpenClaw allows there. A chat added with `--owner-only` (or `owner_only:
true` in the config) holds a review on anyone's turn but yours for you instead: the agent says in the chat that it is
waiting, you get a notice where `/sentrook-notify here` sends them, and `/sentrook-allow <id>` lets that exact call
through once.

The agent's setup proposals can now include a trusted chat or user, shown on `/sentrook-setup` with its warning and
set from there; the setup report counts the trusted chats and users and lists the group chats the agent was used in.
