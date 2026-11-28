---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-setup` and the setup report count a chat as having read content that tried to steer the agent only when
one of its scans gave an `exposure.*` reason: the scanner's own line for it, and every later call of a chat it judged
tainted carries one. The exposure scores alone no longer count, since almost any content scores a little, so the
screen warned about nearly every proposal from the agent and left out reviews you approved in ordinary chats.
