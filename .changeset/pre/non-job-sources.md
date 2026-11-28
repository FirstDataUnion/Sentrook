---
"@firstdataunion/sentrook-openclaw": patch
---

Held calls on runs that are not cron jobs now bind to where the run came from. A heartbeat's hold is bound to its
agent (`ctx.agentId`), and a subagent's to its parent session (the requester session the spawn hooks report). Such a
hold offers `/sentrook-allow <id>` (a one-use pass for the next matching call from the same source within 7 days;
nothing is started), `/sentrook-allow <id> always` where offered, and `/sentrook-deny <id>`, each bound to that
source; the notice and the replies name it, and `/sentrook-passes` lists each pass by its source. The same call from
another agent's heartbeat or another parent session is held again. A webhook or event run keeps allow alone, bound
to the exact arguments: OpenClaw gives plugins no hook or mapping id, and the run's ids are new for every request.
Sources are never read from the prompt or the call, and the stored ref is a hash. The texts are the same as the
Hermes plugin's.
