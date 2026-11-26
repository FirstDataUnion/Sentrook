---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-dismiss <id>` (or `/sentrook-dismiss all`) takes a held call off the waiting list without answering it, as
if it had expired now. It works on any hold, including one that offers no answer (a run with no source, or a hold
from an earlier version) and one you would rather not deny for 30 days. The call never runs and nothing is set: no
pass, denial or grant, and a call like it is held again with a notice. Each dismissed call is recorded in the traffic
log with the resolution `hold_dismissed`, and `/sentrook-history` shows its review as `dismissed`. Like the other
answers, it is for the owner only and the agent is told never to run it.

The dashboard's **Waiting for you** section now folds: click its heading to fold it away, and the tab remembers that
in your browser until something newer is waiting. It shows the first three items with the rest behind **Show more**,
and names `/sentrook-dismiss` on each held call and `/sentrook-dismiss all` when more than one is waiting.
