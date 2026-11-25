---
"@firstdataunion/sentrook-openclaw": patch
---

A cron job's sub-agents belong to the job. A sub-agent of a cron run (its parent session as `subagent_spawned` names
it, or a sub-agent of such a sub-agent) now makes the job's holds: the notice says "a sub-agent of cron job …",
`/sentrook-allow` starts the job again, and the job's passes and denials cover the same call from its later runs'
sub-agents. Before, they were bound to the parent session, new every run, so no answer carried to the next run. A
sub-agent whose parent is not known yet when it makes its first call is held as before.

One notice per cron run. The run's first held call sends the notice; a later held call of another action in the same
run joins it and sends nothing then, and when the run ends one line lists those calls with their ids.
`/sentrook-allow <id> all`, on the id that line names, lets every listed call through once in the same started run,
each still checked against its own scan; a listed call that itself sends or writes is left for its own answer.
