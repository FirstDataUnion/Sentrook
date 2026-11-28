---
"@firstdataunion/sentrook-openclaw": patch
---

With no notify target set, a held call's notice (and a run's end line, and the line on how a started run went) no
longer goes nowhere: it goes to the chat the cron job delivers its own output to (an `announce` delivery that names
its `channel` and `to`), else to your direct message when `commands.ownerAllowFrom` names exactly one owner on a
channel OpenClaw has configured. It never goes to a chat the job does not deliver to, and it ends with a line saying
where it went and how to set a target. While calls are held with no target set, `/sentrook status` warns, `verify`
fails its held-call notices check and the setup report lists it as its first gap. The setup skill now asks for
`/sentrook-notify here` right after checking the install.
