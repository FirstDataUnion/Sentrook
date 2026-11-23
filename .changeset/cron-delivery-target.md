---
"@firstdataunion/sentrook-openclaw": patch
---

A cron job's own delivery channel counts as yours on that job's run. When a job set up with `--announce --channel
discord --to <channel id>` has its agent post to that channel with the message tool, the plugin sends that channel
as a grant for the run, so the post is not treated as going somewhere unfamiliar and is no longer held for review.
The plugin reads the job's delivery from OpenClaw's job store (read-only); a channel named in the task or in content
the run read never counts, nor does a person, a job with no target of its own, or a job changed after its run began
or by the agent during the run. The dashboard shows that relief as the job's delivery target.
