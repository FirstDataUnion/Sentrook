---
"@firstdataunion/sentrook-openclaw": patch
---

Held calls: `/sentrook-allow <id>` on a held call of a cron job now runs the job again straight away, instead of
waiting for its next scheduled run. The plugin sets a one-use pass bound to the new run and starts it with
`openclaw cron run <job> --json` as a child process (the gateway's own OpenClaw, else `openclaw` on the PATH), with no
extra prompt; it never runs the held call itself. The pass serves only the run that command returns, as the job's
running receipt in OpenClaw's job store names it. When that run ends (`agent_end`, else the job's next scan), you get
one line on where notices go: the call went through, the run did not make it, or it made a different call (held as
`h-…`); a pass that run did not use ends with it. One run per held call.

Nothing is started, and the pass waits for the job's next scheduled run, when the job is gone, finished, disabled,
running, or changed since the hold (a digest of its definition is kept on the hold), when OpenClaw refuses the run, or
in observe mode; the reply says which. When the held run had already sent or written something before the held call,
plain `allow` waits for the next run and the notice offers `/sentrook-allow <id> now`, which starts the whole job again
with a warning that it repeats what it already did. `/sentrook-allow <id> later` keeps the wait-for-the-next-run answer.
The notice, the replies and the outcome line are the same text as the Hermes plugin's.
