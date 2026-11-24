---
"@firstdataunion/sentrook-openclaw": patch
---

Held calls: every answer now does something. Before, `/sentrook-approve <id>` only set the grant Sentrook suggested,
and on scheduled runs it never suggests one, so approving set nothing and the job was held again on its next run. A
hold on a cron job now offers, in its notice, only the answers that apply:

- `/sentrook-allow <id>`: the job's next run may make the same call once (`/sentrook-allow <id> later` does the same).
- `/sentrook-allow <id> always`: the job may make the same call for 30 days, with a use count. Offered only when the
  scan's `owner_pass` says the call may be let through for good and the call names its parties; a scanner that does
  not send `owner_pass` never gets it.
- `/sentrook-deny <id>`: the job is refused the same call for 30 days. The agent gets a plain declined result and no
  notice is sent.
- `/sentrook-approve <id>` stays as `/sentrook-allow` for one release.

"The same call" is matched on the same terms as the Hermes plugin's Session answer: the same tool, the same parties,
a score no higher, no new warning, nothing enforced and no floor, and the scan's `owner_pass` at or above the pass's
level. The job is the one OpenClaw's run metadata names on a cron run (`ctx.inputProvenance.jobId`, else `ctx.jobId`),
never the prompt's `[cron:...]` tag. A call that names nothing is matched on its exact arguments and offered allow once
only. A hold on a run that is not a cron job offers only allow, bound to the exact arguments, for 7 days. Answering
never sets the suggested grant: `/sentrook-why <id>` shows its command.

Holds can be answered for 7 days (was 24 hours), and a repeat of a waiting hold updates it without a new notice.
`holds.json` is version 2 and keeps no raw arguments; older holds stay answerable as before until they expire.
`/sentrook-passes` lists and revokes the passes and denials (`passes.json`); status, verify and the dashboard show them.
After allow, the held call's history entry becomes `approved_by_user`, so a retry in the same session is not scored
as a retry after a review nobody answered. The traffic log records `allowed_by_pass` and `denied_by_owner`.
