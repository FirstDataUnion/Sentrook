---
"@firstdataunion/sentrook-openclaw": patch
---

Report a scan that looks wrong. `/sentrook-report [id|last]` (owner only; `openclaw sentrook report` on the command
line) prints a report to copy and send to Sentrook: what `/sentrook-why` shows, plus the host, plugin and scanner
versions from the scan's own record, and two lines to fill in (what you expected, what you were doing). It holds no
call arguments or conversation text. `--github` gives a link that opens a public GitHub issue with the report filled
in. `--full` adds the full record, the scan's traffic-log lines exactly as written, so Sentrook can replay the scan;
it can hold conversation text, paths and addresses, so it is only for private sending, never an issue. `--save`
writes the report and full record to a file only you can read, to email to sentrook@firstdataunion.org (kept for up
to 30 days, then deleted). In the Sentrook tab, every scan has **Report this scan…**: the report to copy, the GitHub
button, and the commands and email address for the full record, which the tab never shows.
