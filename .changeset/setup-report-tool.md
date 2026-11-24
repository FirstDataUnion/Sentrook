---
"@firstdataunion/sentrook-openclaw": patch
---

The agent gets a read-only tool, `sentrook_setup_report` (listed in `contracts.tools`), which the setup skill now uses
at check-in: what is set (counts of grants and bindings by kind, never the grants), the gaps in plain words (a skill
with the name of one Sentrook ships included), the grants Sentrook suggested on reviews you approved at least twice
(marked covered when a grant in force already covers one), approved reviews with nothing to suggest by tool, and API
key names Sentrook saw sent only to their own service, over the last 14 days (`days`, up to 30), saying how far back
the log actually went. It shows no call's arguments or request text, and every name from a tool call is neutralised.
OpenClaw offers it only when the sender is the owner, and Sentrook answers only a run started by your own message in a
direct chat; everywhere else (cron, heartbeat, webhook and event runs, subagents, group rooms, OpenClaw's background
runs) the whole answer is "Setup needs the owner in a direct chat." The call itself is not scanned, its result goes to
the next scan, and each call is logged as a `setup_report` record.
