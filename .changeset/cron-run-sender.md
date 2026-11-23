---
"@firstdataunion/sentrook-openclaw": patch
---

Cron and heartbeat runs are again sent as runs nobody wrote, whatever requester OpenClaw attaches. Since OpenClaw
2026.11 a cron run carries its delivery channel as the requester, so the plugin sent it as someone else's message:
a held call in it never suggested a grant, and a destination the job's own task named got no relief. A run
flagged as the owner's stays the owner's.
