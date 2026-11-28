---
"@firstdataunion/sentrook-openclaw": patch
---

The `sentrook-guide` skill has a new section, "Working well with Sentrook", on shaping work so Sentrook can judge it
clearly: fetch web pages and APIs with OpenClaw's own web tools rather than HTTP in code; keep code local (a code or
shell call that reads local files does not also reach the network); install packages once, early, in a chat with the
owner, not in cron jobs, heartbeats or subagents; keep a task's files in one work directory; refer to keys by name;
and when a call is held or blocked, tell the owner and point to `/sentrook-why` rather than try it again in a new
shape. It says plainly that this is about clear scans, never about getting past a check.
