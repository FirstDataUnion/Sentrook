---
"@firstdataunion/sentrook-openclaw": patch
---

The setup skill now starts by making sure approval cards reach your chat apps: it reads `commands.ownerAllowFrom` and
each app's `execApprovals` and gives you the `openclaw config set` commands to run in a terminal (Discord and Slack
need their cards switched on, WhatsApp and Signal need `approvals.plugin` forwarding). It never changes those settings
itself. It suggests doing the first setup in the Control UI or `openclaw tui`, works out what is routine from the
agent's own cron jobs, skills, MCP servers and the setup report instead of asking you a list of questions, shows a
short list to keep or drop, and ends with how to get help when regular work is blocked later. The install guide has a
new section, "Approval cards in chat apps".
