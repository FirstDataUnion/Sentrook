---
"@firstdataunion/sentrook-openclaw": patch
---

A read of the plugin's own `sentrook-setup` or `sentrook-guide` skill now counts as a read of the agent's own skills
again on OpenClaw 2026.11, which runs plugin code from a copy of the installed folder: the plugin also accepts the
folder OpenClaw installed it in (where `~/.openclaw/plugin-skills/` points), with the same checks as before (the text
the plugin loaded, a regular file, no link leading elsewhere). Before, the skill's instructions counted as content
steering the agent, so a setup chat asked about calls it should not have. The `sentrook-setup` skill also tells the
agent never to read Sentrook's folder or traffic log and to call the `sentrook_setup_report` tool instead.
