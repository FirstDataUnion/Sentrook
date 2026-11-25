---
"@firstdataunion/sentrook-openclaw": patch
---

The plugin ships two agent skills, which OpenClaw loads while the plugin is enabled: `sentrook-guide` (how Sentrook
works, so the agent can explain an approval prompt, a block, a held call or a notice, and point you to
`/sentrook-why` and `/sentrook-report`) and `sentrook-setup` (the agent asks what is routine for you and gives you the
grant and binding commands to type, one at a time). The agent's system prompt also gets a few short rules from the
`/sentrook` command: never run the commands that change Sentrook, never edit its settings or folder, never disable
the plugin, and never retry a blocked call reworded. A read of the plugin's own skill file goes to the scanner as a
read of the agent's own skills (only when its path resolves to the plugin's own file and it returned the text the
plugin loaded), so the skill's instructions do not count as content steering the agent; a copy of the text anywhere
else is read as before. `openclaw sentrook verify` warns when a workspace, project, personal or
managed skill has the same name as one of these, since OpenClaw would load it instead.
