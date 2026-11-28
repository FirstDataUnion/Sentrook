---
"@firstdataunion/sentrook-openclaw": patch
---

The agent's setup tools (`sentrook_setup_report` and `sentrook_propose_setup`) are now offered when OpenClaw's config
sets a tool profile (`tools.profile`, for example `coding`): the plugin manifest lists them for every profile, so the
agent can help you set Sentrook up. `openclaw sentrook verify` warns when a `tools.allow` or `tools.deny` list (global
or one agent's) still hides them, with the setting to change; `/sentrook-setup` works either way.
