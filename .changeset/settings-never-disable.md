---
"@firstdataunion/sentrook-openclaw": patch
---

A typo in Sentrook's settings no longer gets the plugin disabled. OpenClaw's `doctor --fix`, which the official
Docker image runs on every start, deleted the settings of a plugin whose config failed its manifest schema and
disabled the plugin, so a misspelt key or a grant scope such as `"persistant"` left every tool call unscanned with no
warning. The manifest now accepts any settings and Sentrook checks them itself: a setting it cannot read is ignored or
replaced, and named in the gateway log at start, on a new `settings` line in `openclaw sentrook verify` (which fails)
and `/sentrook status`, and in a notice to you at most every 6 hours while it stands.
