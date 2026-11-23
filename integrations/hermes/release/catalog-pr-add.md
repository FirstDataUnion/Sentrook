**What it does.** Sentrook scans each tool call the agent is about to make (terminal, file, web, messaging, MCP and so on) in the context of what the owner asked for and what the session has done so far. Depending on the risk score it allows the call, hands it to Hermes's own approval prompt, or blocks it with a short reason for the agent. It is a security tool and is proposed as one: it sends redacted tool calls to a hosted scanner.

**Hermes surfaces used.**

- Hooks: {{hooks}}. `pre_llm_call` gives the owner's request for the turn, `post_api_request` the model's narration and batched calls, `pre_tool_call` runs the scan and returns the allow / approval / block directive, `post_tool_call` keeps tool results for the next scan, `post_approval_response` keeps the owner's answer in the session history.
- `ctx.register_command` (`/sentrook status|history|why|grants|grant|revoke|bind|snooze`) and `ctx.register_cli_command` (`hermes sentrook verify` and the same subcommands). Owner-only subcommands check the sender.
- `ctx.get_config` for settings; `agent.secret_scope.get_secret` for the two scan credentials ({{requires_env}}), declared as `type: secret` and `requires_env`.
- `hermes send` (run with Hermes's own Python, the text on standard input) for the one notice to the owner's home channel when a call is held on an unattended run, or blocked there because the scan failed. Hermes 0.23 registers no `send_message` tool for `ctx.dispatch_tool`; the plugin uses that tool only on a Hermes that registers it and has no `hermes send`.
- Validate warnings (rule 9): the plugin reads, but never patches, some undocumented core modules; the warnings name each one by file and line. Each read is guarded: if Hermes moves the symbol, the plugin falls back to the more cautious reading instead of failing. We would rather use public seams for these and are glad to open issues for them.

**Disclosures.**

- Network: one request per tool call to `sentrook.firstdataunion.org` (First Data Union's scan service) with the pending call, its arguments, recent tool results (capped at 256 KB), a short session history and host facts. Secrets the plugin recognises are replaced with placeholders before sending; other content, including personal data in files and messages, is sent as it is. Token mint at `identity.firstdataunion.org`.
- With `skill_review: allow` (default), Hermes's own background skill and memory saves are sent with the redacted recent conversation so they can be judged against it; the plugin keeps that conversation, redacted, under `HERMES_HOME/sentrook/conversations/` (pruned after 7 days). `skill_review: review` stops both and deletes the logs.
- Can block a call or route it to Hermes's approval. It never approves anything itself. Where nobody can answer (cron, webhooks, the API server unless configured as attended), a review holds the call and sends the owner one notice on a home channel; those notices, and one per job when a scan failure blocks a call there, are the only messages it sends.
- Files: only its own folder, `HERMES_HOME/sentrook/` (a local traffic log of the redacted scans, rotated at 50 MB; grants; snooze state; held calls), or paths the owner sets. Reads Hermes's config.yaml for approval and redaction settings. No shell commands, no self-update; the only process it starts is `hermes send`, for a notice.
- Credentials: stored by Hermes, read with `get_secret`. The plugin never reads `.env` or `auth.json`.
- Telemetry: none beyond the scans themselves.
- Off switches: observe mode (`settings.mode observe`) scores and logs without ever blocking or asking; `hermes plugins disable sentrook` stops all scanning.

**This release ({{version}}).**

{{changelog}}

**Checks.** {{checks}}

Pinned commit: `{{sha}}` ({{tag}}).

Submitted by First Data Union, the plugin's owner.
