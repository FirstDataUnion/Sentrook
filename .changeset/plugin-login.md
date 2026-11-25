---
"@firstdataunion/sentrook-openclaw": patch
---

`openclaw sentrook login` signs in instead of making you copy credentials. It prints a link and a code; open the link
on any device, sign in or create a free FIDU account, and approve. The command then writes this machine's scan
credentials to `~/.openclaw/.env` (mode 600, every other line kept) and runs the same checks as `verify`. Signing in
again from the same machine replaces its credentials (a random id for the machine is kept in the state folder) and
says when to restart the gateway; `--name` sets how the machine is listed in the account. If credentials are already
set somewhere that wins over `.env` (plain values in the plugin config, or the gateway's environment), it says where
and stops before signing in. Ctrl-C ends it at any point with nothing changed. Nothing the identity service
writes is printed, and never the secret.

Sentrook still stops every tool call while it has no credentials, and now says how to fix it: the block the agent
reads, the approval card, `/sentrook-status`, `verify` and a warning at startup name `openclaw sentrook login`.
Credentials the identity service refuses (`invalid_client`: revoked or wrong) say to sign in again.
