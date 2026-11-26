---
"@firstdataunion/sentrook-openclaw": patch
---

If you withdraw consent on the FIDU portal, the identity service stops accepting this machine's scan credentials.
Sentrook then tells you once, where notices go and in observe mode too, that scans stopped and how to connect again
(`openclaw sentrook login`), switch to observe mode or uninstall, instead of a scan-failure notice per job. It is sent once for
these credentials, also across restarts; signing in again or setting new credentials resets it. Calls are handled
as for any credential problem: asked where you can answer, blocked where nobody can (and with `onScanError: allow` too), run
in observe mode; the prompt, the agent's message and `verify` say consent was withdrawn.

`openclaw sentrook login` now prints what each check sends and to whom, the privacy policy, the terms and how to stop, with the
terms version you accepted (and when) if the identity service gives it.
