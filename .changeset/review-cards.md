---
"@firstdataunion/sentrook-openclaw": patch
---

The approval card is easier to read and always recognisable as Sentrook's: its title is
`🪶 Sentrook security check · risk 62/100`, and the description says what the call does and why in plain words,
what "Always allow" would also trust, and ends with `/sentrook-why <id>` for the full detail. Reason codes and scores
moved to `/sentrook-why`. The card is fitted to OpenClaw's approval limits, so it is never refused; the description
of the call is shortened first.
