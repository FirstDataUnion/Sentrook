---
"@firstdataunion/sentrook-openclaw": patch
---

Beta: while a snooze is on, a block in a chat you attend asks you instead of stopping, whatever caused it: a floor, a
strong signal or a rule that always blocks included. Until now only a block Sentrook marks as having no clear attack
signal asked, so a false alarm with a floor left no way past but switching Sentrook to observe. That prompt keeps its
wording ("Would be blocked, but a snooze is on."). Any other block gets a stronger warning: it names why it would be
blocked and says "A snooze is on: allow only if you asked for exactly this call." Both are at critical severity, offer
**Allow once** and **Deny** only, and ask again on the next call; the stronger one suggests no grant, and while the
snooze lasts an action asked about either way asks with the stronger warning again even when it is scored later as an
ordinary review. The stronger one needs a complete scan: when one of Sentrook's checks failed, the block stays a
block. A change to Sentrook itself (its files, settings or log, turning the plugin off, stopping the gateway, a
Sentrook command only you should run, loosening the host's approvals), and any block that may be one, stays a block
during a snooze; so does a block with a floor or a strong signal on email, SMS, IRC or ntfy, where anyone can claim a
sender. Nothing changes on unattended runs, for other senders, in group rooms, in observe mode, on
scan errors or without a snooze. The snooze reply, `/sentrook-snooze status`, the guide and the agent skill say so.
The traffic log marks such a prompt with `relaxed_strong: true`.
