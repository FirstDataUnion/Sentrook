---
"@firstdataunion/sentrook-openclaw": patch
---

Smoother agent-led setup. The setup report the agent reads (`sentrook_setup_report`) has a new "Approval cards in
chat apps" section: for each chat app OpenClaw has on, whether Sentrook's approval cards reach you there, and the
`openclaw config set` command to run when they do not (Discord needs `execApprovals` enabled, Discord and Telegram an
approver, WhatsApp and Signal `approvals.plugin`). The `sentrook-setup` skill's approval-card step now reads it and
covers every chat app you use. The agent sends you to `/sentrook-setup` only after its proposal tool has added the
items; if its setup tools are missing it says so and gives you exact owner commands instead of guessing; it runs
only `openclaw sentrook verify` and `status`, with a long enough timeout to wait for them. `/sentrook-setup` with
nothing on the list now says that Sentrook found nothing new and the agent added nothing.
