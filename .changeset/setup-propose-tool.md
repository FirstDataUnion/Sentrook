---
"@firstdataunion/sentrook-openclaw": patch
---

The agent gets a second tool, `sentrook_propose_setup` (listed in `contracts.tools`), which the setup skill now uses at
hand-over instead of giving you commands to paste: it adds up to 20 grants and channel bindings you told the agent
about, each with a reason of at most 200 characters, to your `/sentrook-setup` list as "proposed by the agent, not seen
yet". It sets nothing. Each item must be one `/sentrook-grant ... --persistent` or `/sentrook-bind add` would accept,
and the agent is told which were not added and why; settings, attended platforms and session grants are refused, and a
key is named, never its value. The agent hears only how many items were added and to ask you to open
`/sentrook-setup`. A proposal is kept in `proposals.json` for a day, at most three at once. OpenClaw offers it only
when the sender is the owner, and Sentrook answers only a run started by your own message in a direct chat, with the
same refusal elsewhere and nothing stored; the call itself is not scanned, its result goes to the next scan, and each
call is logged as a `setup_proposal` record. The setup report and the proposal share one gate: the one-time marker is
keyed by the session and the call id, and a call another tool of the same name answered is logged as foreign, after
which calls of that name are scanned like any call.
