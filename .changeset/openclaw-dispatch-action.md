---
"@firstdataunion/sentrook-openclaw": patch
---

On OpenClaw 2026.11.3 or newer, where tool search's dispatcher is named `dispatch_action` (it was `tool_call`, which
OpenClaw still accepts), the dispatcher is again not scanned itself: only the call it runs is, once, as before. Until
now each such call was scanned twice, once as a `dispatch_action` call of unknown kind and once as itself, the plugin's
own setup tools got a scan of their dispatcher that could raise a review, and the history sent with a scan showed the
bare dispatcher instead of the call it ran. A dispatcher beside the call being scanned is shown as the call it runs,
under either name. Both names are handled on every supported OpenClaw (2026.9.5 or newer).
