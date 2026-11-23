---
"@firstdataunion/sentrook-openclaw": patch
---

A channel binding or destination grant written `channel:<id>` (or `group:`, `thread:`) now reaches the scan of a
message send that names that channel only by its bare id, as `{channelId: "<id>"}`. Before, the plugin left such a
binding out of the request, so a send written that way was never relieved by it.
