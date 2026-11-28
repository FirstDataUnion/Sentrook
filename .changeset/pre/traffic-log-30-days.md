---
"@firstdataunion/sentrook-openclaw": patch
---

The local traffic log keeps records for 30 days. As it writes (at most once an hour), the plugin deletes older records
from `traffic.jsonl` and its rotated copy `traffic.jsonl.1`: a file holding only older records is deleted, and one that
holds both is rewritten without them. `/sentrook-history`, `/sentrook-why`, `/sentrook-report` and the dashboard show
what is inside those 30 days.
