---
"@firstdataunion/sentrook-openclaw": patch
---

A destination grant over a whole public suffix is refused. A destination may use a wildcard on a host or a mail domain
only as `*.` and one registrable domain (`*.example.com`, `*.example.co.uk`). `/sentrook-grant destination *.com` (or
`*.co.uk`, `*.io`, `**.com`, `*.0.1`, `api*.example.com`) is refused with the reason, as Sentrook ignores such a grant:
it would let calls reach sites run by many owners. A wildcard in a channel's name (`discord:#daily-*`) or before an `@`
(`*@example.com`) is still taken. Such a grant in `openclaw.json`, or one already in the grants file, is never sent:
`/sentrook-grants`, `/sentrook status` and `openclaw sentrook verify` list it as too broad, and the other grants still
apply. A channel binding like it (`*.com`, `daily-*`) is listed as too broad and never sent.
