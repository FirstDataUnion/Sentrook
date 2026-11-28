---
"@firstdataunion/sentrook-openclaw": patch
---

A destination grant over a whole public suffix is refused. A destination may use a wildcard on a host or a mail domain
only as `*.` and one registrable domain (`*.example.com`, `*.example.co.uk`, `*.myname.github.io`), or as `*.` and a
name that never resolves on the public internet (`*.lan`, `*.local`, `*.internal`, `*.test`, `*.example` and the
like). `/sentrook-grant destination *.com` is refused with the reason, and so is a wildcard over another top-level
domain or a common shared suffix where anyone can get a name (`*.co.uk`, `*.ne.jp`, `*.github.io`, `*.vercel.app`,
`*.amazonaws.com`; the common ones, not every one), or inside a name (`api*.example.com`), as Sentrook ignores such a
grant: it would let calls reach sites run by strangers. A wildcard in a channel's name (`discord:#daily-*`) or before
an `@` (`*@example.com`) is still taken. Such a grant in `openclaw.json`, or one already in the grants file, is never
sent: `/sentrook-grants`, `/sentrook status` and `openclaw sentrook verify` list it as too broad, and the other grants
still apply. A channel binding like it is listed as too broad and never sent. A credential grant's host follows the
same list of shared suffixes. A wildcard address such as `192.168.1.*` is refused too, and one already in the config
is listed as too broad and never sent: write the exact hosts instead. A bare name with a wildcard such as `daily-*` is
refused as a destination, as it would match hosts too: write `#daily-*` or `discord:#daily-*` for channel names.
