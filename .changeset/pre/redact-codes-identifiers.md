---
"@firstdataunion/sentrook-openclaw": patch
---

Access codes, PINs, passport numbers and random values under a key or header no longer leave the host raw. A short
number is redacted after a cue word ("the gate code is …", "Alarm code: …", "collection PIN for order 441 is …",
"… is your verification code") or under a code or PIN key (`yard_code=`, `client_pin=`, `pin=`, a form's `code=`);
with no cue it stays, and so do postal, country, status, error and other ordinary codes. A passport number becomes
`⟦secret:identifier:…⟧`. A random value of 12 or more letters and digits is redacted under any key or header
(`value: …`, `-H "X-Desk: …"`, a `headers` object), never in prose, and never under a key that names an id, a hash, a
version, a trace or data; hex values, UUIDs and camelCase words stay. Traffic logs written by earlier versions may
hold these values.
