---
"@firstdataunion/sentrook-openclaw": patch
---

A credential field's name is no longer redacted as if it were a secret. In text, a value after a password, token or
API-key key that names such a field or stands in for one (`api_key:api_secret` quoted from an API's docs,
`password: your_password`, `apiKey=apiSecret`, `token: xxxxxxxx`) or is a short lower-case word (`password=changeme`)
stays, so a call that quotes documentation is not scored as sending a secret. Values with a digit, mixed case or a
symbol, vendor shapes such as `sk-live-…` and `ghp_…`, and longer values are redacted as before, and so is any value
under a credential key in a parsed object.
