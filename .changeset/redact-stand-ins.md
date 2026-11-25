---
"@firstdataunion/sentrook-openclaw": patch
---

A quoted example value that only stands in for a secret is no longer redacted as if it were one. Docs and notes that
show a token file's shape (`"access_token": "ya29.a0..."`, `"refresh_token": "1//0g..."`) keep a value cut short with
an ellipsis (up to 15 characters before it), the word `REDACTED`, a run of one symbol (`••••••••`) and a phrase that
says what it stands for (`"short-lived token"`), so saving such notes into a skill or memory is not scored as saving a
secret. A full token, with or without an ellipsis after it, a run of one letter or digit, a phrase with a long run of
token characters or a word that mixes letters with digits or symbols, an unquoted value before an ellipsis and any
value under a credential key in a parsed object are redacted as before.
