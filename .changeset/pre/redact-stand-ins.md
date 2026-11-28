---
"@firstdataunion/sentrook-openclaw": patch
---

A quoted example value that only stands in for a secret is no longer redacted as if it were one, so docs and notes
that show a token file's shape can be saved into a skill or memory without being scored as saving a secret. Kept under
any key: the word `REDACTED` and a mask of `*`, `•` or `·` (`"••••••••"`). Kept only in a quoted value under a token
or key that does not name a password: a token cut short with an ellipsis after at most ten token characters
(`"access_token": "ya29.a0..."`, `"refresh_token": "1//0g..."`), and a short phrase that says what it is
(`"short-lived token"`, `"your api key"`). Still redacted as before: a full token, with or without an ellipsis;
anything under a password (`"password": "<short value>..."`, a passphrase); a phrase that does not say what the value
is; a value after a command-line flag, `mysql -p` or `sshpass -p`; an unquoted value before an ellipsis; and any value
under a credential key in a parsed object.
