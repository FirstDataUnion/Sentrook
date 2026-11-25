---
"@firstdataunion/sentrook-openclaw": patch
---

A password or token with `&`, `,` or `;` in it is now redacted whole. After a key in an assignment, an `.env` line or
a quoted value (`password=<value>&<rest>`, `export DB_PASSWORD=…`, `password='…'`) the value used to end at the first
of these characters, so the rest of it left the machine as written, and the same password written `password: …` got
another placeholder. What follows a value is still kept where it is something else: another parameter in a link's
query or a form body (`?password=…&page=2`, `user=a&password=…&remember=1`), the next key of a list or a connection
string (`a=1,b=2`, `;Initial Catalog=…`), an HTML entity (`&quot;`), and a command or statement after the value (`…;
echo ok`, `…;npm publish`, `…&&next`, `…;return x`), so the scanner still sees it.
