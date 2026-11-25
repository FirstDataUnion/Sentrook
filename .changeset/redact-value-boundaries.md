---
"@firstdataunion/sentrook-openclaw": patch
---

A password or token with `&`, `,` or `;` in it is now redacted whole. After a key in an assignment, an `.env` line or
a quoted value (`password=Tr0ub4dor&3`, `export DB_PASSWORD=…`, `password='…'`) the value used to end at the first of
these characters, so the rest of it left the machine as written, and the same password written `password: …` got
another placeholder. A link's query (`?password=…&page=2`), a form body (`user=a&password=…&remember=1`), a list
(`a=1,b=2`) and a shell command after a value (`…; echo ok`, `…&&next`) still end the value where they did.
