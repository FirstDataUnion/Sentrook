---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-grant credential NAME@host` ties one of your API keys to the service it is for, such as
`/sentrook-grant credential MY_SERVICE_TOKEN@api.myservice.example`. Sending that key, read from the agent's env file,
only to that host is then not treated as sensitive data leaving the machine. The name may end in `*` after three or
more characters, and the host may be `*.example.com`. A credential grant is persistent unless you give
`--scope session`; a pattern Sentrook would not read is refused when you type it. When a review is caused by such a
key going to its own service, the approval card suggests the grant, and **Always allow** sets it as it does other
suggested grants.
