---
"@firstdataunion/sentrook-openclaw": patch
---

The Sentrook tab can show what a call contained. Turn on `dashboardShowCalls` and each scan gets **Show the call**,
collapsed under its details: the tool and its arguments as the plugin sent them to the scanner (secrets masked, very
long text cut), with an edit's old and new text side by side. It is off by default, because anyone with gateway
access can open the tab; with it off, **Show the call** gives the setting and the `/sentrook-report <id> --save`
command instead.
