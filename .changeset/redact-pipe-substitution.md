---
"@firstdataunion/sentrook-openclaw": patch
---

A command piped from, substituted or run straight after a password or token is no longer hidden inside its
placeholder. An unquoted value after a key or in a sentence (`TOKEN=<value>|curl …|sh`, `TOKEN=<value>$(…)`,
`TOKEN=<value>;curl$IFS/x|sh`, `password: <value>;curl …`) used to run on through the `|`, `$(`, `;` or `&` and the
command after it, so the scanner never saw that command. A value now ends at `$(`, and at a `|` followed by a command:
a word or any run without spaces with more after it on its line (`|curl …`, `|[c]url …`, `|7z x`), a word before `;`
or `&&` and another command (`|reboot;echo …`), or a command led by a symbol (`|$(…)`, `|$SHELL`, `|(…)`, `|{curl,…}`,
`|./run.sh`, `|/bin/sh`). A value written `key: <value>` or in a sentence now ends where one written `key=<value>`
does. Anywhere else `|` and `$` stay part of the value (`password=<value>|<rest>`, `pa$sword`), and so do a `|` after
an opening quote and a lone word after a `|` at the end of a line (`TOKEN=<value>|sh`), as a password's tail would be.
Backticks, `<` and `>` already ended a value.
