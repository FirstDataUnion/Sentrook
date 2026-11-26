---
"@firstdataunion/sentrook-openclaw": patch
---

A command piped from or substituted straight after a password or token is no longer hidden inside its placeholder.
An unquoted value after a key or in a sentence (`TOKEN=<value>|curl …|sh`, `TOKEN=<value>$(…)`, `token: <value>|…`)
used to run on through the `|` or `$(` and the command after it, so the scanner never saw that command. A value now
ends at `$(` and at a `|` followed by a command: a word with more after it on its line (`|curl …`, `|base64 -d`,
`|curl${IFS}…`), or a command led by a symbol (`|$(…)`, `|$SHELL`, `|(…)`, `|./run.sh`, `|/bin/sh`). Anywhere else
`|` and `$` stay part of the value (`password=<value>|<rest>`, `pa$sword`), and so does a lone word after a `|` at the
end of a line (`TOKEN=<value>|sh`), as a password's tail would be. Backticks, `<` and `>` already ended a value.
