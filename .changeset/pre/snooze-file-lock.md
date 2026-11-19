---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-snooze` changes are now safe when the gateway and the command line change snoozes at the same time: a
snooze set or ended in one is no longer undone by the other. When the snooze file stays locked by another process,
nothing is changed and the reply says to try again.
