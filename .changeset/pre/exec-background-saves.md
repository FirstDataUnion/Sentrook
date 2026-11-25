---
"@firstdataunion/sentrook-openclaw": patch
---

A skill the Skill Workshop review (or the skill collection review, or a note the memory flush) saves from the shell,
with a heredoc, `tee` or `cp` into the skill folder, is now judged as a background save, like one saved with the skill
or file tools: Sentrook checks it against the conversation the review read, and it is never asked about. It runs when
the scan allows it, and is otherwise held or blocked, never let through on a review, since a command carries no
content a draft could keep. The plugin sends each command of these runs with that conversation, and Sentrook treats a
command as a save only when saving into the run's own skill folder (the day's note for the memory flush) is all it
does; any other command, including one that saves and also does something else, is scanned as before.
