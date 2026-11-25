---
"@firstdataunion/sentrook-openclaw": patch
---

A Code Mode `exec` (the cell of JavaScript that runs other tools) is sent with OpenClaw's own mark that it is one, so
Sentrook no longer reads its JavaScript as a shell command: an arrow function such as `f => f.name` looked like a
command writing a file in the working directory, which in the Skill Workshop review (it works in the agent's skill
folder) read as the agent changing its own setup and could stop the review before it saved anything. Only OpenClaw's
mark on the hook event counts, never the call's arguments; a shell `exec` is read as before, and every call the cell
makes is still scanned on its own.
