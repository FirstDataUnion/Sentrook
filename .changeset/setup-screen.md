---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-setup` (owner only; also `openclaw sentrook setup`) lists what would stop Sentrook asking about routine
work, each item described by Sentrook in its own words with how long it lasts and what to check: a channel binding for
each cron job's delivery to a room that is not bound yet, a provider grant for each MCP server no grant covers, the
grant Sentrook suggested on at least two reviews you approved in the last 30 days (from your own message, in a chat
where the scanner flagged no steering content, and only for exactly that grant: a broader pattern never counts), and
items the agent proposed, with its reason shown last as a note. Every name and note is shown in a code span, so links,
mentions and emphasis in them do nothing, and a config entry that is not one plain word is left out and counted. The screen ends with a four-digit code, new each time
and valid for 15 minutes: `/sentrook-setup apply <code>` sets every item, `apply <code> 1,3` some of them. Grants
backed by reviews you approved last until revoked, the others 30 days, and channel bindings until removed; `--expires
90d` or `--until-revoked` changes the grants' lifetime. Applied grants are persistent and say where they came from;
applying an item twice sets nothing new. `/sentrook-setup discard <id>` drops an agent proposal. OpenClaw keeps a
command's reply in the chat's transcript, so the agent can read the screen afterwards; everything on it is Sentrook's
own text, and the code only proves the screen was shown in your chat. The setup skill now sends you to this screen,
and the agent's rules add `/sentrook-setup apply` to the commands it never runs.

A refused owner command now says where owner commands run: your own direct message to the agent (a sender in
`commands.ownerAllowFrom`, which your first pairing approval fills), the Control UI, or `openclaw sentrook <command>`
on the machine. It used to name only the Control UI.

`/sentrook-setup` refuses in a group or channel room, where OpenClaw would still count your message as the owner's
and the list would be shown to everyone there.
