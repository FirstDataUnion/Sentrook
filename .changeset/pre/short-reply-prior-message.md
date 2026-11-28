---
"@firstdataunion/sentrook-openclaw": patch
---

When you answer the agent with a short message (300 characters or less, such as "yes", "go with A" or "try again"),
each call of that run also sends the agent's last message before it, so the scanner can see what you agreed to
instead of reading your reply alone. It is sent as the agent's words, never as your request, redacted and cut to 2,000
characters (start and end), and only with `allowConversationAccess`. It is not sent with a longer message, someone
else's message, a scheduled run or a sub-agent.
