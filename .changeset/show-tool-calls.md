---
"@firstdataunion/sentrook-openclaw": patch
---

`/sentrook-why` now shows the call itself (the tool's arguments as sent to the scanner: secrets masked, long text
cut), and a background-save notice shows the save it is about, marked as data, so you can judge it without opening the
dashboard. The dashboard shows each scan's call by default too. One new setting, `hideToolCalls`, hides calls in all
three places; `dashboardShowCalls` is no longer needed and does nothing. A report's summary never carries the call.
