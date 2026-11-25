---
"@firstdataunion/sentrook-openclaw": patch
---

The Sentrook tab's explanations now show. Every label, score, signal and badge had a hover hint, but the browser's
own tooltip does not appear inside the Control UI tab frame in some browsers (Opera GX and DuckDuckGo among them),
so only the help cursor showed. The tab now draws its hints itself: on hover, on keyboard focus (hinted labels can
be reached with Tab) and on tap on a touch screen. Escape, moving away or tapping elsewhere hides them.
