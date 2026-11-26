---
"@firstdataunion/sentrook-openclaw": patch
---

An unattended run keeps the scanner's `cap.local_code` ceiling, as it keeps the ceiling on a retry of a review nobody
answered, so both plugins decide the same from the same response. The scanner sets it only for Hermes `execute_code`
programs today.
