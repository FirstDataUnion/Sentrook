---
"@firstdataunion/sentrook-openclaw": patch
---

A Google Drive, Docs or Sheets file or folder id is no longer redacted as a secret where the call names Google. Since a
value that looks random under a key is redacted, an id in a Drive query (`parents='<id>'`) or in a script that works on
documents (`const PLAN = "<id>"` beside `documentId`, `textRun`, a Google API host or client library, or a Drive or Docs
tool such as `drive_files_list` or `docs_get`) became a placeholder: the scanner could not see which document or folder
the call reads or writes, and counted the id as a secret being sent. Such an id now stays when its own text, or for a
value in a call's arguments its own object, names Google. A value of that shape with nothing naming Google, any value
under a credential key, a key with a secret word in it (`SESSION_KEY`, `Authorization`, `connect.sid`, `cookie`, `hmac`) or a custom `X-`
header, and every other random value are redacted as before.
