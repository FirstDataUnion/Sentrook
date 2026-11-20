# Wrong-scan report fixtures

Shared by both plugins' tests: for the same traffic log, `report` builds the same text and links.

- `traffic.jsonl`: a scored scan with a resolution, host versions, scanner metadata and suggested grants
  (`aaaa1b2c`); a failed scan from another host (`bbbb1b2c`); a bare scan with no PlanIR host (`cccc1b2c`).
  `PLANIR-BODY-MARKER` and `PRIVATE-PATH-MARKER` appear only in the PlanIR body, reason details and failure
  details, so they must never reach a summary or a link.
- `long.jsonl`: a scan with 79 long entities (`dddd1b2c`, the issue link drops entity lines from the end) and
  one with 120 long reason codes (`eeee1b2c`, too long for a link even without entities: the blank form).
- `odd.jsonl`: a record the plugins never write, read with `last`: a request id with path characters (the saved file's
  name keeps letters, digits and dashes only), lone surrogates in the tool and an entity (shown as U+FFFD, so the
  links encode), and a mode that is not text. Its goldens are `*-odd.txt`.
- `summary-<id>.txt`: the summary block.
- `full-<id>.txt`: the full record block; its lines are the log's lines byte for byte.
- `github-<id>.txt`: how the summary was fitted (`whole`, `trimmed` or `blank`), then the issue link.
- `mailto-<id>.txt`: the email link (subject and a short note, never the record).
