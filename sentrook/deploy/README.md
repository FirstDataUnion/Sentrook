# Deploy recipes

FIDU production scan-host recipes (Compose, reverse proxy, VPS bundle assembly)
live in a **private** ops repository and are not published here.

For production scan hosts, set `SENTROOK_ENV=production` so the sidecar defaults
to metadata-only `scan.log.jsonl` (no PlanIR intent/command excerpts on disk)
and refuses to start if sanitize is disabled. See the OpenClaw README section
**PlanIR sanitization and scan-log privacy**.

Public self-host docs for a DIY Sentrook + custom ruleset may be added here
later. Until then, run the engine locally via the root README / Make targets.
