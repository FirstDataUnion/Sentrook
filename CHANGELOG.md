# Changelog

Sentrook 2.0 scanner. Work packages are tracked on the Notion page "Sentrook 2.0 build plan".
The 1.x engine and plugins keep their own history on `release/1.x`.

## Unreleased (2.0.0a1)

### WP0: skeleton (2026-10-16)
- Project scaffold: `pyproject.toml`, `Makefile`, package layout under `sentrook/sentrook/`, CI (lint, tests, schema drift check).
- PlanIR 2.0, Response 2.0 and probe-envelope models (`planir`, `response`, `probes`), with tolerant enums and additive fields kept.
- JSON Schema contracts generated from the models into `schema/`; `sentrook schema export [--check]`.
- Unit tests on the two worked examples from the design page and synthetic cases; no suite fixtures.

### WP1: preparation (2026-10-16)
- `planir.validate`: the 1.7 invariants (`InvalidPlanIR` for structural failures, warnings for coverage).
- `planir.canonical`: per-platform argument canonicalisation to one vocabulary per `tool_kind`; URL queries percent-decoded for analysis only.
- `prepare`: trust classification, entity extraction with roles and opaque IDs (pending call, siblings, request, grants, inputs, history, agent-written files), the untrusted-entity set with "echo does not promote", action fingerprint `afp1`, Jev state views byte-identical to the runner's `trim-v1`.
- `state.token`: HS256 state token bound to `session_ref` and step; test-mode seeding from `state_seed`.

### WP3: AIRA probe (2026-10-16)
- `probes.aira.AiraProbe`: the deterministic consequence probe. One envelope per request with contributions on `consequence.sensitivity|reach|irreversibility|self_modification` and `suspicion.concealment`, the `guardrail_tampering` (min_risk 1.0, block) and `untrusted_code_execution` (min_risk 0.9, block; obfuscated decode-to-shell only) floors, the `holds_sensitive` flag, and evidence (classes, internal rule ids, exec shape summary, packs, per-finding detail). Siblings are scanned with the same detectors and count the same. Never raises.
- `aira.detectors`: C1 credential material reached, C2 exfiltration (source × sink) and plain sends, C3 untrusted code (fetch-to-shell, decode-to-shell, install-from-URL, package install, running a file written since a fetch), C4 self-modification and persistence, C4* guardrail tampering (OpenClaw and Hermes; content-aware for `openclaw.json` / Hermes `config.yaml` edits), C7 destruction outside scratch and C8 privilege change (pack `host_gated`; the preload/setuid/shadowing arms always on; C7 records evidence only when the host already granted approval), C9 irreversible remote side effects, C10 secret written into an artefact, extent (recursive / wildcard / bulk recipients raise reach), concealment for output suppression on network calls. Encoding alone contributes nothing.
- `aira.lists`: rules as code, knowledge as data. Versioned YAML under `aira/lists/` (`sensitive_paths`, `guardrail`, `destructive`, `remote_destructive`, `privilege`, `egress`, `installers`, `selfmod`, `extent`, `weights`), compiled at load, with an additive operator overlay from `SENTROOK_LISTS_DIR`; the combined version string is reported as `versions["ruleset"]`.
- Ported from 1.x (`engine/2.0-policy-switch`): `aira.exec_shape` (tree-sitter-bash segments, wrappers, privilege, env assignments, sinks, now also redirect targets and pipelines), `aira.path_classes` (location and group classification, URL hosts), `aira.normalize` (base64 / hex / quote-concat deobfuscation for matching), `aira.sensitive_paths` (the path-group compiler; the list gains browser-profile and PII-store groups and the agent-context groups for C4).
- Tests: `test_aira_exec_shape` (ported assertions plus authored shape cases), `test_aira_lists` (loader, overlay, compilation, normaliser), `test_aira_detectors` (one positive and one benign twin per class on synthetic PlanIRs with invented hosts, plus the two worked examples: the attack and its sanctioned twin carry the same consequence).

### WP2: Jev probes (2026-10-16)
- `jev.client`: Decisions API client behind one configurable base URL, `zdr` provider preferences, retry with backoff, context-limit and timeout surfaced as coverage events; `X-TestNest-Repeat` forwarded for the runner's proxy.
- `jev.questions`: `exposure-v1` and `call-v1`, the two halves of the frozen `designed-v1-split`, word for word. Verified: every request body for all 691 suite cases hashes to the runner's cache key.
- `jev.chunking`: head-and-tail chunking of oversize exposure inputs, highest chunk score taken.
- `probes.jev`: exposure probe (sets `tainted`, skipped without new untrusted inputs) and call probe (misalignment, concealment, consequence signals, mean model certainty; `untrusted_origin` and the action category in evidence only).

### WP4: entity oracle and context probes (2026-10-16)
- `oracle.client`: the `OracleClient` contract Rookery will implement (`lookup` with roles → verdicts + library snapshot); `SeedOracle` (test mode), `NullOracle` (live, everything unknown, coverage lowered), `HttpOracle` stub.
- `probes.oracle`: distrust by verdict and role, `known_bad_entity` floor, coverage for unknown risky entities; loopback hosts and paths are not looked up.
- `probes.context`: `untrusted_origin` per entity (request/grant 0, visible creation 0.1, agent-generated 0.4, untrusted content 1.0, taint and lineage propagate), `request_origin` from the trigger (OpenClaw and Hermes bases), `retry_after_denial` from fingerprints recomputed over denied history steps, sticky exposure, session sensitivity, escalation flag, coverage from stale requests and fresh sessions.

### WP6: serve and CLI (2026-10-16)
- `serve`: stdlib threaded HTTP daemon with `GET /healthz`, `GET /metrics`, `POST /scan` (200 for ok and degraded, 422 with the Response error shape for an unscoreable body) and the config-gated `POST /testnest/scan` (`{fixture, state_seed, oracle_seed, options}` → `{response, probes, prepared}`; `options.repeat` forwarded to the runner's proxy; `options.probes` for ablation).
- Auth (API key and FIDU OIDC), per-caller token-bucket rate limiting and Prometheus metrics carried from 1.x; `ServeConfig.from_env` with production guards (state key required, test mode refused, content logging off).
- CLI: `sentrook scan FILE [--envelopes] [--probes]` for a PlanIR or a TestNest case file; `sentrook serve`.
