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

### WP2: Jev probes (2026-10-16)
- `jev.client`: Decisions API client behind one configurable base URL, `zdr` provider preferences, retry with backoff, context-limit and timeout surfaced as coverage events; `X-TestNest-Repeat` forwarded for the runner's proxy.
- `jev.questions`: `exposure-v1` and `call-v1`, the two halves of the frozen `designed-v1-split`, word for word. Verified: every request body for all 691 suite cases hashes to the runner's cache key.
- `jev.chunking`: head-and-tail chunking of oversize exposure inputs, highest chunk score taken.
- `probes.jev`: exposure probe (sets `tainted`, skipped without new untrusted inputs) and call probe (misalignment, concealment, consequence signals, mean model certainty; `untrusted_origin` and the action category in evidence only).

### WP4: entity oracle and context probes (2026-10-16)
- `oracle.client`: the `OracleClient` contract Rookery will implement (`lookup` with roles → verdicts + library snapshot); `SeedOracle` (test mode), `NullOracle` (live, everything unknown, coverage lowered), `HttpOracle` stub.
- `probes.oracle`: distrust by verdict and role, `known_bad_entity` floor, coverage for unknown risky entities; loopback hosts and paths are not looked up.
- `probes.context`: `untrusted_origin` per entity (request/grant 0, visible creation 0.1, agent-generated 0.4, untrusted content 1.0, taint and lineage propagate), `request_origin` from the trigger (OpenClaw and Hermes bases), `retry_after_denial` from fingerprints recomputed over denied history steps, sticky exposure, session sensitivity, escalation flag, coverage from stale requests and fresh sessions.
