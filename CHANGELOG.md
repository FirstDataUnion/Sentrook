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
