# Changelog

Sentrook 2.0 scanner. Work packages are tracked on the Notion page "Sentrook 2.0 build plan".
The 1.x engine and plugins keep their own history on `release/1.x`.

## Unreleased (2.0.0a1)

### WP0: skeleton (2026-10-16)
- Project scaffold: `pyproject.toml`, `Makefile`, package layout under `sentrook/sentrook/`, CI (lint, tests, schema drift check).
- PlanIR 2.0, Response 2.0 and probe-envelope models (`planir`, `response`, `probes`), with tolerant enums and additive fields kept.
- JSON Schema contracts generated from the models into `schema/`; `sentrook schema export [--check]`.
- Unit tests on the two worked examples from the design page and synthetic cases; no suite fixtures.
