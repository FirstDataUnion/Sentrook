# TestNest

Scenario test harness for [Sentrook](../README.md). Runs tagged PlanIR scenarios against the Sentrook scanner and asserts on `ScanResult` output.

TestNest is not installed with Sentrook by default. Install separately for development and CI:

```bash
uv pip install -e .
uv pip install -e ./testnest
```

```bash
testnest run --suite core --profile v0
testnest run --suite negative --profile v0
testnest run --suite edge --profile v0
testnest run --suite ambiguous --profile l3_primary   # exercises Layer 3
testnest list
```

Scenarios live in `testnest/fixtures/scenarios/`. Shared PlanIR fixtures and YAIRA rules remain at the repo root (`fixtures/plans/`, `rules/`).

## Profiles

`fixtures/scenarios/profiles.yaml` maps a profile name to the `ScannerConfig` the runner
scans with, and each scenario declares its expectations per profile:

- `v0` — default full stack (L1+L2+L3 tie-breaker).
- `l3_primary` — same scanner as `v0`; scenarios add L3-specific assertions such as
  `l3_required: true`.

The runner loads the corpus (repo `corpus/` by default, override with `--corpus`) and
builds the bi-encoder. Pass `--l3-policy off` on `sentrook scan` or define a profile with
`l3_policy: "off"` to run L2-only. A scenario can assert `l3_required: true` to require that L3 actually ran (`L3` in `layer_exits`).
Every report header (and JSON report) echoes the resolved scanner config and corpus path.
