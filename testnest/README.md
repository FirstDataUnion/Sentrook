# TestNest

Scenario test harness for [Sentrook](../README.md). Runs tagged PlanIR scenarios against the Sentrook scanner and asserts on `ScanResult` output.

TestNest is not installed with Sentrook by default. Install separately for development and CI:

```bash
uv pip install -e .
uv pip install -e ./testnest
```

## Smoke (committed in this repo)

This checkout ships only the **smoke** suite plus DEMO rules/corpus:

```bash
make smoke
# or:
testnest run --suite smoke --profile v0 \
  --rules examples/rules --corpus examples/corpus
testnest list --scenarios testnest/fixtures/scenarios
```

Scenarios: `testnest/fixtures/scenarios/`. Smoke PlanIR inputs: `fixtures/plans/` (and duplicates under `testnest/fixtures/plans/`).

## Full policy suites (Rookery SoT)

Production YAIRA rules, corpus, and suites (`core`, `negative`, `edge`, `ambiguous`, `asi`, `ast`, …) live in **Rookery**. From Sentrook:

```bash
# B — sync a gitignored mirror, then run
make sync-library
make testnest-core    # or: make testnest-all

# C — point at a sibling Rookery without copying
testnest run --suite core --profile v0 \
  --scenarios ../FIDU-Rookery/eval/scenarios \
  --rules ../FIDU-Rookery/rules \
  --corpus ../FIDU-Rookery/corpus
```

Pinning, release gates, and CI shape: sibling **[Rookery TESTING.md](../../FIDU-Rookery/TESTING.md)** ([FirstDataUnion/Rookery](https://github.com/FirstDataUnion/Rookery)).

## Profiles

`profiles.yaml` (in the scenarios dir you pass) maps a profile name to the `ScannerConfig` the runner uses; each scenario declares expectations per profile:

- `v0` — default full stack (L1+L2+L3 tie-breaker), or L2-only when the profile sets `l3_policy: "off"` (smoke does).
- `l3_primary` — same scanner as `v0` with L3-focused assertions such as `l3_required: true` (Rookery suites).

The runner loads the corpus (override with `--corpus`) and builds the bi-encoder when L3 is on. A scenario can assert `l3_required: true` to require that L3 actually ran (`L3` in `layer_exits`). Every report header (and JSON report) echoes the resolved scanner config and corpus path.
