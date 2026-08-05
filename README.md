# Sentrook

FIDU runtime scanner for agent execution trajectories (PlanIR / Ariadne thread).

**Version:** Sentrook `0.2.13` (prototype). The OpenClaw plugin uses its own SemVer (`@firstdataunion/sentrook-shadow`).

Production YAIRA rules and corpus live in the private **Rookery** registry. This repo ships the engine, TestNest harness, plugins, and a tiny `examples/` demo library for format docs and smoke tests only.

## Quick start

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
uv pip install -e ./testnest
sentrook scan --plan fixtures/plans/safe_read_only.json --rules examples/rules
make test
make smoke
```

## Layout

| Path | Purpose |
|------|---------|
| `sentrook/` | Scanner package, unit tests, hosted-scan deploy recipes |
| `testnest/` | Scenario harness (engine-smoke suites only in this repo) |
| `examples/rules`, `examples/corpus` | Synthetic DEMO-* format examples — not the regression net |
| `fixtures/plans` | Minimal PlanIR smoke inputs |
| `integrations/openclaw/` | OpenClaw plugin for hosted Sentrook scan |

## Library sync (Rookery)

```bash
sentrook library sync --url https://rookery.firstdataunion.org   # when deployed
sentrook library status --url http://127.0.0.1:8080              # local Rookery
```

## Phase 1 readiness (not in this repo yet)

- GitHub Actions: lint, unit, plugin, sanitize-parity, smoke TestNest
- Private full TestNest eval (Rookery) before release/deploy
- ruff, Dependabot, image scan, Changesets for the plugin
- Flip repo public only after a secret/library scrub pass (history is already clean)

## Related

- Private library + eval: [FirstDataUnion/Rookery](https://github.com/FirstDataUnion/Rookery)
- Prior monorepo archive: `FirstDataUnion/Medivh` (left in place)
