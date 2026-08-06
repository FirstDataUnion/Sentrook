# Sentrook

FIDU runtime scanner for agent execution trajectories (**PlanIR 1.0** / Ariadne thread).

**License:** [MIT](LICENSE) · **Version:** Sentrook `1.0.0`. The OpenClaw plugin uses its own SemVer (`@firstdataunion/sentrook-openclaw@1.0.0`).

Production YAIRA rules and corpus are not publically available at this time. This repo ships the engine, TestNest harness, plugins, and a tiny `examples/` demo library for format docs and smoke tests only.

Offline and live traffic share one ingress: PlanIR `version: "1.0"` in, `ScanResult` `version: "1.0"` out. CLI: `sentrook scan` (PlanIR file) and `sentrook serve` (warm HTTP `/scan`). Mode: `observe` | `enforce`.

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
| `sentrook/` | Scanner package (`planir`, `serve`, layers), unit tests; `deploy/` scripts (FIDU ops runbook in Notion) |
| `testnest/` | Scenario harness (engine-smoke suites only in this repo) |
| `examples/rules`, `examples/corpus` | Synthetic DEMO-* format examples — not the regression net |
| `fixtures/plans` | Minimal PlanIR 1.0 smoke inputs |
| `integrations/openclaw/` | OpenClaw plugin — builds PlanIR 1.0 and POSTs `/scan` |
| `rules/`, `corpus/`, `eval/` | **Gitignored** local mirror of Rookery SoT (`make sync-library`) |

## Test paths

Policy-bound L1/L2/`scan_plan` pytest and full TestNest suites live in **Rookery**
(against production `rules/` / `corpus/` / `eval/`). This repo keeps library-free
unit tests + DEMO smoke so a clean checkout stays public-ready. Full strategy:
sibling [Rookery `TESTING.md`](../FIDU-Rookery/TESTING.md).

| Path | What | Command |
|------|------|---------|
| **A — committed** | Unit + TestNest harness unit + OpenClaw plugin | `make test` · `make plugin-test` |
| **A — smoke** | DEMO scenarios only (no production library) | `make smoke` |
| **B — TestNest (mirror)** | Full-policy TestNest against synced Rookery SoT | `make sync-library` then `make testnest-core` (or `testnest-all`) |
| **C — TestNest (sibling)** | Same suites without copying | `testnest run --suite core --profile v0 --scenarios ../FIDU-Rookery/eval/scenarios --rules ../FIDU-Rookery/rules --corpus ../FIDU-Rookery/corpus` |
| **D — engine pytest** | L1/L2/`scan_plan` + replay (Rookery `tests/engine`) | `make test-engine` (delegates to sibling Rookery; use editable Sentrook pin there while iterating) |
| **D — sanitize gate** | Plugin TS ↔ server Python scrub + decision parity | `make sanitize-gate` (delegates to Rookery parity/replay tests; subset of engine suite) |
| **E — CI RC gate** | Full eval against a Sentrook SHA | Runs in **Rookery** (Sentrook may `repository_dispatch` the SHA) |

## Library sync (hosted Rookery)

Runtime sync of a *published* library into `~/.sentrook` (separate from the gitignored eval mirror):

```bash
sentrook library sync --url https://rookery.firstdataunion.org   # when deployed
sentrook library status --url http://127.0.0.1:8080              # local Rookery
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.

## Phase 1 readiness (not in this repo yet)

- GitHub Actions: lint, unit, plugin, smoke TestNest
- Full TestNest eval gate hosted in Rookery (triggered by Sentrook commit dispatch)
- ruff, Dependabot, image scan, Changesets for the plugin
- Flip repo public only after a secret/library scrub pass (history is already clean)

## Related

- Private library + eval: [FirstDataUnion/Rookery](https://github.com/FirstDataUnion/Rookery) — see `TESTING.md`
- FIDU internal testing + deploy runbook: Notion **Sentrook + Rookery** (Documentation/RunBooks)

## License

[MIT](LICENSE) — Copyright (c) 2026 FirstDataUnion
