# Sentrook

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@firstdataunion/sentrook-openclaw.svg)](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)

Sentrook is a runtime security scanner for open-source AI agents, developed by
[FIDU](https://firstdataunion.org). It reviews an agent's pending tool calls, in the context of the
trajectory that led to them, and flags or blocks the dangerous ones.

**Sentrook 2.0 is being rebuilt.** This branch is a clean start for the new scan pipeline. The
currently published offering (engine 1.x and the `@firstdataunion/sentrook-openclaw` plugin) is in
maintenance mode and lives on the [`release/1.x`](../../tree/release/1.x) branch.

The 2.0 scanner is being built in work packages; see [CHANGELOG.md](CHANGELOG.md) for what has
landed. The wire contracts (PlanIR 2.0, Response 2.0, the probe envelope) are published as JSON Schema
under [`schema/`](schema/). Nothing is deployable yet. See [CLAUDE.md](CLAUDE.md) for the repo layout
and conventions.

```bash
make install   # uv sync with dev extras
make test      # unit tests
make lint      # ruff check + format check
```

## License

MIT. See [LICENSE](LICENSE).
