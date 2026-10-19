# Sentrook

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@firstdataunion/sentrook-openclaw.svg)](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)

Sentrook is a runtime security scanner for open-source AI agents, developed by
[FIDU](https://firstdataunion.org). It reviews an agent's pending tool calls, in the context of the
trajectory that led to them, and flags or blocks the dangerous ones.

**Sentrook 2.0 is being rebuilt.** This branch is a clean start for the new scan pipeline. The
currently published offering (engine 1.x and the `@firstdataunion/sentrook-openclaw` plugin) is in
maintenance mode and lives on the [`release/1.x`](../../tree/release/1.x) branch.

Nothing here is installable yet. See [CLAUDE.md](CLAUDE.md) for the repo layout and conventions.

## Configuration

The scanner is configured through `SENTROOK_*` environment variables. The Jev probes and convergence read:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTROOK_JEV_BASE_URL` | `https://openrouter.ai` | Decisions API base URL (a caching proxy can sit here) |
| `SENTROOK_JEV_API_KEY` | unset | API key for the Decisions API |
| `SENTROOK_JEV_MODEL` | `typesafe/jev-1.13` | Jev model |
| `SENTROOK_JEV_TIMEOUT_MS` | `20000` | Per-request timeout |
| `SENTROOK_JEV_EXPOSURE_QUESTIONS` | `exposure-v2` | Exposure question set on the redacted view (`exposure-v1`, the frozen set, stays selectable) |
| `SENTROOK_JEV_CALL_QUESTIONS` | `call-v2` | Call question set, which also sees the turn's inputs (`call-v1`, the frozen set, stays selectable) |
| `SENTROOK_CONVERGENCE` | `conv-v3` | Convergence parameter set (`conv-v1` and `conv-v2` stay selectable) |

## License

MIT. See [LICENSE](LICENSE).
