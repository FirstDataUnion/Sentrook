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

The scanner is configured through `SENTROOK_*` environment variables. The Jev probes read:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTROOK_JEV_BASE_URL` | `https://openrouter.ai` | Decisions API base URL (a caching proxy can sit here) |
| `SENTROOK_JEV_API_KEY` | unset | API key for the Decisions API |
| `SENTROOK_JEV_MODEL` | `typesafe/jev-1.13` | Jev model |
| `SENTROOK_JEV_TIMEOUT_MS` | `20000` | Per-request timeout |
| `SENTROOK_JEV_EXPOSURE_QUESTIONS` | `exposure-v1` | Exposure question set (`exposure-v1`, or `exposure-v2` on the redacted view) |
| `SENTROOK_JEV_CALL_QUESTIONS` | `call-v1` | Call question set (`call-v1`, or `call-v2`, which also sees the turn's inputs) |

## License

MIT. See [LICENSE](LICENSE).
