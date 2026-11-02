# Sentrook

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@firstdataunion/sentrook-openclaw.svg)](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)

Sentrook is a runtime security scanner for open-source AI agents, developed by
[FIDU](https://firstdataunion.org). It reviews an agent's pending tool calls, in the context of the
trajectory that led to them, and flags or blocks the dangerous ones.

Sentrook runs as a plugin inside the agent host. The plugin builds a description of each pending call (what the
owner asked for, the call and its arguments, recent inputs and history), redacts secrets on the host, and sends it
to the hosted scan service. The service scores the risk and the plugin allows the call, asks the owner, or blocks it.

**Status: 2.0 beta.** The install guides set Sentrook up in enforce mode. Observe mode, where every call is scored
and logged but nothing is blocked or asked, is one setting away. The 1.x line (engine 1.x and plugin 1.0.x) is in maintenance on the
[`release/1.x`](../../tree/release/1.x) branch.

## Install

| Host | Guide |
| --- | --- |
| [OpenClaw](https://github.com/openclaw/openclaw) | [integrations/openclaw/README.md](integrations/openclaw/README.md) |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | [integrations/hermes/README.md](integrations/hermes/README.md) |

Each guide covers credentials, install, a first scan, channel bindings and grants, the plugin's commands, enforce and
observe mode, what is sent to the scan service, and uninstalling.

## Repository layout

| Path | What it is |
| --- | --- |
| `sentrook/` | The scan service (Python): request validation and preparation, the Jev probes, AIRA, the entity oracle, convergence and the HTTP service |
| `integrations/openclaw/plugin/` | The OpenClaw plugin (TypeScript) |
| `integrations/hermes/plugin/` | The Hermes plugin (Python, standard library only) |
| `integrations/fixtures/` | Shared fixtures both plugins are tested against |
| `schema/` | JSON Schemas for the scan request and response, generated from the models |
| `testnest/` | The 1.x scenario harness, kept as reference; it does not run on `main` |

Development uses [uv](https://docs.astral.sh/uv/) and `make`: `make install`, then `make lint` and `make test`
for the service, `make plugin-test` and `make hermes-plugin-test` for the plugins.

## Scan service configuration

For running the scan service yourself; plugin users don't need this. The scanner is configured through
`SENTROOK_*` environment variables. The Jev probes and convergence read:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTROOK_JEV_BASE_URL` | `https://openrouter.ai` | Decisions API base URL (a caching proxy can sit here) |
| `SENTROOK_JEV_API_KEY` | unset | API key for the Decisions API |
| `SENTROOK_JEV_MODEL` | `typesafe/jev-1.13` | Jev model |
| `SENTROOK_JEV_TIMEOUT_MS` | `20000` | Per-request timeout |
| `SENTROOK_JEV_EXPOSURE_QUESTIONS` | `exposure-v2` | Exposure question set on the redacted view (`exposure-v1`, the frozen set, stays selectable) |
| `SENTROOK_JEV_CALL_QUESTIONS` | `call-v4` | Call question set: the turn's inputs plus the entity library's verdicts, and a note that hosts may wrap the request in their own text (`call-v3` without the note, `call-v2` without the verdicts and `call-v1`, the frozen set, stay selectable) |
| `SENTROOK_CONVERGENCE` | `conv-v3` | Convergence parameter set (`conv-v1` and `conv-v2` stay selectable) |

## License

MIT. See [LICENSE](LICENSE).
