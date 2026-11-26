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

Each guide covers install, signing in, a first scan, channel bindings and grants, the plugin's commands, enforce and
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
| `SENTROOK_JEV_ROUTE` | `primary` | Which route answers the Jev calls: `primary` (the Decisions API only), `fallback_on_outage` (the secondary answers when the primary returns 5xx, times out or cannot be reached), `fallback_on_rejected` (the secondary answers when the primary refuses the call with a 4xx other than 429 and the context limit) or `secondary` (the secondary only). Every mode but `primary` needs the two settings below. The answering route is recorded as `route` in the Jev probes' versions, and `/metrics` counts every call as `sentrook_jev_calls_total{route,outcome}` |
| `SENTROOK_JEV_SECONDARY_BASE_URL` | unset | Base URL of an OpenAI-compatible API (`POST <url>/chat/completions`), such as a self-hosted vLLM or llama.cpp server |
| `SENTROOK_JEV_SECONDARY_MODEL` | unset | Model name sent to the secondary |
| `SENTROOK_JEV_SECONDARY_API_KEY` | unset | Bearer key for the secondary, if it needs one (or `SENTROOK_JEV_SECONDARY_API_KEY_FILE`) |
| `SENTROOK_JEV_SECONDARY_TIMEOUT_MS` | `20000` | Per-request timeout for the secondary |
| `SENTROOK_JEV_SECONDARY_STRUCTURED` | `1` | Send the answers' JSON schema as `response_format`. Replies are validated either way: one that is not the typed answer degrades the scan |
| `SENTROOK_JEV_EXPOSURE_QUESTIONS` | `exposure-v2` | Exposure question set on the redacted view (`exposure-v1`, the frozen set, stays selectable) |
| `SENTROOK_JEV_CALL_QUESTIONS` | `call-v11` | Call question set: the turn's inputs plus the entity library's verdicts and near misses, a note that hosts may wrap the request in their own text, a destination grant counting as a destination the owner named, and the batch the call was issued in, the command resolved through it and destinations the owner's configuration supplies, each question sent only the parts of the preamble it needs, the batch and reputation paragraphs only when the request has them, and a read of the owner's own data in a service the request names counted as asked for even when the agent supplied the id of what it reads, and, only when the request names a service the entity library lists for one of the call's hosts, a question on whether the request means that service or the ordinary word, and, when the call sends secret placeholders, a note that each stands for the hidden value in its place, so one the owner asked to send is covered by the request (`call-v10` without that note, `call-v9` without the service question, `call-v8` without the read rule, `call-v7` with the whole preamble on every question, `call-v6` without the batch, `call-v5` without the grant clause, `call-v4` without the near misses, `call-v3` without the note, `call-v2` without the verdicts and `call-v1`, the frozen set, stay selectable) |
| `SENTROOK_CONVERGENCE` | `conv-v9` | Convergence parameter set: `conv-v5` plus the credential-home relief, which also relieves the provider host of its distrust and untrusted origin, and the service-name relief: a host the entity library lists for a service the owner names, where the call judge reads the request as meaning that service, is relieved as a host the owner named (`conv-v1` to `conv-v8` stay selectable; `conv-v6` adds the attended-owner ceiling, `conv-v7` relieves the key's sensitivity only, `conv-v8` has no service-name relief) |

## License

MIT. See [LICENSE](LICENSE). The licence does not cover the Sentrook name or logo: see [TRADEMARKS.md](TRADEMARKS.md).
