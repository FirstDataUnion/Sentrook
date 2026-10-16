# Sentrook (2.0 rebuild)

Public repo. On 2026-10-01 `main` was reset to a clean slate for the Sentrook 2.0 pipeline
(Jev probes, AIRA, entity oracle, context, convergence; design in Notion, "Sentrook 2.0").

## Where things are
- `main` (this branch): the 2.0 scanner, being built in work packages (WP0 skeleton landed 2026-10-16).
  Design and the live plan: Notion, "Sentrook 2.0 build plan" (sections 5 to 8; decision log D1 to D7).
  - `sentrook/sentrook/`: the package. `planir/` (PlanIR 2.0 models), `response/` (Response 2.0),
    `probes/` (envelope and `Probe` protocol), `enums.py`, `contracts.py` (JSON Schema export),
    `cli/`. `prepare/`, `state/`, `jev/`, `aira/`, `oracle/`, `converge/`, `serve/` are placeholders
    for WP1 to WP6.
  - `schema/`: generated contracts; `make schema` regenerates, `make schema-check` and a test fail on drift.
  - `sentrook/tests/`: pytest, no network. Fixtures are synthetic plus the two worked examples from the
    design page. **The TestNest suite is private and never enters this repo.**
  - `CHANGELOG.md`: one entry per work package.
  - `testnest/` is the 1.x scenario harness, **reference only, does not run**; excluded from lint.
    The 2.0 runner lives in Rookery (`testnest/`) and drives this scanner over HTTP.
- `release/1.x`: the 1.x line as deployed (engine 1.0.3, OpenClaw plugin 1.0.5, Hermes beta). Hotfixes only.
- `archive/pre-2.0-main`: old `main` tip. Contains the **plugin dashboard work** (commit `63e0170`,
  `integrations/openclaw/plugin/dashboard*.ts`, `control-ui.*`) and the unreleased rearchitecture phases.
- `engine/2.0-policy-switch`: unmerged engine commits that Rookery's pin (`4ff6fb9`) still points at. Do not delete.

## Rules for agents
- Do not read or copy from `release/1.x` or `archive/pre-2.0-main` unless the task says to. They are
  reference, not the design. Use `git show <branch>:<path>`. The pieces the build plan names for reuse
  (scan auth and OIDC, metrics, rate limit, exec shape, path classes, normaliser, sensitive-path list)
  are on `engine/2.0-policy-switch`.
- Public repo. No suite cases, no real hosts, no results from private runs. Test fixtures use invented
  hosts that do not resolve and the agent name `clawbot`. Secrets only from env. Design notes that name
  incidents or unpublished weaknesses stay in Rookery or Notion; `docs/` here describes the mechanism.
- Models are the source of the wire contracts: change a model, run `make schema`, commit both.
- Every work package ends with tests green, a `CHANGELOG.md` entry and its row updated on the build plan.
- Plugins are being rewritten by hand; old plugin code is a reference that may be copied closely.
- Fixtures and the private library live in the **Rookery** repo for now (`fixtures/`).
- Do not trim `.gitleaks.toml` allowlists or `.github/secret_scanning.yml`: gitleaks scans every ref,
  so old fixtures stay visible until those branches are gone.
- `release-plugin.yml` and `release-hermes-plugin.yml` must stay on `main` (a dispatchable workflow has
  to exist on the default branch). They fail on `main` until the new plugins exist; that is expected.
