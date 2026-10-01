# Sentrook (2.0 rebuild)

Public repo. On 2026-10-01 `main` was reset to a clean slate for the Sentrook 2.0 pipeline
(Jev probes, AIRA, entity oracle, context, convergence; design in Notion, "Sentrook 2.0").

## Where things are
- `main` (this branch): clean start. Only `testnest/` (1.x harness, **reference, does not run**),
  release/security tooling in `.github/`, and `.changeset/` remain.
- `release/1.x`: the 1.x line as deployed (engine 1.0.3, OpenClaw plugin 1.0.5, Hermes beta). Hotfixes only.
- `archive/pre-2.0-main`: old `main` tip. Contains the **plugin dashboard work** (commit `63e0170`,
  `integrations/openclaw/plugin/dashboard*.ts`, `control-ui.*`) and the unreleased rearchitecture phases.
- `engine/2.0-policy-switch`: unmerged engine commits that Rookery's pin (`4ff6fb9`) still points at. Do not delete.

## Rules for agents
- Do not read or copy from `release/1.x` or `archive/pre-2.0-main` unless the task says to. They are
  reference, not the design. Use `git show <branch>:<path>`.
- Plugins are being rewritten by hand; old plugin code is a reference that may be copied closely.
- Fixtures and the private library live in the **Rookery** repo for now (`fixtures/`).
- Do not trim `.gitleaks.toml` allowlists or `.github/secret_scanning.yml`: gitleaks scans every ref,
  so old fixtures stay visible until those branches are gone.
- `release-plugin.yml` and `release-hermes-plugin.yml` must stay on `main` (a dispatchable workflow has
  to exist on the default branch). They fail on `main` until the new plugins exist; that is expected.
