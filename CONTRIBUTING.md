# Contributing to Sentrook

Thanks for interest in improving Sentrook. This repo is the **public-target
scanner engine**, TestNest harness, DEMO examples, and OpenClaw plugin. 

The actual attack rule definitions are not currently publically hosted. For 
interest in contributing to these, please get in touch with one of the team 
or via hello@firstdataunion.org. While we plan to develop a proper channel for 
contributing to these it is not yet ready, but we'd still love to hear your thoughts. 

## Ground rules

- By contributing, you agree your work is licensed under the MIT License (see
  [`LICENSE`](LICENSE)).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Prefer small, focused pull requests with a clear problem statement.
- Do not commit secrets, `.env` files, npm tokens, or a local production
  library mirror (`rules/`, `corpus/`, `eval/` are gitignored for a reason).

## Pull requests

1. Fork (or branch) from `main`.
2. Make the change; keep public paths green: `make lint`, unit tests, smoke
   TestNest, and plugin tests when you touch a host plugin (`npm ci` at the repo
   root, then `make plugin-test` and/or `make hermes-plugin-test`). Those targets
   include a publish-surface check (npm tarball / Hermes promote tree), not a
   live gateway. Use `make lint-fix` to autofix ruff findings. GitHub Actions
   runs these on every PR (`.github/workflows/ci.yml`).
3. If you change scanner decisions (L1/L2/`scan_plan`, PlanIR, serve), also run
   the full policy-bound engine regression if you have FIDU maintainer access
   (`make test-engine` from this repo). Do not copy production rules or engine
   policy tests into this tree. After merge to `main`, Sentrook may dispatch a
   private full-eval for the SHA (non-blocking on merge; required before release).
4. If you change OpenClaw plugin behaviour or its installable API, add a
   changeset (`make plugin-changeset`). Docs/test-only plugin PRs skip this.
   Merging a changeset does **not** publish to npm; a Version PR bumps
   SemVer, then `release-plugin` is the npm write.
5. Open a PR with:
    - **What** changed and **why**
    - How you tested (`make lint`, `make test`, `make smoke`, `make test-engine`, …)
    - Any follow-ups or known gaps

Use the PR template when prompted. Link related issues.

## Reporting bugs and security

- Bugs / features: [GitHub Issues](https://github.com/FirstDataUnion/Sentrook/issues)
  (use the templates).
- Security vulnerabilities: see [`SECURITY.md`](SECURITY.md) — private report
  only.

## Questions

Open a Discussion or Issue on the repo. 
