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
- Do not commit secrets, `.env` files, npm tokens, or a local Rookery mirror
  (`rules/`, `corpus/`, `eval/` are gitignored for a reason).

## Pull requests

1. Fork (or branch) from `main`.
2. Make the change; keep public CI paths green: unit tests, smoke TestNest,
   plugin tests when you touch the plugin.
3. Open a PR with:
   - **What** changed and **why**
   - How you tested (`make test`, `make smoke`, …)
   - Any follow-ups or known gaps

Use the PR template when prompted. Link related issues.

## Reporting bugs and security

- Bugs / features: [GitHub Issues](https://github.com/FirstDataUnion/Sentrook/issues)
  (use the templates).
- Security vulnerabilities: see [`SECURITY.md`](SECURITY.md) — private report
  only.

## Questions

Open a Discussion or Issue on the repo. 
