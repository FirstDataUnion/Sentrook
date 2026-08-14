# Security Policy

## Supported versions

Security fixes are applied on the current `main` branch of this repository.
Released artifacts (scanner image tags, `@firstdataunion/sentrook-openclaw` npm
versions) receive fixes on a best-effort basis for the latest published line.

Production YAIRA rules and corpus are **not** published in this repo. Report
library-content directly to an owner or via hello@firstdataunion.org, not via
public GitHub issues.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities in
Sentrook (engine, TestNest harness, OpenClaw plugin, or deploy recipes).

Prefer a private GitHub security advisory:

https://github.com/FirstDataUnion/Sentrook/security/advisories/new

If you cannot use GitHub, email **hello@firstdataunion.org**. Include a clear
description, impact, and steps to reproduce, plus affected component versions
or git SHAs when known.

You should receive an acknowledgement within a few business days. Please give
us reasonable time to investigate and ship a fix before any public disclosure.

## Scope

In scope (examples):

- Auth bypass or privilege issues on `sentrook serve` (`/scan`, `/feedback`, …)
- Secrets leakage in logs, sanitize failures, or packaged artifacts
- Remote code execution or unintended filesystem access via PlanIR / rule
  loading
- Supply-chain issues in published plugin or image build recipes in this repo

Out of scope (examples):

- Bypasses that require a custom or incomplete ruleset (detection efficacy of
  third-party YAIRA libraries)
- Issues that only apply with `SENTROOK_MODE=observe` or intentionally open
  local bind configs
- Vulnerabilities in dependency versions that are already fixed upstream when
  you can upgrade

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report findings privately before disclosure
- Do not exploit the issue beyond what is needed to demonstrate it
