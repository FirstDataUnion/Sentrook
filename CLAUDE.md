# Sentrook (2.0 rebuild)

Public repo. On 2026-10-01 `main` was reset to start the Sentrook 2.0 rebuild. The new scan
pipeline (Jev probes, AIRA, entity oracle, context, convergence) and initial plugins are now
implemented here; the design reference is in Notion, "Sentrook 2.0".

Current goal: see the callout at the top of the Sentrook 2.0 Notion page.

## Where things are
- `main` (this branch): active 2.0 implementation. Scanner code is in `sentrook/`; initial/beta
  OpenClaw and Hermes plugins are in `integrations/openclaw/plugin/` and
  `integrations/hermes/plugin/`. The repository also includes the scanner container image and CI.
  `testnest/` is the 1.x harness (**reference, does not run**).
- `release/1.x`: the 1.x line as deployed (engine 1.0.3, OpenClaw plugin 1.0.5, Hermes beta). Hotfixes only.
- `archive/pre-2.0-main`: old `main` tip. Contains the **plugin dashboard work** (commit `63e0170`,
  `integrations/openclaw/plugin/dashboard*.ts`, `control-ui.*`) and the unreleased rearchitecture phases.
- `engine/2.0-policy-switch`: unmerged engine commits that Rookery's pin (`4ff6fb9`) still points at. Do not delete.

## Rules for agents
- Do not read or copy from `release/1.x` or `archive/pre-2.0-main` unless the task says to. They are
  reference, not the design. Use `git show <branch>:<path>`.
- Prefer the current 2.0 plugin implementations under `integrations/`; the archived dashboard and
  pre-2.0 plugin code are reference only.
- Fixtures and the private library live in the **Rookery** repo for now (`fixtures/`).
- Do not trim `.gitleaks.toml` allowlists or `.github/secret_scanning.yml`: gitleaks scans every ref,
  so old fixtures stay visible until those branches are gone.
- `release-plugin.yml` and `release-hermes-plugin.yml` must stay on `main` (a dispatchable workflow has
  to exist on the default branch). Both workflows now package/test the 2.0 plugins and support
  dispatching releases from the default branch.

## Backlog
Bugs, gaps, debt, feature ideas and design questions are tracked in the Notion database "Sentrook Features" (find
it with the Notion search tool; its "How to use this page" callout is the convention, read it before filing).
- **Suggest, then file.** When you find something worth tracking that is outside your task, name it to the user
  with a proposed title, Kind and one line of evidence, and file it when they agree. File without asking only when
  the user asked for the write-up. Do not fix it silently in an unrelated change or leave it only in chat.
- **One ticket, one change.** Search first and extend a matching ticket instead of duplicating it. Each ticket
  stands alone for an agent that never saw your conversation: Problem, Where, Fix (or Options), Tests, Reproduce,
  Related. Status Idea; never set Priority.
- **Public repo:** internal reasoning, case ids and design references live in the ticket. Code, tests, commit
  messages and PR text state the rule in plain words and never cite the ticket or internal documents.

## Working a ticket
- Pick a Ready ticket with no Owner, highest priority first. Don't start Idea or Needs design tickets.
  If it lists open points or needs a design call, stop and ask Oli.
- Claim before coding: Status In progress, Owner Oli (agents have no Notion identity), branch name in PRs.
- One ticket, one change. Write the ticket's "must fire / must stay silent" tests first.
- Before opening the PR: run `make lint` and `make test` (plus `make schema-check` / `make plugin-test`
  where touched). Put the commands and results in the PR description and the ticket's Evidence.
- Have a fresh reviewer check the diff against the ticket's Problem, Fix and Tests only; skip style.
- Open the PR against `main`, add it to PRs, Status In review.
- After merge: Status Done, merged PR in PRs, Evidence says what changed. Agents may set Done once
  the merge is verified (`gh pr view <n> --json state`).
- PR closed unmerged: Status back to Ready, clear Owner, add a note. No movement for 7 days: say so in the ticket.
- Found other work? Suggest a ticket (title, Kind, one line of evidence); file it only if Oli agrees.
- PR text and commit messages never cite the ticket or internal documents.

