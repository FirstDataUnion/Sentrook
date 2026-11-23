# Host compatibility checks

Each host plugin runs on real releases of its host, not only against the stubbed host in its unit tests. The
check installs the plugin the way a user would and drives it through the host, against mock identity and scan
services with synthetic hosts and credentials, so it needs no secrets.

## What runs when

| When | Versions | Blocking |
| --- | --- | --- |
| Pull requests and pushes touching a plugin or this tooling (`host-compat.yml`) | the floor and latest pinned in `versions.txt` | yes |
| Same | the check's self-test, on the latest pinned version | yes |
| Same | the newest pre-release (Hermes release candidate, OpenClaw beta), when it is newer than latest | no (report-only) |
| Plugin release workflows (`host-compat.yml`, mode `release`, for their host) | the floor and latest, on the tree about to be published when the workflow passes it as `plugin-artifact` (Hermes) | yes |
| Nightly (`host-compat-nightly.yml`) | the host's `main` build and the newest pre-release | no: one issue per failing target, labelled `host-compat`, closed when it passes |
| Nightly bump (`host-compat-nightly.yml`) | a new stable release | opens a PR moving `latest` and the install guide's "Tested on" line; its checks decide whether it can merge |

A pull request runs the checks only for the hosts whose plugin it changes (every host when it changes this tooling);
pushes to `main` run every host. The canary skips a `main` build older than the latest stable release, with a
warning: it would only test an older host than the blocking check does. `host-compat result` is the one check to
require in branch protection; the per-version job names change with each bump.

**Version policy:** the plugin supports its declared floor and the latest stable release. The floor is the plugin's
declared minimum (`requires_hermes` for Hermes, `openclaw.compat.pluginApi` and `openclaw.build.openclawVersion` in
`package.json` for OpenClaw) and moves only with it; `make compat-test` fails if the two differ,
or if the install guide's "Tested on" line names other versions than `versions.txt`.

## Layout

- `compat.py`: the shared helpers (matrix, pre-release lookup on Docker Hub or GHCR, warnings baseline, bump,
  canary issue) and their tests in `tests/` (`make compat-test`).
- `mock_services.py`: one stand-in server for the identity service, the scanner and an OpenAI-compatible model,
  used by every host's check.
- `integrations/<host>/compat/`, one per host:
  - `versions.txt`: `floor` and `latest`;
  - `warnings-baseline.txt`: what the host's own checks report about the plugin today; any other report fails;
  - `run.sh <image>`: the check against one host image (needs Docker);
  - `selftest.sh <image>`: breaks the plugin in known ways and expects the check to fail at the right step;
  - whatever runs inside the host image.

To add a host, add it to `HOSTS` in `compat.py` and to `HOSTS` in both workflows, and give it the directory above.

## Hermes

`integrations/hermes/compat/run.sh nousresearch/hermes-agent:<tag>` (or `make hermes-compat` for the pinned
versions). Inside the image, as the `hermes` user, it runs:

1. `hermes plugins validate --install-deps --json` on the plugin as published (no tests): every check must pass,
   and every warning must be in the baseline;
2. `hermes plugins install file://… --enable` from a git repository of the plugin;
3. `hermes config set` for the scan client ID and secret;
4. `hermes sentrook verify` and `hermes sentrook status` against `mock_services.py`;
5. one agent turn, `hermes chat`, with the model served by the same mock: it asks for two terminal calls, and
   the plugin's `pre_tool_call` must block the first and allow the second;
6. `gate_build.py`: the digest of Hermes's background-review memory gate must be on the plugin's list of verified
   builds (`VERIFIED_GATES` in `integrations/hermes/plugin/staging.py`). Only on those builds does the plugin leave
   a background review's memory patch or remove to Hermes's own staging; elsewhere it holds them. A bump to a Hermes
   that changes the gate fails here until someone checks the new gate still stages every such change and adds its
   digest.
7. `platforms.py`: every session platform value Hermes uses (its gateway `Platform` enum, its bundled platform
   plugins, and the surfaces it names as not messaging or as unattended for approvals) must be in the plugin's
   `ATTENDED_PLATFORMS`, `NOT_ATTENDED_PLATFORMS` or `LOCAL_PLATFORMS` (`integrations/hermes/plugin/intent.py`). A
   bump to a Hermes that adds a platform fails here until someone decides whether a human answers approvals there.

Results land in the output directory (`steps.tsv`, `validate.json`, a log per step, and the mock's request log).

## OpenClaw

`integrations/openclaw/compat/run.sh ghcr.io/openclaw/openclaw:<tag>` (or `make openclaw-compat` for the pinned
versions; needs Node 22.6+ and `npm ci` at the repository root). It packs the plugin with `npm run pack:check` and
`npm pack`, then inside the image, as the `node` user, follows the install guide:

1. `openclaw plugins validate --json` on the package: its errors are compared with the baseline;
2. the scan credentials in `~/.openclaw/.env`, SecretRefs to them and conversation access, with `openclaw config set`;
3. `openclaw plugins install <archive> --force --accept-capabilities` and `openclaw plugins enable sentrook`;
4. `openclaw plugins inspect sentrook --runtime`: loaded, with hooks and the `/sentrook` command;
5. `openclaw plugins doctor --json`: the diagnostics for `sentrook` (an unknown or blocked hook name shows only
   here) are compared with the baseline;
6. `openclaw sentrook verify` and `openclaw sentrook status` against `mock_services.py`;
7. one agent turn, `openclaw agent --local`, with the model served by the same mock: it asks for two `exec` calls,
   and the plugin's `before_tool_call` must block the first and allow the second;
8. the seam probe (`probe/`, a test-only plugin installed next to Sentrook) checks the host fields the plugin reads
   without a documented contract: `api.runtime.version`, `api.runtime.config.current()`, the hook and command
   registration functions, a tool-result middleware registered as Sentrook registers it (accepted, and run on the
   allowed call), the `before_tool_call` fields, and the `__openclaw.senderIsOwner` marker on the owner's messages
   (a second turn gives `before_prompt_build` a history to carry it).

Pre-releases are OpenClaw's betas (`YYYY.M.D-beta.N`); the canary's `main` is the `main` image on GHCR, whose build
time stands in for a push time. OpenClaw ships two release lines at once; the blocking check follows the newest
(the older extended-stable line sorts below it).

