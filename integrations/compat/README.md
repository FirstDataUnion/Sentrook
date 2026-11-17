# Host compatibility checks

Each host plugin runs on real releases of its host, not only against the stubbed host in its unit tests. The
check installs the plugin the way a user would and drives it through the host, against mock identity and scan
services with synthetic hosts and credentials, so it needs no secrets.

## What runs when

| When | Versions | Blocking |
| --- | --- | --- |
| Pull requests and pushes touching a plugin or this tooling (`host-compat.yml`) | the floor and latest pinned in `versions.txt` | yes |
| Same | the check's self-test, on the latest pinned version | yes |
| Same | the newest release candidate, when it is newer than latest | no (report-only) |
| Plugin release workflows (`host-compat.yml`, mode `release`) | the floor and latest | yes |
| Nightly (`host-compat-nightly.yml`) | the host's `main` build and the newest release candidate | no: one issue per failing target, labelled `host-compat`, closed when it passes |
| Nightly bump (`host-compat-nightly.yml`) | a new stable release | opens a PR moving `latest` and the install guide's "Tested on" line; its checks decide whether it can merge |

The canary skips a `main` build older than the latest stable release, with a warning: it would only test an
older Hermes than the blocking check does. `host-compat result` is the one check to require in branch protection;
the per-version job names change with each bump.

**Version policy:** the plugin supports its declared floor and the latest stable release. The floor is the plugin's
declared minimum (`requires_hermes` for Hermes) and moves only with it; `make compat-test` fails if the two differ,
or if the install guide's "Tested on" line names other versions than `versions.txt`.

## Layout

- `compat.py`: the shared helpers (matrix, release-candidate lookup, warnings baseline, bump, canary issue) and
  their tests in `tests/` (`make compat-test`).
- `integrations/<host>/compat/`, one per host:
  - `versions.txt`: `floor` and `latest`;
  - `warnings-baseline.txt`: the host validator's warnings the plugin is known to raise; any other fails;
  - `run.sh <image>`: the check against one host image (needs Docker);
  - `selftest.sh <image>`: breaks the plugin in known ways and expects the check to fail at the right step;
  - the mock services and whatever runs inside the host image.

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
   the plugin's `pre_tool_call` must block the first and allow the second.

Results land in the output directory (`steps.tsv`, `validate.json`, a log per step, and the mock's request log).
