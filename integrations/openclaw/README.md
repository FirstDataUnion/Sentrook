# Sentrook OpenClaw integration (online)

Thin TypeScript plugin that scans every `before_tool_call` against **hosted**
Sentrook (`https://sentrook.firstdataunion.org`). No local sidecar.

**Branch note:** this tree is the online-only install path. Offline sidecar
scripts live on `main`.

## PlanIR 1.0 wire format

Every `before_tool_call` builds a **PlanIR 1.0** trajectory (`version: "1.0"`, sequential
`s1`…`sN` steps with one or more `pending` steps) and `POST`s it to `/scan`. Executed
steps include redacted args plus optional `result_summary`; the pending step is the tool
under review.

| Mode | Behaviour |
| --- | --- |
| `observe` (default) | Fire-and-forget scan; never blocks the agent |
| `enforce` | Awaits `/scan`; maps allow / review / block to OpenClaw vetoes or approval UI |

Sanitization scrubs PlanIR before egress (`sanitization.enabled: true` /
`SENTROOK_SANITIZE_PLANIR=1`).
Review feedback `POST /feedback` sends `{ plan, resolution, log, provenance }`.

## Install (public npmjs)

No `.npmrc` or GitHub token. The package is `@firstdataunion/sentrook-openclaw`
on public [npmjs](https://www.npmjs.com/) (first `1.0.0` lands with Sentrook
Actions `release-plugin`; until then use a git checkout / this tree).
Plugin SemVer is **independent** of the Sentrook scanner. Keep installs
**`--pin`ned** so a `latest` publish does not surprise a live gateway.

Hosted scan URLs (after configure):

| Environment | Typical `url` |
|-------------|----------------|
| Production | `https://sentrook.firstdataunion.org` |
| Staging / soak | `https://sentrook-dev.firstdataunion.org` (or your staging host) |

```bash
# 1. Install plugin (pinned to a released version)
openclaw plugins install npm:@firstdataunion/sentrook-openclaw@1.0.0 --pin --force

# 2. Configure (wizard in the package — OIDC + defaults)
openclaw sentrook configure

# 3. Restart gateway (reload ~/.openclaw/.env + plugin config)
# 4. Verify
openclaw sentrook verify
```

Via Docker Compose (typical VPS layout), run `openclaw` **without** `-T` so
prompts work:

```bash
cd ~/openclaw
docker compose exec openclaw-gateway \
  openclaw plugins install npm:@firstdataunion/sentrook-openclaw@1.0.0 --pin --force
docker compose exec openclaw-gateway openclaw sentrook configure

# Restart is enough: OpenClaw reloads ~/.openclaw/.env on process start.
# (force-recreate is only needed if you put secrets in the compose env_file.)
docker compose restart openclaw-gateway

docker compose exec openclaw-gateway openclaw sentrook verify
```

**Updates:** bump the pin, then restart:

```bash
openclaw plugins install npm:@firstdataunion/sentrook-openclaw@1.0.1 --pin --force
# or: openclaw plugins update npm:@firstdataunion/sentrook-openclaw@1.0.1 --force
```

### Soak / release candidate (`next`)

Prereleases publish to dist-tag **`next`** and never move `latest`. Point the
plugin at **staging** Sentrook and keep feedback off there.

```bash
openclaw plugins install npm:@firstdataunion/sentrook-openclaw@next --pin --force
openclaw sentrook configure   # url → staging scan host
```

### Publishing a new plugin version (maintainers)

**Changesets** record bump intent + changelog. They **do not** publish. Add one
on plugin-behaviour PRs:

```bash
make plugin-changeset    # or: npx changeset
```

Merging to `main` opens a Version PR (`.github/workflows/changeset-version.yml`)
that bumps `plugin/package.json` + `CHANGELOG.md`. Merge that, then **manually**
dispatch Sentrook Actions → **`release-plugin`** (`channel=next` or `latest`,
Environment `release-npm`, OIDC). Merging never publishes. Local script is
tests + pack, plus a one-off bootstrap:

```bash
# after package.json already matches the channel (stable x.y.z or x.y.z-rc.N):
./publish-plugin.sh --dry-run                 # tests + pack; infers tag from version
./publish-plugin.sh --publish --tag=latest    # bootstrap / emergency only; npm login
```

`release-plugin` inputs: `channel`, optional `require_full_eval` (default on),
optional `dry_run` (gates only). First CI publish needs npm Trusted Publisher
configured for workflow `release-plugin.yml` + Environment `release-npm`
(or a one-off laptop bootstrap of `1.0.0` so Trusted Publisher can attach).

RCs: `npx changeset pre enter rc` before `make plugin-version`, then
`pre exit` before the matching stable bump. Dist-tag `next` is a publish
concern, not a Changesets tag.

Do **not** publish to GitHub Packages. First-ever npm version must be `1.0.0` on
`latest`; later RCs use `x.y.z-rc.N` + tag `next`. See
[`.changeset/README.md`](../../.changeset/README.md).

## Configure

### Wizard (preferred)

```bash
openclaw sentrook configure
```

Interactive flow:

1. Accept defaults for scan URL / mode / timeout / sanitization (or override)
2. Community corpus: contribute sanitized allow-once/deny reviews by default
   (opt out with `n`, or later `feedback.mode: "off"` / `--contribute-corpus false`)
3. Paste FIDU ID OAuth `client_id` + `client_secret` (link printed in the wizard)
4. Writes credentials + patches `plugins.entries.sentrook-openclaw`
5. Prints reload instructions — **does not restart the gateway**

Non-interactive:

```bash
openclaw sentrook configure --non-interactive \
  --client-id "$SENTROOK_SCAN_CLIENT_ID" \
  --client-secret "$SENTROOK_SCAN_CLIENT_SECRET"
# Opt out of community corpus:
#   --contribute-corpus false
```

Shared scan API key (optional, soak only): `--api-key` / `SENTROOK_SCAN_API_KEY`.

Optional dual-write for Docker: set `SENTROOK_DOTENV=~/openclaw/.env` (or
`OPENCLAW_COMPOSE_ENV`) when that path is visible to the configure process
(host-side, or if you mount the compose project into the gateway).

### Where secrets live (Docker vs native)

Scan credentials are **not** stored as SecretRefs in `openclaw.json` (unresolved
refs on an enabled plugin fail-close the gateway). Configure writes
`SENTROOK_SCAN_*` to **`~/.openclaw/.env`**; the plugin reads them from process
env after OpenClaw loads that file at gateway start.

This matches OpenClaw’s recommended store for provider API keys
([Environment variables](https://docs.openclaw.ai/help/environment)).

| Install | Credentials | Reload after configure |
| --- | --- | --- |
| Native / systemd | `~/.openclaw/.env` | `openclaw gateway restart` |
| Docker Compose | `~/.openclaw/.env` (bind-mounted) | `docker compose restart openclaw-gateway` |

**Do not put Sentrook scan secrets only in `~/openclaw/.env` (compose `env_file`)**
unless you prefer that layout. Compose injects `env_file` only at container
**create** time, so changes need `docker compose up -d --force-recreate` — the
same trap as Notion/Discord keys in the project `.env`. State-dir `.env` avoids
that: a normal **restart** re-reads the file.

Missing credentials → plugin warns and soft-fails scans; gateway stays up.

Trade-off: `openclaw secrets audit` will not track these as SecretRef migrations.
Intentional until optional SecretRefs exist without aborting startup.

**How others do it:** Some CLIs keep an encrypted file keyring under the tool
home plus a process env unlock password (often systemd / `~/.openclaw/.env`) —
different shape, same idea: durable state under the agent home, not compose
`env_file`. Notion and similar integrations that live only in compose `.env`
hit the recreate requirement; we deliberately avoid that for Sentrook.

### Manual (optional)

1. Store credentials: `./sentrook-scan-oidc.sh` (writes `~/.openclaw/.env`)
2. Patch `openclaw.json` (no credential SecretRefs):

```json5
{
  plugins: {
    entries: {
      "sentrook-openclaw": {
        enabled: true,
        config: {
          url: "https://sentrook.firstdataunion.org",
          timeoutMs: 3000,
          mode: "enforce",
          feedback: { mode: "submit" },
          sanitization: { enabled: true },
        },
      },
    },
  },
}
```

`feedback.mode: "submit"` (configure default) posts sanitized allow-once / deny
resolutions to hosted Sentrook `/feedback`, which forwards them to Rookery as
pending community corpus examples (human review still gates publish). Examples are
attributed to post-L3 **kept** review rules (never L3-allowed matches): allow-once /
allow-always fan out to every kept co-firer (fatigue learning); deny trains only the
winning/causal rule. Hosted
Sentrook **derives** community `intent` from the tool trajectory by default
(`SENTROOK_FEEDBACK_DERIVE_INTENT=1`) so chat prompts are not stored in Rookery —
set `0` on the scan host to keep prompt-as-intent while soaking. Set
`feedback.mode: "off"` to opt out. `allow-always` uses the local allowlist below;
it does not write a per-user corpus on the hosted scanner.

3. Put `SENTROOK_SCAN_*` in `~/.openclaw/.env` (preferred) or your compose `env_file`
4. Restart gateway: `docker compose restart openclaw-gateway`
   (use `--force-recreate` only if credentials live solely in the compose `env_file`)

## Allow every time (local allowlist)

In **enforce** mode, Sentrook `review` decisions surface OpenClaw’s approval UI
(`allow-once` / `allow-always` / `deny`). Online hosted Sentrook does **not** keep a
per-user personal corpus, so “Allow every time” would otherwise re-prompt forever.

The plugin restores durable short-circuiting **locally** on the OpenClaw host:

1. Scan still always runs (`POST /scan`); Sentrook `block` is never overridden
2. On `allow-always`, the plugin records a local entry and still `POST`s `/feedback`
3. On later matching `review`s, the plugin skips `requireApproval`

Store: `~/.openclaw/sentrook-allowlist.json` (or `$OPENCLAW_STATE_DIR/sentrook-allowlist.json`).
Separate from OpenClaw’s native `exec-approvals.json`. Treat both files like
`openclaw.json`: they control approval bypass and must not be edited by the agent
without operator review (Sentrook **AIRA-050** flags `write`/`edit` to these paths).

**Security:** Only entries recorded via the plugin’s `allow-always` handler are
honoured at load time (`source: allow-always`, valid `created_at`, schema checks).
Hand-edited or poisoned JSON is ignored. Allowlist hits are logged at **warn**
level with matched rule ids and entry fingerprints — grep gateway logs for
`local allowlist hit` when auditing unexpected auto-allows.

Supported mutations: `openclaw sentrook allowlist list|clear --yes` (not agent `write`).

Two entry kinds:

| Kind | When | Match |
| --- | --- | --- |
| `script_bind` | `python3`/`bash`/`node` + a concrete local script file | Same interpreter + resolved path + **content SHA-256**; trailing args allow only date/UUID/int placeholders (URLs and paths stay literal). Script rewrite ⇒ re-prompt |
| `skeleton` | Other safe command shapes | Constrained argv skeleton; never bare `curl`/`python`/pipes/inline-eval |

Config (optional):

```json5
allowlist: {
  enabled: true,          // SENTROOK_ALLOWLIST_ENABLED
  scriptBind: true,       // SENTROOK_ALLOWLIST_SCRIPT_BIND
  // path: "~/.openclaw/sentrook-allowlist.json"
}
```

### Managing the local store

```bash
openclaw sentrook allowlist path              # print resolved JSON path
openclaw sentrook allowlist list              # show skeleton / script_bind entries
openclaw sentrook allowlist clear --yes       # wipe all entries (debug / start fresh)
```

Optional flags: `--path <file>`, `--state-dir <dir>` (same resolution as the live plugin).

## Uninstall

```bash
OPENCLAW_DIR=~/openclaw ./uninstall-plugin.sh
PURGE=1 OPENCLAW_DIR=~/openclaw ./uninstall-plugin.sh
# Then restart the gateway yourself.
```

## Verify & logs

```bash
docker compose exec openclaw-gateway openclaw sentrook verify
```

Checks plugin config entry, scan credentials in `~/.openclaw/.env`, whether those
env vars are loaded in-process (recreate/restart gateway if not), and `GET /health`
on the scan URL. No Python `sentrook` package required.

Optional runtime inspect:

```bash
docker compose exec openclaw-gateway \
  openclaw plugins inspect sentrook-openclaw --runtime --json
```

Gateway (plugin timing):

```bash
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-openclaw
```

Sentrook VPS (decisions + transport):

```bash
docker exec sentrook-scan tail -f /var/log/sentrook/scan.log.jsonl
docker exec sentrook-scan tail -f /var/log/sentrook/latency.log.jsonl
```

Scans run only on **tool calls**. Chat-only turns produce no scan lines.

## Layout

| Path | Purpose |
|------|---------|
| `plugin/` | OpenClaw plugin (`@firstdataunion/sentrook-openclaw`) + `openclaw sentrook configure` |
| (repo root) `.changeset/` | Plugin bump intent + changelog (does not publish) |
| `publish-plugin.sh` | Test + pack; optional local npmjs publish (`--publish`) |
| `lib/common.sh` | Gateway exec / config helpers |
| `lib/sentrook-scan-auth.sh` | Write scan OIDC / API key to `~/.openclaw/.env` |
| `sentrook-scan-oidc.sh` | Standalone OIDC credential helper (optional) |
| `sentrook-scan-key.sh` | Shared API key helper (optional; prefer OIDC) |
| `uninstall-plugin.sh` | Remove plugin + optional credential purge |

## PlanIR sanitization and scan-log privacy

Plugin egress scrubbing defaults **on** (`sanitization.enabled: true` /
`SENTROOK_SANITIZE_PLANIR=1`). Server
ingress uses `SENTROOK_SERVER_SANITIZE_PLANIR` (default on). FIDU hosted
deploy docs live in Rookery `deploy/sentrook-scan/` (see also
`sentrook/deploy/README.md` pointer).

**Disk logs (`scan.log.jsonl`)** can still hold scrubbed intent / command
excerpts when `SENTROOK_LOG_CONTENT=scrubbed` (the development default).
Pattern scrubbing is **not** a PII guarantee — free-form names and prose that
do not match patterns remain. For production traffic set:

```bash
SENTROOK_ENV=production
# implies SENTROOK_LOG_CONTENT=metadata (omit intent + command excerpts on disk)
# HTTP/feedback echo still gets scrubbed text; only the JSONL file is stripped
# refuses to start if sanitize is off or log content is scrubbed/full
```

| Variable | Role |
|----------|------|
| `SENTROOK_ENV` | `production` \| `development` (aliases: `prod` / `dev`) |
| `SENTROOK_LOG_CONTENT` | `metadata` (no PlanIR free text on disk) \| `scrubbed` \| `full` (dev only) |
| `SENTROOK_LOG_LEVEL` | Stdlib level (`INFO` default; access lines are `DEBUG`) |
| `SENTROOK_SERVER_SANITIZE_PLANIR` | Ingress sanitize + session-id hashing (required in production) |

Latency JSONL (`SENTROOK_LATENCY_LOG_PATH`) stores timings and ids only — no
PlanIR body. Decision summaries in the scan log are rule-engine text, not user
prompts.
