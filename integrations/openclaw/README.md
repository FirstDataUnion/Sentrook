# Sentrook OpenClaw integration (online)

Thin TypeScript plugin that scans every `before_tool_call` against **hosted**
Sentrook (`https://sentrook.firstdataunion.org`). No local sidecar.

**Branch note:** this tree is the online-only install path. Offline sidecar
scripts live on `main`.

## Install (GitHub Packages)

```bash
# 1. Install plugin (pinned)
openclaw plugins install npm:@firstdataunion/sentrook-shadow@0.2.4 --pin --force

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
  openclaw plugins install npm:@firstdataunion/sentrook-shadow@0.2.4 --pin --force
docker compose exec openclaw-gateway openclaw sentrook configure

# Restart is enough: OpenClaw reloads ~/.openclaw/.env on process start.
# (force-recreate is only needed if you put secrets in the compose env_file.)
docker compose restart openclaw-gateway

docker compose exec openclaw-gateway openclaw sentrook verify
```

### Auth for GitHub Packages (colleagues)

One-time `~/.npmrc` (see [`.npmrc.example`](.npmrc.example)):

```
@firstdataunion:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=<GITHUB_TOKEN>
```

Token needs `read:packages` (and org SSO authorize if applicable).
`NODE_AUTH_TOKEN=$(gh auth token)` also works if `gh` is logged into the org.

**Updates:** `openclaw plugins update npm:@firstdataunion/sentrook-shadow@0.2.4 --force`
then recreate/restart the gateway. Pinned installs stay on the exact version until you
opt in.

Plugin SemVer is **independent** of the Sentrook scanner version.

### Publishing a new plugin version (maintainers)

```bash
# bump version in plugin/package.json, then:
./publish-plugin.sh --dry-run    # tests + pack check
NODE_AUTH_TOKEN=$(gh auth token) ./publish-plugin.sh
```

Requires `write:packages` on a token that can publish to the `FirstDataUnion`
GitHub Packages org.

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
4. Writes credentials + patches `plugins.entries.sentrook-shadow`
5. Prints reload instructions — **does not restart the gateway**

Non-interactive:

```bash
openclaw sentrook configure --non-interactive \
  --client-id "$SENTROOK_SCAN_CLIENT_ID" \
  --client-secret "$SENTROOK_SCAN_CLIENT_SECRET"
# Opt out of community corpus:
#   --contribute-corpus false
```

Legacy shared API key (soak only): `--api-key` / `SENTROOK_SCAN_API_KEY`.

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

**How others do it:** gog uses an encrypted file keyring (`GOG_HOME`) plus a
process env unlock password (often systemd/`~/.openclaw/.env`) — different shape,
same idea: durable state under the OpenClaw home, not compose `env_file`. Notion
and similar integrations that live only in compose `.env` hit the recreate
requirement; we deliberately avoid that for Sentrook.

### Manual (optional)

1. Store credentials: `./sentrook-scan-oidc.sh` (writes `~/.openclaw/.env`)
2. Patch `openclaw.json` (no credential SecretRefs):

```json5
{
  plugins: {
    entries: {
      "sentrook-shadow": {
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
  openclaw plugins inspect sentrook-shadow --runtime --json
```

Gateway (plugin timing):

```bash
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-shadow
```

Sentrook VPS (decisions + transport):

```bash
docker exec sentrook-scan tail -f /var/log/sentrook/shadow.log.jsonl
docker exec sentrook-scan tail -f /var/log/sentrook/latency.log.jsonl
```

Scans run only on **tool calls**. Chat-only turns produce no scan lines.

## Layout

| Path | Purpose |
|------|---------|
| `plugin/` | OpenClaw plugin (`@firstdataunion/sentrook-shadow`) + `openclaw sentrook configure` |
| `publish-plugin.sh` | Test + publish to GitHub Packages |
| `.npmrc.example` | Colleague/CI registry auth template |
| `lib/common.sh` | Gateway exec / config helpers |
| `lib/sentrook-scan-auth.sh` | Write scan OIDC / API key to `~/.openclaw/.env` |
| `sentrook-scan-oidc.sh` | Standalone OIDC credential helper (optional) |
| `sentrook-scan-key.sh` | Legacy shared-key helper (soak) |
| `uninstall-plugin.sh` | Remove plugin + optional credential purge |

## Snapshot sanitization

Plugin egress scrubbing defaults **on** (`sanitization.enabled: true` /
`SENTROOK_SANITIZE_SNAPSHOT=1`). Server ingress uses
`SENTROOK_SERVER_SANITIZE_SNAPSHOT` (default on). See hosted deploy docs under
`sentrook/deploy/README.md`.
