# Changesets (OpenClaw plugin)

Bump intent + changelog for `@firstdataunion/sentrook-openclaw`. **Merging a
changeset does not publish to npm.** `release-plugin.yml` (OIDC, Environment
`release-npm`) is the only npm write.

Python packages are not in this Changesets workspace. The root `package.json`
exists so Changesets can see the plugin from the git root.

Tooling: `@changesets/cli` 2.x and `changesets/action@v1`. Action v2 needs
Changesets 3 (still prerelease).

## Feature PRs

When plugin behaviour or the installable API changes:

```bash
make plugin-changeset    # or: npx changeset
```

Pick `patch` / `minor` / `major`, write a user-facing summary. Commit the new
`.changeset/*.md` with the PR. Docs-only / test-only PRs do not need one.

## Version PR

On `main`, `.github/workflows/changeset-version.yml` opens a **Version** PR
(`changeset version` + lockfile). Merge that to bump
`integrations/openclaw/plugin/package.json` and `CHANGELOG.md`. Then dispatch
Sentrook Actions → **`release-plugin`** with `channel=next` or `latest`
(Environment `release-npm`, OIDC Trusted Publisher). That workflow is the only
npm write — merging never publishes.

Local equivalent: `make plugin-version`.

## Release candidates

Prerelease versions are `x.y.z-rc.N` (npm dist-tag `next`). Enter Changesets
pre mode before the version bump:

```bash
npx changeset pre enter rc
make plugin-version          # → e.g. 1.0.1-rc.0
npx changeset pre exit       # before the matching stable bump
```

Do not put a prerelease in `package.json` and then publish `--tag=latest`.
