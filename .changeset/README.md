# Changesets (OpenClaw plugin)

Bump intent + changelog for `@firstdataunion/sentrook-openclaw`. **Merging a
changeset does not publish to npm.** `release-plugin.yml` (OIDC, Environment
`release-npm`) is the only npm write.

Python packages are not in this Changesets workspace. The root `package.json`
exists so Changesets can see the plugin from the git root.

Tooling: `@changesets/cli` 3.x and `changesets/action@v2`.

## Feature PRs

When plugin behaviour or the installable API changes:

```bash
make plugin-changeset    # or: npx changeset
```

Pick `patch` / `minor` / `major`, write a user-facing summary. Commit the new
`.changeset/*.md` with the PR. Docs-only / test-only PRs do not need one.

## Version PR

On `main`, `.github/workflows/changeset-version.yml` opens a **Version** PR
(`npm run version`: `changeset version`, then `PLUGIN_VERSION` in `planir.ts`
set to the new version, then the lockfile). Merge that to bump
`integrations/openclaw/plugin/package.json` and `PLUGIN_VERSION` together (a
test keeps them equal) and write the version's entry in
`integrations/openclaw/plugin/CHANGELOG.md`. Then dispatch
Sentrook Actions → **`release-plugin`** with `channel=next` or `latest`
(`dry_run` first if in doubt; Environment `release-npm`, OIDC Trusted
Publisher). It refuses a version with no CHANGELOG entry, runs the OpenClaw
compatibility check on the packed tarball, then publishes that tarball to
ClawHub (with `clawhub`) and npm. That workflow is the only npm write —
merging never publishes.

Local equivalent: `npm run version` at the repo root.

## Release candidates

Prerelease versions are `x.y.z-beta.N` (npm dist-tag `next`, ClawHub tag
`beta`). While `.changeset/pre.json` says `"mode": "pre"`, every version bump
stays on the beta line (2.0.0-beta.12 plus a patch → 2.0.0-beta.13); outside
pre mode the same patch would publish 2.0.0. Changesets 3 moves consumed
changesets into `.changeset/pre/` until pre mode ends.

```bash
npx changeset pre enter beta   # already on: 2.0.0 betas
npx changeset pre exit         # in the PR before the matching stable bump
```

Do not put a prerelease in `package.json` and then publish `--tag=latest`.
