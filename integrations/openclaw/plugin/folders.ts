/**
 * Trusted folders: the content an owner's `folder` grant vouches for, and the check on each read.
 *
 * When the owner trusts a folder (`/sentrook-grant folder <dir>`, or a folder item set from the setup screen), the
 * plugin records what the folder holds at that moment, in a manifest `<state>/folders/<grant id>.json`: each file's
 * path relative to the folder and a digest of its content.
 *
 * - In a git work tree, the digest is the git blob id of each tracked file at the commit checked out. With
 *   `--follow <remote>/<branch>`, it is the blob id at that branch's tip on the remote instead. The plugin asks the
 *   remote for the tip itself, at the URL recorded when the owner set the grant, at most every few minutes, outside
 *   the repository. The tip commit must already be fetched.
 * - Anywhere else, the digest is the sha256 of each file.
 *
 * After the agent reads a file with OpenClaw's `read` tool, `attest` finds a live folder grant whose folder holds the
 * file's real path (a symlink cannot lead out of the folder). It answers that grant's id only when the file's digest
 * is the one in the manifest. The scan then sends the read with `trusted_by` and Sentrook treats it as the owner's own
 * content. A file the agent or anyone else changed, an untracked file, or a file the manifest does not list is not
 * attested. The owner refreshes the manifest by trusting the folder again.
 *
 * The folder itself never decides anything: the manifest lives in the plugin's state folder, which the agent cannot
 * write without Sentrook blocking it. Git is run with its repository hooks, fsmonitor and replace refs switched off.
 * The Hermes plugin keeps the same manifests and prints the same text.
 */

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { devNull, tmpdir } from "node:os";
import path from "node:path";

export type Manifest = Record<string, any>;

/** The limits on a folder trusted by content, and on a file that is attested (changeable by tests). */
export const LIMITS = {
  /** At most this many files, and this many bytes in all, in a folder trusted by content. */
  maxFiles: 20_000,
  maxBytes: 200 * 1024 * 1024,
  /** A file larger than this is never attested (reading it whole to digest it would stall the hook). */
  maxFileBytes: 16 * 1024 * 1024,
};
/** How often a `--follow` folder asks its remote for the branch tip. */
export const FOLLOW_EVERY_MS = 5 * 60_000;
export const GIT_TIMEOUT_MS = 10_000;
const REMOTE_BRANCH = /^([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/;
const GLOB = /[*?[\]]/;
const NOT_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|[^\P{Zs} ]/u;
/** The host's and Sentrook's own folders under the home: never a folder the owner trusts as content. */
export const HOST_FOLDERS = [".hermes", ".openclaw"];
export const SYSTEM_HOST_FOLDERS = ["/etc/hermes"];
/** Git, with nothing from the repository that could run code or swap what an object id names. */
const GIT = [
  "--no-replace-objects",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "protocol.ext.allow=never",
];

/** Why a folder cannot be trusted, in words for the owner. */
export class FolderError extends Error {}

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;

/** The filesystem ignores letter case (macOS, Windows): `/Users/ME/.OPENCLAW` is `~/.openclaw`. Changeable by tests. */
export const CASE = { folds: process.platform === "darwin" || process.platform === "win32" };

const key = (p: string) => (CASE.folds ? p.toLowerCase() : p);

function under(p: string, root: string): boolean {
  const a = key(p);
  const r = key(root.replace(/\/+$/, ""));
  return a === r || a.startsWith(`${r}/`);
}

/** The path with every symlink resolved, as far as it exists (the rest appended as written), like Python's realpath. */
export function realpath(p: string): string {
  const abs = path.resolve(p);
  try {
    return realpathSync(abs);
  } catch {
    const parent = path.dirname(abs);
    if (parent === abs) return abs;
    return path.join(realpath(parent), path.basename(abs));
  }
}

/** `p` normalised, without a trailing slash (Python's normpath). */
function normpath(p: string): string {
  const n = path.posix.normalize(p);
  return n.length > 1 ? n.replace(/\/+$/, "") : n;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

// ---- which folders may be trusted -----------------------------------------------------------------------------

/**
 * The folder `pattern` names, as its real absolute path, or FolderError saying why it cannot be trusted: a glob, a
 * path that is not an existing folder, `/` or one level below it, the home folder or one above it, the host's own
 * folders (`~/.hermes`, `~/.openclaw`, `/etc/hermes`) or the plugin's state folder. The same rules as Sentrook's
 * `folder_root`, applied to the real path too.
 */
export function resolve(pattern: string, opts: { home: string; stateDir?: string | null }): string {
  const { home } = opts;
  const raw = pattern.trim();
  if (!raw) throw new FolderError("Name a folder to trust.");
  if (GLOB.test(raw) || NOT_PRINTABLE.test(raw)) {
    throw new FolderError(`"${raw}" has a wildcard: name one folder, such as ~/src/my-repo.`);
  }
  let expanded = raw;
  for (const prefix of ["~", "$HOME"]) {
    if (expanded === prefix || expanded.startsWith(`${prefix}/`)) {
      expanded = home.replace(/\/+$/, "") + expanded.slice(prefix.length);
      break;
    }
  }
  if (!expanded.startsWith("/")) throw new FolderError(`"${raw}" is not a full path: start it with / or ~/.`);
  const real = realpath(expanded);
  if (!isDir(real)) throw new FolderError(`"${raw}" is not a folder on this machine.`);
  const homeReal = realpath(home);
  const homes = [...new Set([home.replace(/\/+$/, ""), homeReal])];
  const state = opts.stateDir ? realpath(opts.stateDir) : null;
  for (const candidate of new Set([normpath(expanded), real])) {
    const parts = candidate.split("/").filter(Boolean);
    if (parts.length < 2) throw new FolderError(`"${raw}" is too broad: trust one project folder, not ${candidate}.`);
    for (const h of homes) {
      if (under(h, candidate)) {
        throw new FolderError(`"${raw}" is your home folder or a folder above it: trust one project folder inside it.`);
      }
      if (HOST_FOLDERS.some((d) => under(candidate, `${h}/${d}`))) {
        throw new FolderError(`"${raw}" holds the agent's own files: it can never be a trusted folder.`);
      }
    }
    if (SYSTEM_HOST_FOLDERS.some((d) => under(candidate, d))) {
      throw new FolderError(`"${raw}" holds the agent's own files: it can never be a trusted folder.`);
    }
    if (state !== null) {
      if (under(candidate, state) || under(state, candidate)) {
        throw new FolderError(`"${raw}" holds Sentrook's own files: it can never be a trusted folder.`);
      }
      // The host's own home (`<openclaw state dir>/sentrook` sits in it), wherever it is configured.
      if (path.basename(state) === "sentrook" && under(candidate, path.dirname(state))) {
        throw new FolderError(`"${raw}" holds the agent's own files: it can never be a trusted folder.`);
      }
    }
  }
  return real;
}

/** `origin/main` -> ["origin", "main"]. */
export function parseFollow(value: string): [string, string] {
  const m = REMOTE_BRANCH.exec(value.trim());
  if (!m || value.includes("..")) {
    throw new FolderError(`Unknown branch "${value}": use <remote>/<branch>, such as origin/main.`);
  }
  return [m[1]!, m[2]!];
}

// ---- git ------------------------------------------------------------------------------------------------------

/** Git could not be run at all (missing, timed out): not a reason in the owner's words. */
export class GitRunError extends Error {}

function git(top: string | null, args: string[], timeoutMs = GIT_TIMEOUT_MS): string {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("GIT_") && v !== undefined) env[k] = v;
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_OPTIONAL_LOCKS = "0";
  // Nothing from the global or system git config: the agent can write `~/.gitconfig`, where `url.<x>.insteadOf` would
  // point the recorded remote elsewhere. The repository's own config is still read, with the keys that run code
  // (fsmonitor, hooks) overridden by `GIT`; `ls-remote` runs outside it.
  env.GIT_CONFIG_GLOBAL = devNull;
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_COUNT = "0";
  // The folder is a path, never a pattern: a `*` or `:(...)` in its name matches nothing else.
  env.GIT_LITERAL_PATHSPECS = "1";
  const done = spawnSync("git", [...GIT, ...(top ? ["-C", top] : []), ...args], {
    cwd: top ?? tmpdir(),
    env,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
    shell: false,
  });
  if (done.error) throw new GitRunError(String(done.error.message ?? done.error));
  if (done.status !== 0) {
    const err = (done.stderr ?? Buffer.alloc(0)).toString("utf8").trim().slice(0, 200);
    throw new FolderError(err || "git failed");
  }
  return (done.stdout ?? Buffer.alloc(0)).toString("utf8");
}

/** The top of the git work tree holding `folder`, or null when it is not in one (or git is missing). */
export function gitTop(folder: string): string | null {
  let top: string;
  try {
    top = git(folder, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    return null;
  }
  return top ? realpath(top) : null;
}

/** {path relative to `folder`: blob id} for each regular file under `folder` in `commit`. */
function blobFiles(top: string, folder: string, commit: string): Record<string, string> {
  const prefix = path.relative(top, folder) || ".";
  const args = ["ls-tree", "-r", "-l", "-z", "--full-tree", commit];
  if (prefix !== ".") args.push("--", `${prefix}/`);
  const out = git(top, args, 60_000);
  const files: Record<string, string> = {};
  let n = 0;
  let total = 0;
  for (const entry of out.split("\0")) {
    if (!entry) continue;
    const tab = entry.indexOf("\t");
    const meta = tab < 0 ? entry : entry.slice(0, tab);
    const p = tab < 0 ? "" : entry.slice(tab + 1);
    const [mode = "", kind = "", oid = "", size = ""] = meta.split(/\s+/).filter(Boolean);
    if (kind !== "blob" || (mode !== "100644" && mode !== "100755")) continue; // symlinks and submodules are never attested
    const rel = prefix === "." ? p : p.slice(prefix.length + 1);
    if (!Object.hasOwn(files, rel)) n++;
    files[rel] = oid;
    total += /^\d+$/.test(size) ? Number(size) : 0;
    if (n > LIMITS.maxFiles || total > LIMITS.maxBytes) {
      throw new FolderError(
        `The folder is larger than ${LIMITS.maxFiles} files or ${Math.floor(LIMITS.maxBytes / (1024 * 1024))} MB: trust a ` +
          "smaller folder inside it, or a git repository.",
      );
    }
  }
  return files;
}

/** The git blob id of `data` (`algo` is the repository's object format: sha1 or sha256). */
export function blobId(data: Buffer, algo: string): string {
  return createHash(algo).update(`blob ${data.length}\0`).update(data).digest("hex");
}

// ---- building a manifest --------------------------------------------------------------------------------------

/**
 * The manifest of `folder` (a real path from `resolve`), or FolderError. In a git work tree: the blob ids at the
 * commit checked out, or with `follow` (`origin/main`) at that remote branch's tip, asked of the remote. Else the
 * sha256 of each file, when the folder is within the limits.
 */
export function build(folder: string, opts: { follow?: string | null; now?: Date } = {}): Manifest {
  const now = opts.now ?? new Date();
  const top = gitTop(folder);
  if (opts.follow !== undefined && opts.follow !== null) {
    if (top === null) throw new FolderError("--follow needs a git repository; this folder is not in one.");
    const [remote, branch] = parseFollow(opts.follow);
    let url: string;
    try {
      url = git(top, ["config", "--get", `remote.${remote}.url`]).trim();
    } catch (err) {
      if (err instanceof FolderError) throw new FolderError(`The repository has no remote "${remote}".`);
      throw err;
    }
    if (!url) throw new FolderError(`The repository has no remote "${remote}".`);
    const tip = remoteTip(url, branch);
    if (!hasCommit(top, tip)) {
      throw new FolderError(`The tip of ${remote}/${branch} (${tip.slice(0, 12)}) is not fetched yet: run git fetch ${remote} first.`);
    }
    const manifest = gitManifest(top, folder, tip, now);
    manifest.follow = { remote, branch, url, checked_at: iso(now) };
    return manifest;
  }
  if (top !== null) {
    const head = git(top, ["rev-parse", "--verify", "HEAD^{commit}"]).trim();
    return gitManifest(top, folder, head, now);
  }
  return fileManifest(folder, now);
}

function gitManifest(top: string, folder: string, commit: string, now: Date): Manifest {
  let algo: string;
  try {
    algo = git(top, ["rev-parse", "--show-object-format"]).trim() || "sha1";
  } catch (err) {
    if (!(err instanceof FolderError)) throw err;
    algo = "sha1";
  }
  if (algo !== "sha1" && algo !== "sha256") throw new FolderError(`Unknown git object format ${algo}.`);
  return {
    version: 1,
    folder,
    kind: "git",
    top,
    algo,
    commit,
    built_at: iso(now),
    files: blobFiles(top, folder, commit),
  };
}

function fileManifest(folder: string, now: Date): Manifest {
  const files: Record<string, string> = {};
  let count = 0;
  let total = 0;
  const walk = (dir: string) => {
    const names = readdirSync(dir).sort();
    const dirs: string[] = [];
    for (const name of names) {
      const p = path.join(dir, name);
      const st = lstatSync(p);
      if (st.isDirectory()) {
        if (name !== ".git") dirs.push(p);
        continue;
      }
      if (!st.isFile()) continue; // symlinks and anything else are never attested
      const tooBig = () =>
        new FolderError(
          `The folder is larger than ${LIMITS.maxFiles} files or ${Math.floor(LIMITS.maxBytes / (1024 * 1024))} MB: trust a ` +
            "smaller folder inside it, or a git repository.",
        );
      if (count >= LIMITS.maxFiles) throw tooBig();
      const data = readRegular(p, LIMITS.maxBytes - total);
      if (data === null) {
        // replaced by something other than a regular file since the listing, or too large
        if (total + st.size > LIMITS.maxBytes) throw tooBig();
        continue;
      }
      total += data.length;
      files[path.relative(folder, p)] = createHash("sha256").update(data).digest("hex");
      count++;
    }
    for (const d of dirs) walk(d);
  };
  walk(folder);
  return { version: 1, folder, kind: "files", algo: "sha256", built_at: iso(now), files };
}

/**
 * A regular file's bytes, read through one open descriptor so the checks and the read see the same file (never a
 * symlink, and nothing swapped in between). Null if it is not a regular file or is larger than `max`.
 */
function readRegular(p: string, max: number): Buffer | null {
  let fd: number;
  try {
    fd = openSync(p, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max) return null;
    const data = readFileSync(fd);
    return data.length > max ? null : data;
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/**
 * The commit `branch` points to on the remote at `url`, asked outside any repository, so no repository's config,
 * hooks or remote settings take part.
 */
export function remoteTip(url: string, branch: string): string {
  const out = git(null, ["ls-remote", "--", url, `refs/heads/${branch}`]);
  for (const line of out.split(/\r?\n/)) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const oid = line.slice(0, tab);
    if (line.slice(tab + 1) === `refs/heads/${branch}` && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(oid)) return oid;
  }
  throw new FolderError(`The remote has no branch ${branch}.`);
}

function hasCommit(top: string, oid: string): boolean {
  try {
    git(top, ["cat-file", "-e", `${oid}^{commit}`]);
  } catch (err) {
    if (err instanceof FolderError) return false;
    throw err;
  }
  return true;
}

// ---- storing --------------------------------------------------------------------------------------------------

function manifestPath(stateDir: string, gid: string): string {
  if (!/^gr-[0-9a-f]{6}$/.test(gid)) throw new FolderError(`Unknown grant id ${gid}.`);
  return path.join(stateDir, "folders", `${gid}.json`);
}

export function save(stateDir: string, gid: string, manifest: Manifest): void {
  const file = manifestPath(stateDir, gid);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = path.join(path.dirname(file), `.tmp-${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(manifest));
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
}

export function load(stateDir: string, gid: string): Manifest | null {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(manifestPath(stateDir, gid), "utf8"));
  } catch {
    return null;
  }
  const ok =
    !!data &&
    typeof data === "object" &&
    !Array.isArray(data) &&
    !!(data as Manifest).files &&
    typeof (data as Manifest).files === "object" &&
    !Array.isArray((data as Manifest).files);
  return ok ? (data as Manifest) : null;
}

export function remove(stateDir: string, gid: string): void {
  try {
    unlinkSync(manifestPath(stateDir, gid));
  } catch {
    // already gone, or not a grant id
  }
}

/** Drops the manifests of folder grants that are gone. */
export function prune(stateDir: string, keep: Set<string>): void {
  let names: string[];
  try {
    names = readdirSync(path.join(stateDir, "folders")).filter((n) => n.startsWith("gr-") && n.endsWith(".json"));
  } catch {
    return;
  }
  for (const n of names) {
    if (keep.has(n.slice(0, -5))) continue;
    try {
      unlinkSync(path.join(stateDir, "folders", n));
    } catch {
      // gone already
    }
  }
}

/** A value as Python's str() shows it (None for a missing one), so both plugins print the same. */
const pyStr = (v: unknown) => (v === undefined || v === null ? "None" : String(v));

/** The anchor in a few words, for the grants list. */
export function describe(manifest: Manifest | null): string {
  if (manifest === null || manifest === undefined) return "content record missing: trust the folder again";
  const files = manifest.files;
  const n = Array.isArray(files) ? files.length : files && typeof files === "object" ? Object.keys(files).length : 0;
  if (manifest.kind === "git") {
    const f = manifest.follow;
    const commit = pyStr(manifest.commit).slice(0, 12);
    const where =
      f && typeof f === "object" && !Array.isArray(f) ? `follows ${pyStr(f.remote)}/${pyStr(f.branch)} at ${commit}` : `pinned at ${commit}`;
    return `git, ${where}, ${n} files`;
  }
  return `${n} files as they were ${pyStr(manifest.built_at)}`;
}

// ---- the read check -------------------------------------------------------------------------------------------

function readIso(v: unknown): Date | null {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * A `--follow` manifest, rebuilt from the remote branch's tip when it moved and is fetched; checked at most every
 * `FOLLOW_EVERY_MS`. A remote that cannot be asked leaves the manifest as it was.
 */
function refresh(stateDir: string, gid: string, manifest: Manifest, now: Date): Manifest {
  let f = manifest.follow;
  if (!f || typeof f !== "object" || Array.isArray(f)) return manifest;
  const checked = readIso(f.checked_at);
  if (checked !== null && now.getTime() - checked.getTime() < FOLLOW_EVERY_MS) return manifest;
  f = { ...f, checked_at: iso(now) };
  try {
    if (typeof f.url !== "string" || typeof f.branch !== "string") throw new FolderError("no follow");
    const tip = remoteTip(f.url, f.branch);
    if (tip !== manifest.commit && hasCommit(String(manifest.top), tip)) {
      manifest = gitManifest(String(manifest.top), String(manifest.folder), tip, now);
    }
  } catch {
    // the remote could not be asked: the manifest stays as it was
  }
  manifest = { ...manifest, follow: f };
  try {
    save(stateDir, gid, manifest);
  } catch {
    // checked again next time
  }
  return manifest;
}

/**
 * What OpenClaw's `read` showed the agent (`shown`, its one text block) is the text of the file the plugin hashed, or
 * a run of whole lines of it, as a read with an offset and limit returns them. Anything else (another copy of the
 * file, a notice the host added, nothing at all) is no match.
 */
export function shownMatches(shown: string | null, text: string): boolean {
  if (!shown) return false;
  if (shown === text) return true;
  for (let i = text.indexOf(shown); i >= 0; i = text.indexOf(shown, i + 1)) {
    const end = i + shown.length;
    const starts = i === 0 || text[i - 1] === "\n";
    const ends = end === text.length || shown.endsWith("\n") || text[end] === "\n" || text.startsWith("\r\n", end);
    if (starts && ends) return true;
  }
  return false;
}

/**
 * The id of the folder grant that vouches for the file at `filePath` as read now, or null. `folderGrants` is
 * [grant id, folder pattern] for each live folder grant. `filePath` must be absolute or start with `~/`: the host
 * resolves a relative path against a working folder the plugin cannot know. The file's real path must be inside the
 * folder's real path, its digest must be the manifest's, and what the read showed (`seen`) must be the file's text
 * (`shownMatches`), so the agent saw the trusted bytes wherever the host read them from (a sandbox, a remote backend).
 */
export function attest(
  stateDir: string,
  folderGrants: Array<[string, string]>,
  filePath: unknown,
  opts: { home: string; seen: string | null; now?: Date },
): string | null {
  if (typeof filePath !== "string" || !filePath.trim() || !folderGrants.length || !opts.seen) return null;
  const now = opts.now ?? new Date();
  let p = filePath.trim();
  if (p === "~" || p.startsWith("~/")) p = opts.home.replace(/\/+$/, "") + p.slice(1);
  if (!p.startsWith("/")) return null;
  const real = realpath(p);
  let data: Buffer | null = null;
  for (const [gid, pattern] of folderGrants) {
    const root = realpath(pattern.replace(/\/+$/, "") || "/");
    if (!under(real, root) || real === root) continue;
    let manifest = load(stateDir, gid);
    if (manifest === null || realpath(String(manifest.folder)) !== root) continue;
    manifest = refresh(stateDir, gid, manifest, now);
    const rel = path.relative(root, real);
    const want = Object.hasOwn(manifest.files, rel) ? manifest.files[rel] : undefined;
    if (typeof want !== "string") continue;
    if (data === null) {
      data = readRegular(real, LIMITS.maxFileBytes);
      if (data === null) return null;
    }
    const algo = String(manifest.algo ?? "");
    const got =
      manifest.kind === "git" && (algo === "sha1" || algo === "sha256")
        ? blobId(data, algo)
        : algo === "sha256"
          ? createHash("sha256").update(data).digest("hex")
          : null;
    if (got !== null && got === want) {
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
      } catch {
        return null;
      }
      return shownMatches(opts.seen, text) ? gid : null;
    }
  }
  return null;
}
