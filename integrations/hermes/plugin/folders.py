"""Trusted folders: the content an owner's `folder` grant vouches for, and the check on each read.

When the owner trusts a folder (`grant folder <dir>`, or a folder item set from the setup screen), the plugin records
what the folder holds at that moment, in a manifest `<state>/folders/<grant id>.json`: each file's path relative to
the folder and a digest of its content.

- In a git work tree, the digest is the git blob id of each tracked file at the commit checked out. With
  `--follow <remote>/<branch>`, it is the blob id at that branch's tip on the remote instead. The plugin asks the
  remote for the tip itself, at the URL recorded when the owner set the grant, at most every few minutes, outside
  the repository. The tip commit must already be fetched.
- Anywhere else, the digest is the sha256 of each file.

After the agent reads a file with the host's file-read tool, `attest` finds a live folder grant whose folder holds
the file's real path (a symlink cannot lead out of the folder). It answers that grant's id only when the file's
digest is the one in the manifest. The scan then sends the read with `trusted_by` and Sentrook treats it as the
owner's own content. A file the agent or anyone else changed, an untracked file, or a file the manifest does not
list is not attested. The owner refreshes the manifest by trusting the folder again.

The folder itself never decides anything: the manifest lives in the plugin's state folder, which the agent cannot
write without Sentrook blocking it. Git is run with its repository hooks, fsmonitor and replace refs switched off.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

#: At most this many files, and this many bytes in all, in a folder trusted by content.
MAX_FILES = 20_000
MAX_BYTES = 200 * 1024 * 1024
#: A file larger than this is never attested (reading it whole to digest it would stall the hook).
MAX_FILE_BYTES = 16 * 1024 * 1024
#: How often a `--follow` folder asks its remote for the branch tip.
FOLLOW_EVERY = timedelta(minutes=5)
GIT_TIMEOUT = 10
_REMOTE_BRANCH = re.compile(r"([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)")
_GLOB = re.compile(r"[*?\[\]]")
#: The host's and Sentrook's own folders under the home: never a folder the owner trusts as content.
HOST_FOLDERS = (".hermes", ".openclaw")
SYSTEM_HOST_FOLDERS = ("/etc/hermes",)
#: Git, with nothing from the repository that could run code or swap what an object id names.
_GIT = (
    "git",
    "--no-replace-objects",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.ext.allow=never",
)


class FolderError(Exception):
    """Why a folder cannot be trusted, in words for the owner."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


#: The filesystem ignores letter case (macOS, Windows): `/Users/ME/.HERMES` is `~/.hermes`.
CASE_FOLDS = sys.platform in ("darwin", "win32")


def _key(path: str) -> str:
    return path.casefold() if CASE_FOLDS else path


def _under(path: str, root: str) -> bool:
    path, root = _key(path), _key(root.rstrip("/"))
    return path == root or path.startswith(root + "/")


# ---- which folders may be trusted ---------------------------------------------------------------------------


def resolve(pattern: str, *, home: str, state_dir: Path | None = None) -> str:
    """The folder `pattern` names, as its real absolute path, or FolderError saying why it cannot be trusted:
    a glob, a path that is not an existing folder, `/` or one level below it, the home folder or one above it,
    the host's own folders (`~/.hermes`, `~/.openclaw`, `/etc/hermes`) or the plugin's state folder. The same
    rules as Sentrook's `folder_root`, applied to the real path too."""
    raw = pattern.strip()
    if not raw:
        raise FolderError("Name a folder to trust.")
    if _GLOB.search(raw) or not raw.isprintable():
        raise FolderError(f'"{raw}" has a wildcard: name one folder, such as ~/src/my-repo.')
    expanded = raw
    for prefix in ("~", "$HOME"):
        if expanded == prefix or expanded.startswith(prefix + "/"):
            expanded = home.rstrip("/") + expanded[len(prefix) :]
            break
    if not expanded.startswith("/"):
        raise FolderError(f'"{raw}" is not a full path: start it with / or ~/.')
    real = os.path.realpath(expanded)
    if not os.path.isdir(real):
        raise FolderError(f'"{raw}" is not a folder on this machine.')
    home_real = os.path.realpath(home)
    for candidate in {os.path.normpath(expanded), real}:
        parts = [p for p in candidate.split("/") if p]
        if len(parts) < 2:
            raise FolderError(f'"{raw}" is too broad: trust one project folder, not {candidate}.')
        for h in {home.rstrip("/"), home_real}:
            if _under(h, candidate):
                raise FolderError(
                    f'"{raw}" is your home folder or a folder above it: trust one project folder inside it.'
                )
            if any(_under(candidate, f"{h}/{d}") for d in HOST_FOLDERS):
                raise FolderError(
                    f'"{raw}" holds the agent\'s own files: it can never be a trusted folder.'
                )
        if any(_under(candidate, d) for d in SYSTEM_HOST_FOLDERS):
            raise FolderError(
                f'"{raw}" holds the agent\'s own files: it can never be a trusted folder.'
            )
        if state_dir is not None:
            state_real = os.path.realpath(state_dir)
            if _under(candidate, state_real) or _under(state_real, candidate):
                raise FolderError(
                    f'"{raw}" holds Sentrook\'s own files: it can never be a trusted folder.'
                )
            # The host's own home (`<hermes home>/sentrook` sits in it), wherever it is configured.
            if Path(state_real).name == "sentrook" and _under(
                candidate, str(Path(state_real).parent)
            ):
                raise FolderError(
                    f'"{raw}" holds the agent\'s own files: it can never be a trusted folder.'
                )
    return real


def parse_follow(value: str) -> tuple[str, str]:
    """`origin/main` -> ("origin", "main")."""
    m = _REMOTE_BRANCH.fullmatch(value.strip())
    if not m or ".." in value:
        raise FolderError(f'Unknown branch "{value}": use <remote>/<branch>, such as origin/main.')
    return m.group(1), m.group(2)


# ---- git --------------------------------------------------------------------------------------------------------


def _git(top: str | None, *args: str, timeout: int = GIT_TIMEOUT) -> str:
    cmd = [*_GIT, *(("-C", top) if top else ()), *args]
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        # Nothing from anyone's git config: the agent can write `~/.gitconfig`, where `url.<x>.insteadOf` would
        # point the recorded remote elsewhere; the repository's own config is set aside by `_GIT`.
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
    }
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        cmd,
        capture_output=True,
        timeout=timeout,
        env=env,
        cwd=top or tempfile.gettempdir(),
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if done.returncode != 0:
        raise FolderError(
            (done.stderr or b"").decode("utf-8", "replace").strip()[:200] or "git failed"
        )
    return done.stdout.decode("utf-8", "surrogateescape")


def git_top(folder: str) -> str | None:
    """The top of the git work tree holding `folder`, or None when it is not in one (or git is missing)."""
    try:
        top = _git(folder, "rev-parse", "--show-toplevel").strip()
    except (FolderError, OSError, subprocess.SubprocessError):
        return None
    return os.path.realpath(top) if top else None


def _blob_files(top: str, folder: str, commit: str) -> dict[str, str]:
    """{path relative to `folder`: blob id} for each regular file under `folder` in `commit`."""
    prefix = os.path.relpath(folder, top)
    args = ["ls-tree", "-r", "-l", "-z", "--full-tree", commit]
    if prefix != ".":
        args += ["--", prefix + "/"]
    out = _git(top, *args, timeout=60)
    files: dict[str, str] = {}
    total = 0
    for entry in out.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        mode, kind, oid, size = (meta.split() + ["", "", "", ""])[:4]
        if kind != "blob" or mode not in ("100644", "100755"):
            continue  # symlinks and submodules are never attested
        rel = path if prefix == "." else path[len(prefix) + 1 :]
        files[rel] = oid
        total += int(size) if size.isdigit() else 0
        if len(files) > MAX_FILES or total > MAX_BYTES:
            raise FolderError(
                f"The folder is larger than {MAX_FILES} files or {MAX_BYTES // (1024 * 1024)} MB: trust a "
                "smaller folder inside it, or a git repository."
            )
    return files


def blob_id(data: bytes, algo: str) -> str:
    """The git blob id of `data` (`algo` is the repository's object format: sha1 or sha256)."""
    h = hashlib.new(algo)
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


# ---- building a manifest ----------------------------------------------------------------------------------------


def build(folder: str, *, follow: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    """The manifest of `folder` (a real path from `resolve`), or FolderError. In a git work tree: the blob ids at
    the commit checked out, or with `follow` (`origin/main`) at that remote branch's tip, asked of the remote. Else
    the sha256 of each file, when the folder is within the limits."""
    now = now or _now()
    top = git_top(folder)
    if follow is not None:
        if top is None:
            raise FolderError("--follow needs a git repository; this folder is not in one.")
        remote, branch = parse_follow(follow)
        try:
            url = _git(top, "config", "--get", f"remote.{remote}.url").strip()
        except FolderError:
            raise FolderError(f'The repository has no remote "{remote}".') from None
        if not url:
            raise FolderError(f'The repository has no remote "{remote}".')
        tip = remote_tip(url, branch)
        if not _has_commit(top, tip):
            raise FolderError(
                f"The tip of {remote}/{branch} ({tip[:12]}) is not fetched yet: run git fetch {remote} first."
            )
        manifest = _git_manifest(top, folder, tip, now)
        manifest["follow"] = {
            "remote": remote,
            "branch": branch,
            "url": url,
            "checked_at": _iso(now),
        }
        return manifest
    if top is not None:
        head = _git(top, "rev-parse", "--verify", "HEAD^{commit}").strip()
        return _git_manifest(top, folder, head, now)
    return _file_manifest(folder, now)


def _git_manifest(top: str, folder: str, commit: str, now: datetime) -> dict[str, Any]:
    try:
        algo = _git(top, "rev-parse", "--show-object-format").strip() or "sha1"
    except FolderError:
        algo = "sha1"
    if algo not in ("sha1", "sha256"):
        raise FolderError(f"Unknown git object format {algo}.")
    return {
        "version": 1,
        "folder": folder,
        "kind": "git",
        "top": top,
        "algo": algo,
        "commit": commit,
        "built_at": _iso(now),
        "files": _blob_files(top, folder, commit),
    }


def _file_manifest(folder: str, now: datetime) -> dict[str, Any]:
    files: dict[str, str] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            total += size
            if len(files) >= MAX_FILES or total > MAX_BYTES:
                raise FolderError(
                    f"The folder is larger than {MAX_FILES} files or {MAX_BYTES // (1024 * 1024)} MB: trust a "
                    "smaller folder inside it, or a git repository."
                )
            files[os.path.relpath(path, folder)] = _sha256(path)
    return {
        "version": 1,
        "folder": folder,
        "kind": "files",
        "algo": "sha256",
        "built_at": _iso(now),
        "files": files,
    }


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def remote_tip(url: str, branch: str) -> str:
    """The commit `branch` points to on the remote at `url`, asked outside any repository, so no repository's
    config, hooks or remote settings take part."""
    out = _git(None, "ls-remote", "--", url, f"refs/heads/{branch}")
    for line in out.splitlines():
        oid, _, ref = line.partition("\t")
        if ref == f"refs/heads/{branch}" and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            return oid
    raise FolderError(f"The remote has no branch {branch}.")


def _has_commit(top: str, oid: str) -> bool:
    try:
        _git(top, "cat-file", "-e", f"{oid}^{{commit}}")
    except FolderError:
        return False
    return True


# ---- storing ----------------------------------------------------------------------------------------------------


def _path(state_dir: Path, gid: str) -> Path:
    if not re.fullmatch(r"gr-[0-9a-f]{6}", gid):
        raise FolderError(f"Unknown grant id {gid}.")
    return state_dir / "folders" / f"{gid}.json"


def save(state_dir: Path, gid: str, manifest: dict[str, Any]) -> None:
    path = _path(state_dir, gid)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load(state_dir: Path, gid: str) -> dict[str, Any] | None:
    try:
        data = json.loads(_path(state_dir, gid).read_text(encoding="utf-8"))
    except (OSError, ValueError, FolderError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("files"), dict) else None


def remove(state_dir: Path, gid: str) -> None:
    try:
        _path(state_dir, gid).unlink()
    except (OSError, FolderError):
        pass


def prune(state_dir: Path, keep: set[str]) -> None:
    """Drops the manifests of folder grants that are gone."""
    try:
        names = list((state_dir / "folders").glob("gr-*.json"))
    except OSError:
        return
    for p in names:
        if p.stem not in keep:
            try:
                p.unlink()
            except OSError:
                pass


def describe(manifest: dict[str, Any] | None) -> str:
    """The anchor in a few words, for the grants list."""
    if manifest is None:
        return "content record missing: trust the folder again"
    n = len(manifest.get("files") or {})
    if manifest.get("kind") == "git":
        f = manifest.get("follow")
        where = (
            f"follows {f.get('remote')}/{f.get('branch')} at {str(manifest.get('commit'))[:12]}"
            if isinstance(f, dict)
            else f"pinned at {str(manifest.get('commit'))[:12]}"
        )
        return f"git, {where}, {n} files"
    return f"{n} files as they were {manifest.get('built_at')}"


# ---- the read check ---------------------------------------------------------------------------------------------


def _refresh(state_dir: Path, gid: str, manifest: dict[str, Any], now: datetime) -> dict[str, Any]:
    """A `--follow` manifest, rebuilt from the remote branch's tip when it moved and is fetched; checked at most every
    `FOLLOW_EVERY`. A remote that cannot be asked leaves the manifest as it was."""
    f = manifest.get("follow")
    if not isinstance(f, dict):
        return manifest
    try:
        checked = datetime.strptime(str(f.get("checked_at")), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError:
        checked = None
    if checked is not None and now - checked < FOLLOW_EVERY:
        return manifest
    f = {**f, "checked_at": _iso(now)}
    try:
        tip = remote_tip(str(f["url"]), str(f["branch"]))
        if tip != manifest.get("commit") and _has_commit(str(manifest["top"]), tip):
            manifest = _git_manifest(str(manifest["top"]), str(manifest["folder"]), tip, now)
    except (FolderError, OSError, subprocess.SubprocessError, KeyError):
        pass
    manifest = {**manifest, "follow": f}
    try:
        save(state_dir, gid, manifest)
    except OSError:
        pass
    return manifest


#: How Hermes marks a line it cut short in a read.
TRUNCATED = "... [truncated]"
_NUMBERED = re.compile(r"(\d+)\|(.*)")


def numbered_lines(content: str) -> list[tuple[int, str]] | None:
    """`content` as Hermes's `read_file` numbers it (`<n>|<line>` per line), or None when a line is not so numbered."""
    out = []
    for raw in content.split("\n"):
        m = _NUMBERED.fullmatch(raw)
        if m is None:
            return None
        out.append((int(m.group(1)), m.group(2)))
    return out


def seen_matches(seen: list[tuple[int, str]], text: str) -> bool:
    """The numbered lines the read showed (`seen`) are the lines of `text`, the file as the plugin hashed it. A line
    the host cut short (`... [truncated]`) must be the start of its line. Nothing shown, or a line out of range, is no
    match."""
    lines = text.splitlines()
    if not seen:
        return False
    for n, shown in seen:
        if not 1 <= n <= len(lines):
            return False
        line = lines[n - 1]
        if shown == line:
            continue
        cut = shown.removesuffix(TRUNCATED)
        if cut == shown or not line.startswith(cut):
            return False
    return True


def attest(
    state_dir: Path,
    folder_grants: list[tuple[str, str]],
    path: Any,
    *,
    home: str,
    seen: list[tuple[int, str]] | None,
    now: datetime | None = None,
) -> str | None:
    """The id of the folder grant that vouches for the file at `path` as read now, or None. `folder_grants` is
    (grant id, folder pattern) for each live folder grant. `path` must be absolute or start with `~/`: the host
    resolves a relative path against a working folder the plugin cannot know. The file's real path must be inside
    the folder's real path, its digest must be the manifest's, and the lines the read showed (`seen`) must be the
    file's, so the agent saw the trusted bytes wherever the host read them from (a sandbox, a remote backend)."""
    if not isinstance(path, str) or not path.strip() or not folder_grants or seen is None:
        return None
    now = now or _now()
    p = path.strip()
    if p == "~" or p.startswith("~/"):
        p = home.rstrip("/") + p[1:]
    if not p.startswith("/"):
        return None
    real = os.path.realpath(p)
    try:
        if not os.path.isfile(real) or os.path.getsize(real) > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    data: bytes | None = None
    for gid, pattern in folder_grants:
        root = os.path.realpath(pattern.rstrip("/") or "/")
        if not _under(real, root) or real == root:
            continue
        manifest = load(state_dir, gid)
        if manifest is None or os.path.realpath(str(manifest.get("folder"))) != root:
            continue
        manifest = _refresh(state_dir, gid, manifest, now)
        want = manifest["files"].get(os.path.relpath(real, root))
        if not isinstance(want, str):
            continue
        if data is None:
            try:
                with open(real, "rb") as f:
                    data = f.read(MAX_FILE_BYTES + 1)
            except OSError:
                return None
        algo = str(manifest.get("algo") or "")
        got = (
            blob_id(data, algo)
            if manifest.get("kind") == "git" and algo in ("sha1", "sha256")
            else hashlib.sha256(data).hexdigest()
            if algo == "sha256"
            else None
        )
        if got is not None and got == want:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                return None
            return gid if seen_matches(seen, text) else None
    return None
