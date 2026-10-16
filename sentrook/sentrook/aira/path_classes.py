"""Per-path classification and URL host extraction for the AIRA probe (ported from 1.x).

Two axes, kept apart because they answer different questions and a flat set cannot keep them apart:

* ``locations`` — *where* the path is. **Never empty**: ``other`` is the residue. An earlier flat
  vocabulary added ``other`` only when *nothing* matched, so a role match erased the location and
  ``~/.ssh/id_rsa`` had no location at all; a "was every path in scratch space?" test then read it
  as vacuously true and suppressed a destructive-command review.
* ``roles`` — *what* it holds, from the path groups of `lists/sensitive_paths.yaml`. Legitimately
  empty for an ordinary file.

**Classification is whole-command, never per-segment.** ``cd`` rebases path context, so
``cd ~/.ssh && cat id_rsa`` has a second segment whose argv carries no sensitive path. Paths are
collected from every segment and classified as one set, and the group patterns are additionally run
over the *whole command text* (`derive_path_roles`) so a reference embedded in a flag value
(``curl -F f=@~/.ssh/id_rsa``), a bare basename after a ``cd`` or a redirect target is not lost to
tokenisation.

`tmp` and `workspace` are read **exculpatorily** by the destruction detector (C7 fires on `rm -rf`
whose paths are *not* scratch). That inverts the usual direction: everywhere else a class is a
reason to score and over-matching fails safe, but here over-matching suppresses a contribution.
Both are therefore deliberately narrow, and neither guesses.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .sensitive_paths import PathList

#: **Where** a path lives. Every path gets at least one of these, in this order.
LOCATION_CLASSES: tuple[str, ...] = ("openclaw", "hermes", "tmp", "workspace", "system", "other")

#: Locations where destruction is routine rather than consequential. Named here rather than in a
#: detector because it is read exculpatorily — the one place in the design where matching a class
#: *suppresses* a contribution — so it belongs next to the classifier.
SCRATCH_LOCATIONS: frozenset[str] = frozenset({"tmp", "workspace"})

_URL_RE = re.compile(r"\bhttps?://[^\s\"'`<>|;)\]}]+", re.IGNORECASE)
#: What a hostname may actually contain. `"https://example.org${url}"` has a `urlsplit` host of
#: `example.org${url`; truncating at the first character no hostname can contain recovers the real
#: host, and yields nothing for `https://$HOST/x`, which is the honest answer there.
_HOSTNAME_CHARS = re.compile(r"\A[A-Za-z0-9._-]+")
#: npm/OpenClaw scoped packages contain a slash and are not filesystem paths.
_SCOPED_PKG_RE = re.compile(r"\A@[^/]+/[^/]+\Z")
_OPENCLAW_RE = re.compile(r"(?:\A|/)\.openclaw(?:/|\Z)", re.IGNORECASE)
_HERMES_RE = re.compile(r"(?:\A|/)\.hermes(?:/|\Z)", re.IGNORECASE)
#: Absolute only: a relative `tmp/` is a directory inside the workspace, not `/tmp`, and
#: `rm -rf tmp/foo` must not inherit /tmp's leniency from a name.
_TMP_RE = re.compile(r"\A(?:~/|/)(?:private/)?(?:var/)?tmp(?:/|\Z)", re.IGNORECASE)
#: `workspace` is a specific host concept, not any directory that sounds like one. `repo`, `src`
#: and `project` were here once and made `/usr/src/linux` "workspace". The deployment's real
#: workspace root is passed in by the caller (`workspace_root`); this segment match is the fallback
#: for the default `~/.openclaw/workspace` layout.
_WORKSPACE_RE = re.compile(r"(?:\A|/)workspaces?(?:/|\Z)", re.IGNORECASE)
_SYSTEM_RE = re.compile(
    r"\A/(?:etc|usr|bin|sbin|lib|lib64|opt|boot|sys|proc|dev|srv|var(?!/tmp))(?:/|\Z)",
    re.IGNORECASE,
)


def is_path_like(token: str) -> bool:
    """Whether a token is *recognisably* a filesystem path.

    Conservative on purpose. A bare relative token (`foo.txt`, `main`) is not treated as a path:
    without cwd its class is unknowable, and inventing one would be guessing in the fail-open
    direction. The basename groups and the whole-command scan cover the case that matters — a
    relative reference to something sensitive — so the defences overlap.
    """
    if not token or token.startswith("-"):
        return False
    if any(char.isspace() for char in token):
        # A quoted argument, not a path. `_collect_commands` unquotes string literals, so
        # `echo "Cleaned up /tmp/x"` arrives as one token containing a slash. For a scoring class
        # this is harmless noise, but `tmp` and `workspace` are read exculpatorily, and a prose
        # string mentioning `/workspace/` would supply an excuse for destroying something else.
        return False
    if _URL_RE.match(token) or _SCOPED_PKG_RE.match(token):
        return False
    if token.startswith(("/", "./", "../", "~")):
        return True
    return "/" in token and not token.startswith("@")


def strip_argument_decoration(token: str) -> str:
    """Peel the non-path parts off a token that embeds one.

    `-F f=@/home/node/.env` arrives as one argv entry in curl's own syntax; `--data-binary @-` and
    `KEY=/path` are the same shape. Splitting on the last `=` or leading `@` recovers the path
    without a curl-specific table.
    """
    if "=" in token:
        token = token.rsplit("=", 1)[1]
    return token.lstrip("@")


@dataclass(slots=True)
class ExecPath:
    """One filesystem path the command references, classified on both axes.

    `raw` is carried deliberately: the questions a detector asks today are a subset of the ones
    real traffic will demand, and a detector that can re-examine the path text needs no engine
    change to ask a new one. `segment` is the index of the compound-command half it came from.
    """

    raw: str
    locations: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    segment: int = 0

    @property
    def is_scratch(self) -> bool:
        """Whether this path lives in scratch space — **any** location counts. Locations nest:
        `~/.openclaw/workspace/a.py` is both `openclaw` and `workspace`, and it really is in the
        workspace."""
        return bool(set(self.locations) & SCRATCH_LOCATIONS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "locations": list(self.locations),
            "roles": list(self.roles),
            "segment": self.segment,
        }


def _expand_home(path: str, home: str | None) -> str:
    if home and (path == "~" or path.startswith("~/")):
        return home.rstrip("/") + path[1:]
    return path


def locations_of(
    path: str, workspace_root: str | None = None, home: str | None = None
) -> list[str]:
    """The location classes of one path, in `LOCATION_CLASSES` order. Never empty."""
    found: set[str] = set()
    if _OPENCLAW_RE.search(path):
        found.add("openclaw")
    if _HERMES_RE.search(path):
        found.add("hermes")
    if _TMP_RE.search(path):
        found.add("tmp")
    if _WORKSPACE_RE.search(path):
        found.add("workspace")
    if workspace_root:
        ws = _expand_home(workspace_root, home).rstrip("/")
        expanded = _expand_home(path, home)
        if ws and (expanded == ws or expanded.startswith(ws + "/")):
            found.add("workspace")
    if _SYSTEM_RE.search(path):
        found.add("system")
    if not found:
        found.add("other")
    return [name for name in LOCATION_CLASSES if name in found]


def classify_path_detail(
    path: str,
    groups: Mapping[str, PathList],
    roles_present: Sequence[str] | None = None,
    *,
    workspace_root: str | None = None,
    home: str | None = None,
) -> tuple[list[str], list[str]]:
    """`(locations, roles)` for one path token, in declared order. `roles_present` narrows which
    groups are tested (see `derive_paths`); the default tests all of them."""
    names = list(groups) if roles_present is None else [n for n in roles_present if n in groups]
    roles = [name for name in names if groups[name].search(path)]
    return locations_of(path, workspace_root, home), roles


def derive_path_roles(text: str, groups: Mapping[str, PathList]) -> list[str]:
    """Groups referenced **anywhere in the text**, in declared order.

    Deliberately *not* per path, because the references that matter most often are not extractable
    as path tokens at all: a bare basename after a `cd` (`cat id_ed25519` has no `/`), a redirect
    target (`echo x >> ~/.bashrc` keeps the destination out of argv), a reference inside a quoted
    string, or a mechanism name rather than a path (`crontab`). URLs are removed first: a URL path
    is not a filesystem path, and `https://x/mail/` must not read as a mail store.
    """
    stripped = _URL_RE.sub(" ", text)
    return [name for name, group in groups.items() if group.search(stripped)]


def extract_paths(tokens: Iterable[str]) -> list[str]:
    """Path-like tokens, decoration stripped, in order and deduplicated."""
    seen: set[str] = set()
    out: list[str] = []
    for token in tokens:
        candidate = strip_argument_decoration(token)
        if not is_path_like(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def derive_paths(
    command: str,
    segments: Iterable[Iterable[str]],
    groups: Mapping[str, PathList],
    roles_present: Sequence[str] | None = None,
    *,
    workspace_root: str | None = None,
    home: str | None = None,
) -> list[ExecPath]:
    """Every path the command references, classified on both axes.

    The groups are scanned once over the **whole command** and only the groups that matched are
    re-tested per path. Every token is a substring of the command, so a token cannot carry a role
    the command does not — the narrowing is exact, and it is what keeps the hot path affordable.

    Deduplication is **per segment**: a path named twice in one simple command is one path, but the
    same path named in two segments is two references, because they are two different acts
    (`ls -la ~/.ssh && rm -rf ~/.ssh`).
    """
    present = derive_path_roles(command, groups) if roles_present is None else list(roles_present)
    out: list[ExecPath] = []
    seen: set[tuple[int, str]] = set()
    for index, tokens in enumerate(segments):
        if isinstance(tokens, str):
            raise TypeError(
                "derive_paths expects one token list per segment, e.g. "
                "[s.argv for s in shape.segments]; got a bare string"
            )
        for raw in extract_paths(tokens):
            if (index, raw) in seen:
                continue
            seen.add((index, raw))
            locations, roles = classify_path_detail(
                raw, groups, present, workspace_root=workspace_root, home=home
            )
            out.append(ExecPath(raw=raw, locations=locations, roles=roles, segment=index))
    return out


def roll_up_path_classes(
    path_roles: Iterable[str], paths: Iterable[ExecPath], groups: Mapping[str, PathList]
) -> list[str]:
    """The flat roll-up of both axes (roles in group order, then locations). For evidence and
    metrics only; detectors read the structured `paths`."""
    found: set[str] = set(path_roles)
    for path in paths:
        found.update(path.locations)
        found.update(path.roles)
    order = [*groups, *LOCATION_CLASSES]
    return [name for name in order if name in found]


def derive_url_hosts(text: str) -> list[str]:
    """Lowercased hostnames of every http(s) URL in the text, deduplicated. Userinfo and port are
    dropped — `https://user:tok@evil.example:8443/x` is the host `evil.example` — so a credential
    in the URL cannot smuggle a distinct-looking host past a list."""
    hosts: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if not host:
            continue
        valid = _HOSTNAME_CHARS.match(host)
        if not valid:
            continue
        # A bare label is kept: `http://mediawiki/api.php` really does name a host on a container
        # network, and reporting no host for it would be a fail-open answer about egress.
        host = valid.group(0).lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts
