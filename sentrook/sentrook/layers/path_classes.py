"""Per-path classification and URL host extraction for ``exec_shape`` — §1.1.

**This is deliberately not** ``serve.fingerprint.path_class``. That function
exists and does something that looks similar, and reusing it was the obvious
move; §1.1 rules it out for two reasons worth restating where the code lives:

* It returns **one** class for the **whole** command, chosen by a precedence
  ladder. An allow rule needs to know that a command touches *no* sensitive
  path, which a single winning label cannot express: ``cat README.md
  ~/.ssh/id_rsa`` and ``cat ~/.ssh/id_rsa`` are both just ``"sensitive"``, and
  ``cat ~/.ssh/id_rsa README.md`` would be too if the ladder had gone the other
  way. Allow eligibility is a property of the whole path *set*.
* It folds ``PIPE_SINK_RE`` and ``ENV_PROBE_RE`` into ``sensitive``, so
  ``curl x | sh`` — which references no path at all — classifies as a sensitive
  *path*. Sinks are their own field on the shape.

And it must not simply be *changed*, because ``path_class`` is a component of
the fingerprint string, and fingerprints are the identity that corpus near-dup,
session caps, Rookery ingest and ``loop_sim`` history are keyed on. The two
share the canonical list (§1.3) and nothing else.

**Classification is whole-command, never per-segment.** ``cd`` rebases path
context, so ``cd ~/.ssh && cat id_rsa`` has a second segment whose argv carries
no sensitive path. Paths are collected from every segment and classified as one
set, and the canonical patterns are additionally run over the *whole command
text* so a reference embedded in a flag value (``curl -F f=@~/.ssh/id_rsa``) or
inside quotes is not lost to tokenisation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sentrook.sanitize.sensitive_paths import load_sensitive_paths

#: The closed class vocabulary. Order is the order they appear in
#: ``path_classes``, which rules match as a newline-joined string — so it is
#: API, not cosmetics.
PATH_CLASSES: tuple[str, ...] = (
    "sensitive",
    "agent_config",
    "persistence",
    "openclaw",
    "tmp",
    "workspace",
    "system",
    "other",
)

#: **Where** a path lives. Every path gets at least one of these.
LOCATION_CLASSES: tuple[str, ...] = ("openclaw", "tmp", "workspace", "system", "other")

#: **What** a path holds. A path may have none of these.
#: Bound to the canonical list's group names, so a group added there is one
#: line from being a role here.
ROLE_CLASSES: tuple[str, ...] = ("sensitive", "agent_config", "persistence")

#: Backwards name for the role groups, used where the loader is addressed.
_LIST_CLASSES: tuple[str, ...] = ROLE_CLASSES

#: Locations where destruction is routine rather than consequential. Named here
#: rather than in a rule because it is read **exculpatorily** — the one place in
#: the design where matching a class *suppresses* a review — so it belongs
#: somewhere a reader will find it next to the classifier.
SCRATCH_LOCATIONS: frozenset[str] = frozenset({"tmp", "workspace"})

_URL_RE = re.compile(r"\bhttps?://[^\s\"'`<>|;)\]}]+", re.IGNORECASE)
#: What a hostname may actually contain. Measured need: the corpus carries
#: `"https://brightlingseaharbour.org${url}"`, whose `urlsplit` host is
#: `brightlingseaharbour.org${url` — a string that is not a host and would sit
#: in `url_hosts` looking like one. Truncating at the first character no
#: hostname can contain recovers the real host where there is one, and yields
#: nothing for `https://$HOST/x`, which is the honest answer there.
_HOSTNAME_CHARS = re.compile(r"\A[A-Za-z0-9._-]+")
#: npm/OpenClaw scoped packages contain a slash and are not filesystem paths.
_SCOPED_PKG_RE = re.compile(r"\A@[^/]+/[^/]+\Z")
_OPENCLAW_RE = re.compile(r"(?:\A|/)\.openclaw(?:/|\Z)", re.IGNORECASE)
#: `tmp` and `workspace` are the only two classes a rule uses **exculpatorily**
#: — Phase 3a's class-5 rule fires on `rm -rf` whose path class is *other than*
#: `tmp`/`workspace`. That inverts the usual direction: everywhere else a class
#: is a reason to refuse and over-matching fails safe, but here over-matching
#: **suppresses a destructive-command review**. Both are therefore deliberately
#: narrow, and neither guesses.
#:
#: Absolute only: a relative `tmp/` is a directory inside the workspace, not
#: `/tmp`, and `rm -rf tmp/foo` must not inherit /tmp's leniency from a name.
_TMP_RE = re.compile(r"\A(?:~/|/)(?:private/)?(?:var/)?tmp(?:/|\Z)", re.IGNORECASE)
#: `workspace` is a specific OpenClaw concept, not any directory that sounds
#: like one. `repo`, `src` and `project` were here and are guesses — they made
#: `/usr/src/linux` and `/var/lib/repo` "workspace", which under the class-5
#: rule would have excused `rm -rf` of either. Real workspace identification
#: needs `posture.workspace_root` (Phase 5); until then, match only the name
#: the deployment actually uses.
_WORKSPACE_RE = re.compile(r"(?:\A|/)workspaces?(?:/|\Z)", re.IGNORECASE)
_SYSTEM_RE = re.compile(
    r"\A/(?:etc|usr|bin|sbin|lib|lib64|opt|boot|sys|proc|dev|var(?!/tmp))(?:/|\Z)",
    re.IGNORECASE,
)


def is_path_like(token: str) -> bool:
    """Whether a token is *recognisably* a filesystem path.

    Conservative on purpose. A bare relative token (``foo.txt``, ``main``) is
    not treated as a path: without cwd its class is unknowable, and inventing
    one would be guessing in the fail-**open** direction. §1.3's basenames and
    the whole-command scan cover the case that actually matters — a relative
    reference to something sensitive — and Phase 3b refuses ``cd`` outright, so
    the three defences overlap rather than any one of them having to be right.
    """
    if not token or token.startswith("-"):
        return False
    if any(char.isspace() for char in token):
        # A quoted argument, not a path. `_collect_commands` unquotes string
        # literals, so `echo "Cleaned up /tmp/x"` and `-H "Content-Type:
        # application/json"` arrive as single tokens containing a slash.
        # Measured: 62 of the corpus's "paths" were prose of this shape.
        #
        # The direction matters. For a refusal class this is harmless noise,
        # and a genuine quoted path with a space still reports `sensitive`
        # through the whole-command scan. But `tmp` and `workspace` are read
        # *exculpatorily* by the class-5 rule, and a prose string mentioning
        # `/workspace/` would have supplied an excuse for destroying something
        # else. Dropping these loses nothing and closes that.
        return False
    if _URL_RE.match(token) or _SCOPED_PKG_RE.match(token):
        return False
    if token.startswith(("/", "./", "../", "~")):
        return True
    return "/" in token and not token.startswith("@")


def _strip_argument_decoration(token: str) -> str:
    """Peel the non-path parts off a token that embeds one.

    ``-F f=@/home/node/.env`` arrives as one argv entry in curl's own syntax;
    ``--data-binary @-`` and ``KEY=/path`` are the same shape. Splitting on the
    last ``=`` or leading ``@`` recovers the path without a curl-specific table.
    """
    if "=" in token:
        token = token.rsplit("=", 1)[1]
    return token.lstrip("@")


@dataclass(slots=True)
class ExecPath:
    """One filesystem path the command references, classified on both axes.

    The two axes are separate fields rather than one set because they answer
    different questions and a flat set cannot keep them apart (F27):

    * ``locations`` — *where* the path is. **Never empty**: ``other`` is the
      residue. The earlier flat vocabulary added ``other`` only when *nothing*
      matched, so a role match erased the location and ``~/.ssh/id_rsa`` had no
      location at all. A "was every path in scratch space?" test then read it as
      vacuously true and suppressed a destructive-command review.
    * ``roles`` — *what* it holds. Legitimately empty for an ordinary file.

    ``raw`` is carried deliberately. The questions a rule asks today are a small
    subset of the ones real traffic will demand, and a rule that can re-examine
    the path text needs no engine change to ask a new one.
    """

    raw: str
    locations: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    #: Index of the compound-command segment this path came from — 0 for
    #: ``cat a b``, 1 for the second half of ``cat a && rm b``. Recorded rather
    #: than needed: nothing reads it today, and that is the point of carrying
    #: it, the same as ``raw``.
    segment: int = 0

    @property
    def is_scratch(self) -> bool:
        """Whether this path lives in scratch space — **any** location counts.

        Locations nest: `~/.openclaw/workspace/a.py` is both `openclaw` and
        `workspace`, and it really is in the workspace. Requiring *every*
        location to be scratch would call it non-scratch and fire a
        destructive-command review on ordinary workspace cleanup.

        This must agree with the rule idiom documented for the same question,
        `location: "\\A(?!.*(?:tmp|workspace))"`, which asks whether *no*
        location is scratch. Two definitions of one concept is the drift that
        produced F27; `test_is_scratch_agrees_with_the_documented_rule_idiom`
        holds them together.
        """
        return bool(set(self.locations) & SCRATCH_LOCATIONS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "locations": list(self.locations),
            "roles": list(self.roles),
            "segment": self.segment,
        }


def classify_path_detail(
    path: str, groups: Sequence[str] = ROLE_CLASSES
) -> tuple[list[str], list[str]]:
    """``(locations, roles)`` for one path token, in declared order.

    ``locations`` is never empty. ``groups`` narrows which role groups are
    tested — see :func:`derive_paths` for why that is exact rather than an
    approximation.
    """
    lists = load_sensitive_paths()
    roles = {name for name in groups if lists.group(name).regex.search(path)}
    locations: set[str] = set()
    if _OPENCLAW_RE.search(path):
        locations.add("openclaw")
    if _TMP_RE.search(path):
        locations.add("tmp")
    if _WORKSPACE_RE.search(path):
        locations.add("workspace")
    if _SYSTEM_RE.search(path):
        locations.add("system")
    if not locations:
        locations.add("other")
    return (
        [name for name in LOCATION_CLASSES if name in locations],
        [name for name in ROLE_CLASSES if name in roles],
    )


def derive_paths(
    command: str,
    segments: Iterable[Iterable[str]],
    roles_present: Sequence[str] | None = None,
) -> list[ExecPath]:
    """Every path the command references, classified on both axes.

    The role groups are scanned once over the **whole command** and only the
    groups that matched are re-tested per path. Every token is a substring of
    the command, so a token cannot carry a role the command does not — the
    narrowing is exact, not an approximation, and it is what keeps the hot path
    affordable: the ``sensitive`` group is a ~1 kB alternation and running it
    per token made shape derivation three times slower.

    Locations are always computed per path; they are cheap and, unlike roles,
    cannot be inferred from a whole-command scan.

    ``segments`` is one token list per simple command, so a path knows which
    half of ``cat a && rm b`` it came from. Deduplication is across the whole
    command: a path named twice is one path, attributed to where it first
    appeared.

    ``roles_present`` lets a caller that has already run
    :func:`derive_path_roles` pass the result in. The group regexes are the
    expensive part by two orders of magnitude, so running the whole-command scan
    once per command rather than once per consumer is the difference between
    one scan and four.
    """
    present = derive_path_roles(command) if roles_present is None else list(roles_present)
    out: list[ExecPath] = []
    seen: set[str] = set()
    for index, tokens in enumerate(segments):
        if isinstance(tokens, str):
            # A flat token list would otherwise iterate *characters*, silently
            # producing no paths at all. Loud beats subtle.
            raise TypeError(
                "derive_paths expects one token list per segment, e.g. "
                "[s.argv for s in shape.segments]; got a bare string"
            )
        for raw in extract_paths(tokens):
            if raw in seen:
                continue
            seen.add(raw)
            locations, roles = classify_path_detail(raw, present)
            out.append(ExecPath(raw=raw, locations=locations, roles=roles, segment=index))
    return out


def classify_path(path: str, groups: Sequence[str] = _LIST_CLASSES) -> set[str]:
    """**Every** class one path token belongs to.

    Not a precedence ladder. ``~/.openclaw/exec-approvals.json`` is both
    ``agent_config`` and ``openclaw``, and returning only the first match is a
    fail-open bug rather than a tidier answer: Phase 3b's Read family refuses
    ``path_classes`` containing ``openclaw``, so a path labelled *only*
    ``agent_config`` would slip past a rule written to exclude exactly it.
    A path in two categories is in two categories.

    ``other`` is the residue — present only when nothing else matched — so
    ``"other" in classes`` means "touches a path we could not characterise"
    rather than "touches nothing interesting".

    ``groups`` narrows which canonical list groups are tested. Callers that
    have already scanned the whole command pass only the groups it matched; a
    token is a substring of that command, so it cannot belong to a group the
    command did not. The default tests all of them, which is what a caller
    holding a bare path wants. See :func:`derive_path_classes` for why this
    matters — the group regexes are the expensive part by two orders of
    magnitude.
    """
    lists = load_sensitive_paths()
    found = {name for name in groups if lists.group(name).regex.search(path)}
    if _OPENCLAW_RE.search(path):
        found.add("openclaw")
    if _TMP_RE.search(path):
        found.add("tmp")
    if _WORKSPACE_RE.search(path):
        found.add("workspace")
    if _SYSTEM_RE.search(path):
        found.add("system")
    return found or {"other"}


def extract_paths(tokens: Iterable[str]) -> list[str]:
    """Path-like tokens, decoration stripped, in order and deduplicated."""
    seen: set[str] = set()
    out: list[str] = []
    for token in tokens:
        candidate = _strip_argument_decoration(token)
        if not is_path_like(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def derive_path_roles(command: str) -> list[str]:
    """Roles referenced **anywhere in the command text**, in declared order.

    Deliberately *not* per path, because the references that matter most often
    are not extractable as path tokens at all:

    * a bare basename after a ``cd`` — ``cat id_ed25519`` has no ``/``, so it is
      not path-like, and §1.3's basenames exist precisely for it;
    * a redirect target — ``echo x >> ~/.bashrc`` keeps the destination out of
      the command's argv;
    * a reference inside a quoted string, or a mechanism name rather than a
      path (``crontab``).

    So this is a property of the **command**, with no quantifier implied, and it
    is the §1.3 whole-command defence in its own field. The per-path view
    (:func:`derive_paths`) is structurally unable to see any of the above, which
    is why an allow rule must constrain *this* to establish "references no
    sensitive material" — `paths:` with a `none` quantifier would be vacuously
    satisfied by a command whose only reference is a bare basename.
    """
    lists = load_sensitive_paths()
    return [name for name in ROLE_CLASSES if lists.group(name).regex.search(command)]


def derive_path_classes(command: str, argv_tokens: Iterable[str]) -> list[str]:
    """Flat union of both axes, in :data:`PATH_CLASSES` order.

    **Derived from :func:`derive_paths`, and not matchable by a rule.** It is
    kept for metrics and the fatigue report (§5.2's
    `consequence_flagged_total{class}`), where a per-command roll-up is exactly
    what is wanted and no quantifier is implied.

    Rules use the `paths:` condition instead. A flat union forces the reader to
    infer a quantifier — "contains something other than tmp/workspace" over
    *which* path? — and that inference is what F27 got wrong in both directions
    at once. Deriving this from the structured view rather than computing it
    separately means the roll-up can never disagree with what rules see.
    """
    roles = derive_path_roles(command)
    return roll_up_path_classes(roles, derive_paths(command, [argv_tokens], roles))


def roll_up_path_classes(path_roles: Iterable[str], paths: Iterable[ExecPath]) -> list[str]:
    """The flat metrics roll-up, from values a caller already has."""
    found: set[str] = set(path_roles)
    for path in paths:
        found.update(path.locations)
        found.update(path.roles)
    return [name for name in PATH_CLASSES if name in found]


def derive_url_hosts(command: str) -> list[str]:
    """Lowercased hostnames of every http(s) URL in the command, deduplicated.

    Hosts rather than URLs: Phase 4 asks "did this reach an external host", and
    Phase 5's posture arm allowlists hosts. Userinfo and port are dropped —
    ``https://user:tok@evil.example:8443/x`` is the host ``evil.example`` — so a
    credential in the URL cannot smuggle a distinct-looking host past a list.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(command):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if not host:
            continue
        valid = _HOSTNAME_CHARS.match(host)
        if not valid:
            continue
        # A bare label is kept: `http://mediawiki/api.php` really does name a
        # host on a container network. Requiring a dot would report *no* hosts
        # for it, which an allow rule would read as "touches no network" —
        # a fail-open answer to a question about egress.
        host = valid.group(0).lower().rstrip(".")
        if not host:
            continue
        if host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts
