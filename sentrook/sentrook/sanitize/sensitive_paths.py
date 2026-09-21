"""Load the canonical sensitive-path and named-binary lists — §1.3.

One list, four consumers. Before this module they were four hand-maintained
regexes that had already diverged: ``signal_excerpt`` classed every ``/etc``
path as sensitive while ``fingerprint`` classed none of them, and the rule
files carried a fifth copy pasted across seven YAML documents with a
``# keep in sync`` comment as the only enforcement.

Everything here is derived from :data:`SENSITIVE_PATHS_PATH` at import time and
cached. Nothing downstream may hold a copy of a pattern string — consumers bind
to the compiled object or to :func:`sensitive_path_fragment`, so adding an entry
to the YAML reaches all four without a second edit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any

import yaml

SENSITIVE_PATHS_PATH = Path(__file__).with_name("sensitive_paths.yaml")

#: A basename is a path *component*, so it may be preceded by a separator, a
#: quote, an ``=``, a ``-`` or nothing, but never by an alphanumeric that would
#: make it part of a longer word. ``myapp.env`` must not match ``.env``.
_BASENAME_PREFIX = r"(?<![A-Za-z0-9_])"

#: ...and must not run into a longer word either. ``.`` and ``-`` are allowed
#: after, on purpose: ``id_rsa.pub``, ``.env.local`` and ``credentials-draft``
#: are all the sensitive thing, and the bare ``credentials`` this replaces
#: matched them. ``shadowsocks`` and ``credentials_backup`` do not match.
_BASENAME_SUFFIX = r"(?![A-Za-z0-9_])"


def basename_pattern(basename: str) -> str:
    """Regex source matching ``basename`` as a whole path component.

    The basename is escaped, so the YAML carries literals rather than regexes
    and a maintainer adding ``.docker/config.json`` cannot accidentally ship a
    metacharacter.
    """
    return _BASENAME_PREFIX + re.escape(basename) + _BASENAME_SUFFIX


def _alternation(fragments: list[str]) -> str:
    """Join into one non-capturing group.

    Non-capturing matters: ``${sensitive_path}`` is expanded *inside* existing
    rule regexes — AIRA-071 embeds it in an alternation branch followed by
    ``.{0,400}https?://`` — and a capturing group there would renumber every
    backreference in the host pattern.
    """
    return "(?:" + "|".join(fragments) + ")" if fragments else "(?!)"


@dataclass(frozen=True)
class PathList:
    """One named group of path patterns, plus optional literal basenames."""

    name: str
    patterns: tuple[str, ...]
    basenames: tuple[str, ...]

    @cached_property
    def fragment(self) -> str:
        """Regex *source* for this group — embeddable, never anchored.

        Cached because a plain ``property`` rebuilds it on every access, and the
        hot path reads it once per group per exec step. Measured: reassembling
        the 996-character ``sensitive`` fragment and re-hashing it for ``re``'s
        compile cache costs ~8 us. That is 1% of a match against a 4 kB command
        — and **ten times the entire cost** of a match against ``ls -la``, which
        is what real traffic mostly is, so it dominated the p50 rather than the
        tail. ``cached_property`` writes through ``__dict__`` rather than
        ``__setattr__``, so it works on a frozen dataclass.
        """
        return _alternation([*self.patterns, *(basename_pattern(b) for b in self.basenames)])

    @cached_property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.fragment, re.IGNORECASE)


@dataclass(frozen=True)
class SensitivePathRules:
    """The whole file, compiled."""

    version: int
    sensitive: PathList
    credential_store: PathList
    credential_bearing_config: PathList
    auth_store: PathList
    agent_config: PathList
    persistence: PathList
    reading_binaries: frozenset[str]
    shell_binaries: frozenset[str]
    interpreter_binaries: frozenset[str]
    fetch_binaries: frozenset[str]
    package_mgmt_binaries: frozenset[str]
    safe_exec_binaries: dict[str, tuple[str, ...]]
    unsafe_argv_flags: dict[str, tuple[str, ...]]

    def group(self, name: str) -> PathList:
        group = getattr(self, name, None)
        if not isinstance(group, PathList):
            raise KeyError(f"unknown path group {name!r}")
        return group


def _path_list(name: str, raw: dict[str, Any] | None) -> PathList:
    raw = raw or {}
    return PathList(
        name=name,
        patterns=tuple(str(p) for p in raw.get("patterns", ())),
        basenames=tuple(str(b) for b in raw.get("basenames", ())),
    )


def _composed(name: str, raw: dict[str, Any] | None, groups: dict[str, PathList]) -> PathList:
    """A group defined as the union of others, so no entry is written twice.

    `sensitive` is `credential_store | credential_bearing_config`. The two
    halves exist because they want different rule *authority* — a per-rule
    property, so they have to be separately nameable — while every consumer of
    `sensitive` (`fingerprint.path_class`, `signal_excerpt`,
    `exec_shape.path_roles`, `${sensitive_path}`) must go on seeing one list.

    Listing the union by hand instead would be the `# keep in sync` comment
    §1.3 was written to delete, one level up.
    """
    members = (raw or {}).get("includes")
    if not members:
        # Written flat, which stays valid: composition is an option, not a
        # requirement. `test_a_bad_pattern_fails_at_load_not_at_match` writes a
        # minimal flat file and must still fail on the *pattern*, not on a
        # missing key — a loader that raises `KeyError: 'includes'` there is
        # failing at load for the wrong reason, which is how a real bad pattern
        # would get misdiagnosed.
        return _path_list(name, raw)
    included = [groups[member] for member in members]
    return PathList(
        name=name,
        patterns=tuple(p for group in included for p in group.patterns),
        basenames=tuple(b for group in included for b in group.basenames),
    )


@lru_cache(maxsize=1)
def load_sensitive_paths(path: Path | None = None) -> SensitivePathRules:
    """Load and compile the canonical lists (cached)."""
    source = path or SENSITIVE_PATHS_PATH
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    leaves = {
        name: _path_list(name, raw.get(name))
        for name in (
            "credential_store",
            "credential_bearing_config",
            "auth_store",
            "agent_config",
            "persistence",
        )
    }
    rules = SensitivePathRules(
        version=int(raw["version"]),
        sensitive=_composed("sensitive", raw.get("sensitive"), leaves),
        credential_store=leaves["credential_store"],
        credential_bearing_config=leaves["credential_bearing_config"],
        auth_store=leaves["auth_store"],
        agent_config=leaves["agent_config"],
        persistence=leaves["persistence"],
        reading_binaries=frozenset(raw.get("reading_binaries", ())),
        shell_binaries=frozenset(raw.get("shell_binaries", ())),
        interpreter_binaries=frozenset(raw.get("interpreter_binaries", ())),
        fetch_binaries=frozenset(raw.get("fetch_binaries", ())),
        package_mgmt_binaries=frozenset(raw.get("package_mgmt_binaries", ())),
        safe_exec_binaries={
            family: tuple(heads) for family, heads in (raw.get("safe_exec_binaries") or {}).items()
        },
        unsafe_argv_flags={
            key: tuple(values) for key, values in (raw.get("unsafe_argv_flags") or {}).items()
        },
    )
    # Compile every group once here rather than lazily at first match: a bad
    # pattern must fail at load, not on the scan that happens to reach it (F20).
    for group in (
        rules.sensitive,
        rules.credential_store,
        rules.credential_bearing_config,
        rules.auth_store,
        rules.agent_config,
        rules.persistence,
    ):
        group.regex  # noqa: B018 - compilation is the point
    return rules


def sensitive_path_fragment() -> str:
    """Regex source for ``${sensitive_path}`` — see the compiler macro."""
    return load_sensitive_paths().sensitive.fragment


def sensitive_path_regex() -> re.Pattern[str]:
    return load_sensitive_paths().sensitive.regex


def unsafe_argv_fragment(flags: dict[str, tuple[str, ...]]) -> str:
    """Regex *source* matching any flag that redirects what a command acts on.

    Three shapes, because three spellings carry the same capability and a
    single alternation over the bare names would match the wrong things:

    * ``--files0-from`` — long flags, on a word boundary, so ``--file`` does
      not match inside ``--files0-from``'s own text but ``--file=x`` does.
    * ``-f`` — short flags, delimited on both sides, so ``-f`` does not match
      inside ``-force`` and ``--prefix`` does not match the ``-f`` branch.
    * ``-delete`` — find's action predicates, which look like long flags with
      one dash.

    Composed here rather than in each rule: the alternation is the safety
    property of eight fail-open rules, and §1.3 is the record of what happens
    when such a list is pasted into each of them.
    """
    parts: list[str] = []
    long_flags = flags.get("long", ())
    if long_flags:
        parts.append("--(?:" + "|".join(re.escape(f) for f in sorted(long_flags)) + r")\b")
    for entry in flags.get("scoped", ()):
        head = entry["head"] if isinstance(entry, dict) else entry[0]
        names = entry["flags"] if isinstance(entry, dict) else entry[1]
        # Head, then flag, with no command separator between them — the
        # proximity idiom, because distance is not the discriminator and a
        # separator is. `sed -n p && grep -i x` keeps working; `sed -i` does
        # not. 80 characters is enough for the flags of one simple command.
        parts.append(
            r"\b"
            + re.escape(head)
            + r"\b[^;&|\n]{0,80}?[\s]-[a-z]*(?:"
            + "|".join(re.escape(f) for f in sorted(names))
            + r")"
        )
    for entry in flags.get("verb_gated", ()):
        head = entry["head"] if isinstance(entry, dict) else entry[0]
        verbs = entry["verbs"] if isinstance(entry, dict) else entry[1]
        # "this head, not immediately followed by a read-only verb". A
        # negative lookahead over the whole command rather than an anchored
        # positive match at the start, because an anchored match reads only
        # the first segment and `git status && git push` would pass it.
        parts.append(
            r"\b" + re.escape(head) + r"\s+(?!(?:" + "|".join(re.escape(v) for v in verbs) + r")\b)"
        )

    actions = flags.get("find_actions", ())
    if actions:
        parts.append(
            r"(?:\A|[\s;&|])-(?:"
            + "|".join(re.escape(f) for f in sorted(actions, reverse=True))
            + r")\b"
        )
    return "(?:" + "|".join(parts) + ")"


def binary_alternation(names: Iterable[str]) -> str:
    """Regex *source* for a set of binary names — embeddable, never anchored.

    Sorted so the fragment is stable across runs (the YAML is a list, the model
    holds a frozenset), and escaped because a binary name may contain a `.` or
    a `+`. Non-capturing, so it can sit mid-pattern without renumbering groups.
    """
    return "(?:" + "|".join(re.escape(name) for name in sorted(names)) + ")"
