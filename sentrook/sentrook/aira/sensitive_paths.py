"""Compile the path groups of `lists/sensitive_paths.yaml` (ported from the 1.x sanitize loader).

One list, every consumer. In 1.x the sensitive-path list started as four hand-maintained regexes
that had already diverged; this module is what replaced them. Nothing downstream may hold a copy of
a pattern string: consumers bind to the compiled `PathList` objects, so adding an entry to the YAML
reaches all of them without a second edit.

A group is either a leaf (`patterns` and/or `basenames`) or composed (`includes` other groups), so
no entry is ever written twice. Every group is compiled at load: a bad pattern must fail at load,
not on the scan that happens to reach it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any

#: A basename is a path *component*, so it may be preceded by a separator, a quote, an `=`, a `-`
#: or nothing, but never by an alphanumeric that would make it part of a longer word. `myapp.env`
#: must not match `.env`.
_BASENAME_PREFIX = r"(?<![A-Za-z0-9_])"

#: ...and must not run into a longer word either. `.` and `-` are allowed after, on purpose:
#: `id_rsa.pub`, `.env.local` and `id_rsa-old` are all the sensitive thing. `id_rsa_backup` does
#: not match. Word basenames (`credentials`, `shadow`) are stricter, see `_WORD_SUFFIX`.
_BASENAME_SUFFIX = r"(?![A-Za-z0-9_])"

#: A *word* basename is also an ordinary word ("credentials", "shadow"), so in free text it counts only where it
#: reads as a file name: right after a path separator, a quote, one of `=@<>{,:` (`-d @credentials`, `< credentials`,
#: `{credentials,config}`, `host:credentials`), or at the very start, optionally with a leading dot (`.credentials`,
#: which may also follow a space). Prose ("the account credentials, not") and attribute access in code
#: (`self.credentials`) have none of these. A whole shell argument (`cat credentials`) is tested on its own, so it
#: starts the text (`path_classes.derive_path_roles`).
_WORD_PREFIX = r"(?:(?<=[/\\'\"`=@<>{,:])\.?|(?<=<\s)\.?|(?<![\s\S])\.?|(?<=\s)\.)"

#: ...and is the whole name or its stem: `credentials.json` and `credentials/` count, `credentials-guide.md` and
#: `credentials_backup` are other files.
_WORD_SUFFIX = r"(?![A-Za-z0-9_-])"

#: Keys that make a mapping in the YAML a path group.
GROUP_KEYS = frozenset({"patterns", "basenames", "words", "includes"})


def basename_pattern(basename: str) -> str:
    """Regex source matching `basename` as a whole path component.

    The basename is escaped, so the YAML carries literals rather than regexes and a maintainer
    adding `.docker/config.json` cannot accidentally ship a metacharacter.
    """
    return _BASENAME_PREFIX + re.escape(basename) + _BASENAME_SUFFIX


def word_pattern(word: str) -> str:
    """Regex source matching `word` as a file or directory name, not as a word in prose (`_WORD_PREFIX`)."""
    return _WORD_PREFIX + re.escape(word) + _WORD_SUFFIX


def _alternation(fragments: list[str]) -> str:
    """Join into one non-capturing group (embeddable inside a larger pattern without renumbering
    groups). An empty group compiles to a pattern that never matches."""
    return "(?:" + "|".join(fragments) + ")" if fragments else "(?!)"


@dataclass(frozen=True)
class PathList:
    """One named group of path patterns, plus optional literal basenames and word basenames."""

    name: str
    patterns: tuple[str, ...]
    basenames: tuple[str, ...]
    words: tuple[str, ...] = ()

    @cached_property
    def fragment(self) -> str:
        """Regex *source* for this group — embeddable, never anchored. Cached: the hot path reads it
        once per group per call, and reassembling a ~1 kB alternation costs more than matching
        `ls -la` against it."""
        return _alternation(
            [
                *self.patterns,
                *(basename_pattern(b) for b in self.basenames),
                *(word_pattern(w) for w in self.words),
            ]
        )

    @cached_property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.fragment, re.IGNORECASE)

    @property
    def empty(self) -> bool:
        return not self.patterns and not self.basenames and not self.words

    def search(self, subject: str) -> bool:
        return bool(self.regex.search(subject))


def is_group(value: Any) -> bool:
    return isinstance(value, dict) and bool(value) and set(value) <= GROUP_KEYS


def _leaf(name: str, raw: dict[str, Any]) -> PathList:
    return PathList(
        name=name,
        patterns=tuple(str(p) for p in raw.get("patterns") or ()),
        basenames=tuple(str(b) for b in raw.get("basenames") or ()),
        words=tuple(str(w) for w in raw.get("words") or ()),
    )


def compile_groups(raw: dict[str, Any]) -> dict[str, PathList]:
    """Every path group in a loaded list file, leaves first, then composed groups, in file order.

    Composition is resolved in dependency order so a composed group may include another composed
    one. A cycle or an unknown member is a load error.
    """
    groups: dict[str, PathList] = {}
    pending: dict[str, dict[str, Any]] = {}
    for name, value in raw.items():
        if not is_group(value):
            continue
        if value.get("includes"):
            pending[name] = value
        else:
            groups[name] = _leaf(name, value)

    guard = len(pending) + 1
    while pending and guard:
        guard -= 1
        for name in list(pending):
            members = [str(m) for m in pending[name]["includes"]]
            if all(m in groups for m in members):
                included = [groups[m] for m in members]
                own = _leaf(name, pending.pop(name))
                groups[name] = PathList(
                    name=name,
                    patterns=tuple(
                        dict.fromkeys([*own.patterns, *(p for g in included for p in g.patterns)])
                    ),
                    basenames=tuple(
                        dict.fromkeys([*own.basenames, *(b for g in included for b in g.basenames)])
                    ),
                    words=tuple(
                        dict.fromkeys([*own.words, *(w for g in included for w in g.words)])
                    ),
                )
    if pending:
        raise ValueError(f"path groups with unresolved includes: {sorted(pending)}")

    ordered = {name: groups[name] for name in raw if name in groups}
    for group in ordered.values():
        group.regex  # noqa: B018 - compilation at load is the point
    return ordered
