"""Near misses of what the owner named: a package or a person one edit away from a name in the request.

A look-alike host is already checked against the hosts the owner named. The same slip, or the same trick,
happens with the other names an owner gives: the package to install and the people to pay or write to.
These helpers only compare text; the context probe decides what a match is worth.

- `package_lookalike`: the package the call installs is not a word of the request, but is one edit (or one
  confusable character) away from one. Names of five characters or more only, and the registry's own
  spelling rule first: `-`, `_` and `.` runs are the same name, not a look-alike.
- `name_lookalikes`: a person's name is read as two capitalised words side by side (`Maren Solt`). A pair
  in the text the call acts on is a look-alike when one word equals the owner's and the other is one edit
  or one confusable away, and the owner's request does not hold that pair itself. A single word, or a
  request written without capitals, gives nothing to compare; a word that differs only by a final `s`
  is a plural, not a look-alike, since a capitalised pair is as often a title as a person.
"""

from __future__ import annotations

import re

from ..oracle.near_miss import edit_distance_le1, fold

_ECOSYSTEMS = ("pypi", "npm", "cargo", "gem", "go", "docker", "brew", "apt", "nuget", "composer")
_VERSION_RE = re.compile(r"(?:@[^@/:\s]+|[=<>~!]=?[^\s]*)$")
_WORD_RE = re.compile(r"@?[a-z0-9][a-z0-9._/-]*[a-z0-9]")
_NAME_WORD_RE = re.compile(r"[^\W\d_]+(?:['’-][^\W\d_]+)*")
#: The shortest package name compared, and the shortest word of a person's name that may differ.
MIN_PACKAGE = 5
MIN_NAME_WORD = 4


def package_name(value: str) -> str:
    """The name a person types: no ecosystem prefix, no version (`pypi:acme-hooks==1.2` -> `acme-hooks`,
    `npm:@acme/hooks@2.0.1` -> `@acme/hooks`)."""
    name = value.strip().lower()
    head, sep, rest = name.partition(":")
    if sep and head in _ECOSYSTEMS:
        name = rest
    return (
        _VERSION_RE.sub("", name)
        if not name.startswith("@")
        else "@" + _VERSION_RE.sub("", name[1:])
    )


def _same_package(a: str, b: str) -> bool:
    return re.sub(r"[-_.]+", "-", a) == re.sub(r"[-_.]+", "-", b)


def package_lookalike(value: str, request_words: str) -> str | None:
    """The word of the request the package `value` imitates, or None. None when the request holds the
    package's own name."""
    name = package_name(value)
    if len(name) < MIN_PACKAGE:
        return None
    words = {w.strip("./-") for w in _WORD_RE.findall((request_words or "").lower())}
    if any(_same_package(name, w) for w in words):
        return None
    for word in sorted(words):
        if len(word) < MIN_PACKAGE:
            continue
        if edit_distance_le1(name, word) or fold(name) == fold(word):
            return word
    return None


def name_pairs(text: str, *, capitalised: bool = True) -> set[tuple[str, str]]:
    """Two words side by side on one line, lower-cased; with `capitalised`, both start with a capital."""
    out: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        prev: re.Match[str] | None = None
        for m in _NAME_WORD_RE.finditer(line):
            word = m.group(0)
            ok = word[0].isupper() or not capitalised
            if (
                ok
                and prev is not None
                and line[prev.end() : m.start()].strip(" \t") == ""
                and m.start() > prev.end()
            ):
                out.add((prev.group(0).lower(), word.lower()))
            prev = m if ok else None
    return out


def _near(a: str, b: str) -> bool:
    if a == b or min(len(a), len(b)) < MIN_NAME_WORD:
        return False
    if a + "s" == b or b + "s" == a:
        return False  # a plural of an ordinary capitalised phrase (`Sales Report`, `Sales Reports`)
    return edit_distance_le1(a, b) or fold(a) == fold(b)


def name_lookalikes(
    request_words: str, text: str, *, capitalised: bool = True
) -> list[tuple[str, str]]:
    """(look-alike, the name the owner gave) for each pair of words in `text` that is one edit away from
    a name in the request and is not itself in the request."""
    named = name_pairs(request_words)
    if not named:
        return []
    request = " ".join((request_words or "").lower().split())
    out: list[tuple[str, str]] = []
    for first, last in sorted(name_pairs(text, capitalised=capitalised)):
        if (first, last) in named or f"{first} {last}" in request:
            continue
        for n_first, n_last in sorted(named):
            if (first == n_first and _near(last, n_last)) or (
                last == n_last and _near(first, n_first)
            ):
                out.append((f"{first} {last}", f"{n_first} {n_last}"))
                break
    return out
