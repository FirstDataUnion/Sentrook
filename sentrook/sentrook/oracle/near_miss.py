"""Near misses: an entity the library does not list that is one slip away from one it vouches for.

The oracle answers the exact lookup first. When nothing matches, it reports the nearest `known_good` entry
the queried value could be mistaken for, and how the two differ (`how`, nearest first):
- `tld`: a host with the same registrable label under another suffix (`cindervale.io` for `cindervale.net`);
- `fold`: equal once hyphens, dots and underscores are dropped and confusable characters folded together
  (`rn`/`m`, `vv`/`w`, `0`/`o`, `1`/`l`, `i`/`l`, `3`/`e`, `5`/`s`): `fern-mere` for `fernmere`;
- `edit`: one insertion, deletion or substitution apart (`brindlfen` for `brindlefen`).

What is compared, per kind:
- a host: its registrable label (`reports.cindervale.net` → `cindervale`). A host under the same registrable
  domain as a listed one is that party, never a near miss;
- a package, MCP server or plugin: its name without a version, within one ecosystem (`npm:`, `pypi:`). The
  same name at another version is that party, and so is a container image under another tag or digest
  (`docker:node:22` for `docker:node:20`) or a PyPI project spelt with other separators (`Python_Dateutil`);
- an email recipient: its domain, by the host rule, against listed addresses with the same local part;
  any other recipient (a handle) whole.
Labels and names shorter than five characters never match: too many short names are one edit apart.
Roles are ignored: a value that imitates a vouched-for entity is suspicious in whatever role it appears.

Rookery's oracle implements the same rule; the two share a test table.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MIN_LENGTH = 5
#: `how`, nearest first.
HOWS = ("tld", "fold", "edit")
NAME_KINDS = ("package", "mcp_server", "plugin")

CONFUSABLES = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("i", "l"),
    ("3", "e"),
    ("5", "s"),
)
_TLDS_2 = frozenset({"co", "com", "org", "net", "ac", "gov", "edu"})
_VERSION_RE = re.compile(r"@[^@/:\s]+$")
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]+$")
_ECOSYSTEM_RE = re.compile(r"^([a-z][a-z0-9]{0,15}):(?!//)")


def fold(text: str) -> str:
    """`text` with hyphens, dots and underscores dropped and confusable characters folded together."""
    out = re.sub(r"[-._]", "", text.lower())
    for a, b in CONFUSABLES:
        out = out.replace(a, b)
    return out


def edit_distance_le1(a: str, b: str) -> bool:
    """`a` and `b` are at most one insertion, deletion or substitution apart."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(a) - i) + (len(b) - j) <= 1


def registrable(host: str) -> tuple[str, str]:
    """The label a person reads as the brand and the registrable domain it sits in:
    `get.docker.com` → (`docker`, `docker.com`), `foo.co.uk` → (`foo`, `foo.co.uk`)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in _TLDS_2 and len(parts[-1]) == 2:
        return parts[-3], ".".join(parts[-3:])
    if len(parts) >= 2:
        return parts[-2], ".".join(parts[-2:])
    return parts[0], parts[0]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _differ(a: str, b: str) -> str | None:
    if fold(a) == fold(b):
        return "fold"
    if edit_distance_le1(a, b):
        return "edit"
    return None


def _host_how(query: str, listed: str) -> str | None:
    """None, `same` (the listed party itself) or how `query` imitates `listed`."""
    if _is_ip(query) or _is_ip(listed):
        return None
    q_label, q_domain = registrable(query)
    l_label, l_domain = registrable(listed)
    if q_domain == l_domain:
        return "same"
    if min(len(q_label), len(l_label)) < MIN_LENGTH:
        return None
    if q_label == l_label:
        return "tld"
    return _differ(q_label, l_label)


def _name(value: str) -> tuple[str, str] | None:
    """(ecosystem, name without version) of a package, MCP server or plugin; None for a URL."""
    if "://" in value:
        return None
    m = _ECOSYSTEM_RE.match(value)
    eco, rest = (m.group(1), value[m.end() :]) if m else ("", value)
    if eco == "docker":
        # `[registry[:port]/]path[:tag][@sha256:digest]`: the tag sits after the last `/`.
        rest = _DIGEST_RE.sub("", rest)
        head, slash, last = rest.rpartition("/")
        return eco, head + slash + last.split(":", 1)[0]
    name = _VERSION_RE.sub("", rest) or rest
    if eco == "pypi":
        name = re.sub(r"[-_.]+", "-", name)  # PyPI's own name comparison
    return eco, name


def _name_how(query: str, listed: str) -> str | None:
    q, entry = _name(query), _name(listed)
    if q is None or entry is None or q[0] != entry[0]:
        return None
    if q[1] == entry[1]:
        return "same"
    bare = (q[1].rsplit("/", 1)[-1], entry[1].rsplit("/", 1)[-1])
    if min(len(b) for b in bare) < MIN_LENGTH:
        return None
    return _differ(q[1], entry[1])


def _email(value: str) -> tuple[str, str] | None:
    local, at, domain = value.rpartition("@")
    return (local, domain) if at and local and domain else None


def _recipient_how(query: str, listed: str) -> str | None:
    q, entry = _email(query), _email(listed)
    if q is not None or entry is not None:
        if q is None or entry is None or q[0] != entry[0]:
            return None
        return _host_how(q[1], entry[1])
    if min(len(fold(query)), len(fold(listed))) < MIN_LENGTH:
        return None
    return _differ(query, listed)


def how_near(kind: str, query: str, listed: str) -> str | None:
    """How the normalised `query` imitates the normalised `listed` entry of the same kind: one of `HOWS`,
    `same` when it is that party (a subdomain, another version), or None."""
    if query == listed:
        return "same"
    if kind == "host":
        return _host_how(query, listed)
    if kind in NAME_KINDS:
        return _name_how(query, listed)
    if kind == "recipient":
        return _recipient_how(query, listed)
    return None


def near_miss_of(kind: str, query: str, listed: Iterable[str]) -> tuple[str, str] | None:
    """The `known_good` entry (normalised values, same kind) nearest to `query`, as (entry, how), or None.
    None too when `query` is one of the listed parties (a subdomain of a listed host, a listed package at
    another version). Ties go to the alphabetically first entry, so the answer is stable."""
    best: tuple[int, str, str] | None = None
    for entry in listed:
        how = how_near(kind, query, entry)
        if how is None:
            continue
        if how == "same":
            return None
        rank = (HOWS.index(how), entry, how)
        if best is None or rank < best:
            best = rank
    return (best[1], best[2]) if best else None
