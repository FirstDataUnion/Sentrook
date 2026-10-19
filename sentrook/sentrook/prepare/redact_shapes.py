"""The vendor key shapes of the second redaction pass, as data: `redact_shapes.yaml` beside this module.

Each shape is a regex for one vendor's key format (a fixed prefix and a fixed charset), with its
minimum match length, its source and the source's version. Most entries are generated from the
gitleaks default rules by `sentrook redact-shapes import` (`prepare.redact_import`); entries with
`source: sentrook` are kept by hand. The generic shapes (PEM, JWT, `Authorization: Bearer`,
assignment forms) stay in code in `prepare.redact`: they are the catch-all and never depend on the
import.

An operator can add shapes without a release: a `redact_shapes.yaml` with `version` and `shapes` in the
`SENTROOK_LISTS_DIR` overlay directory (the one the AIRA lists read) is appended to the base list, and
its version is appended to the reported shapes version as `+<version>`. Every regex is compiled at
load, so a bad entry fails at load and not on the scan that reaches it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

SHAPES_PATH = Path(__file__).with_name("redact_shapes.yaml")
OVERLAY_ENV = "SENTROOK_LISTS_DIR"
OVERLAY_NAME = "redact_shapes.yaml"

#: A shape matches only where no ASCII letter or digit comes right before it, so a prefix inside a
#: longer word (`disk-usage-…`, `task-…`) does not match.
WORD_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


@dataclass(frozen=True)
class Shape:
    name: str
    regex: str
    min_length: int
    source: str
    source_version: str
    compiled: re.Pattern[str]


@dataclass(frozen=True)
class Shapes:
    #: `<file version>;<upstream>=<tag>`, plus `+<overlay version>` when an overlay contributed.
    version: str
    shapes: tuple[Shape, ...]


def compile_shape(regex: str) -> re.Pattern[str]:
    """The shape's regex as is. The boundary is checked by `spans`, not by a look-behind in front:
    a pattern that starts with a literal lets the regex engine skip ahead to its prefix, which is
    several times faster over a long view."""
    return re.compile(regex)


def spans(rx: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    """Every match of a shape in `text` that has no letter or digit right before it."""
    out: list[tuple[int, int]] = []
    pos = 0
    while (m := rx.search(text, pos)) is not None:
        start, end = m.span()
        if start > 0 and text[start - 1] in WORD_CHARS:
            pos = start + 1
            continue
        if end > start:
            out.append((start, end))
        pos = max(end, start + 1)
    return out


def _shape(entry: Any, where: str) -> Shape:
    if not isinstance(entry, dict) or not entry.get("name") or not entry.get("regex"):
        raise ValueError(f"{where}: a shape needs `name` and `regex`")
    name, regex = str(entry["name"]), str(entry["regex"])
    try:
        compiled = compile_shape(regex)
    except re.error as exc:
        raise ValueError(f"{where}: {name}: bad regex: {exc}") from exc
    return Shape(
        name=name,
        regex=regex,
        min_length=int(entry.get("min_length", 0)),
        source=str(entry.get("source", "")),
        source_version=str(entry.get("source_version", "")),
        compiled=compiled,
    )


def read_file(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not isinstance(data.get("shapes", []), list):
        raise ValueError(f"{path}: a shapes file is a mapping with a `shapes` list")
    return data


def load_shapes_from(path: Path, overlay: Path | None = None) -> Shapes:
    data = read_file(path)
    shapes = [_shape(e, str(path)) for e in data.get("shapes") or ()]
    version = str(data.get("version", "0"))
    upstream = data.get("upstream") or {}
    if upstream.get("name") and upstream.get("tag"):
        version += f";{upstream['name']}={upstream['tag']}"
    over_path = overlay / OVERLAY_NAME if overlay is not None else None
    if over_path is not None and over_path.exists():
        over = read_file(over_path)
        names = {s.name for s in shapes}
        for entry in over.get("shapes") or ():
            shape = _shape(entry, str(over_path))
            if shape.name in names:
                raise ValueError(f"{over_path}: {shape.name}: already in the base list")
            names.add(shape.name)
            shapes.append(shape)
        version += f"+{over.get('version', '0')}"
    return Shapes(version=version, shapes=tuple(shapes))


@lru_cache(maxsize=4)
def _cached(overlay: str) -> Shapes:
    path = Path(overlay).expanduser() if overlay else None
    return load_shapes_from(SHAPES_PATH, path if path is not None and path.is_dir() else None)


def load_shapes() -> Shapes:
    """The compiled shapes, with the overlay from `SENTROOK_LISTS_DIR`; cached per overlay value."""
    return _cached(os.environ.get(OVERLAY_ENV, "").strip())


def clear_cache() -> None:
    _cached.cache_clear()


__all__ = [
    "OVERLAY_ENV",
    "SHAPES_PATH",
    "Shape",
    "Shapes",
    "clear_cache",
    "compile_shape",
    "load_shapes",
    "load_shapes_from",
    "read_file",
    "spans",
    "WORD_CHARS",
]
