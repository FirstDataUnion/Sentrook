"""The AIRA data lists: versioned YAML under this directory, plus an optional operator overlay.

Rules are code, knowledge is data. Every list-like thing a detector reads lives
here: path groups, binary names, verb maps, egress markers, installer shapes, weights. The loader:

- reads each `<name>.yaml` in `LIST_NAMES`;
- if the environment variable `SENTROOK_LISTS_DIR` names a directory (or `overlay=` is passed), reads
  the same file names from it and merges them **additively** — lists are appended (deduplicated),
  mappings are merged recursively, scalars (weights) are overridden;
- compiles every regex at load, so a bad pattern fails at load and not on the scan that reaches it;
- builds the combined `version` string that the probe reports as `versions["ruleset"]`:
  `name=version` per list, joined with `;`, with `+<overlay version>` appended where an overlay
  file contributed.
"""

from __future__ import annotations

import copy
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..sensitive_paths import PathList, compile_groups

LISTS_DIR = Path(__file__).parent
OVERLAY_ENV = "SENTROOK_LISTS_DIR"
LIST_NAMES: tuple[str, ...] = (
    "sensitive_paths",
    "guardrail",
    "destructive",
    "remote_destructive",
    "privilege",
    "egress",
    "installers",
    "selfmod",
    "extent",
    "lineage",
    "weights",
)

#: Binary-name lists in `sensitive_paths.yaml` exposed as frozensets.
BINARY_LISTS: tuple[str, ...] = (
    "reading_binaries",
    "listing_binaries",
    "shell_binaries",
    "interpreter_binaries",
    "fetch_binaries",
    "package_mgmt_binaries",
)


@dataclass(frozen=True)
class Rule:
    """One entry of a list of `{pattern: …, reason: …, …}` mappings, compiled."""

    regex: re.Pattern[str]
    data: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


@dataclass(frozen=True)
class Lists:
    version: str
    raw: dict[str, dict[str, Any]]
    path_groups: dict[str, PathList]
    binaries: dict[str, frozenset[str]]
    _patterns: dict[tuple[str, str], tuple[re.Pattern[str], ...]] = field(repr=False)
    _rules: dict[tuple[str, str], tuple[Rule, ...]] = field(repr=False)

    # ----------------------------------------------------------------- access

    def get(self, name: str, *path: str, default: Any = None) -> Any:
        """A value from list `name` by dotted key path, e.g. `get("weights", "code", "reach")`."""
        node: Any = self.raw.get(name, {})
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def strings(self, name: str, *path: str) -> tuple[str, ...]:
        value = self.get(name, *path, default=())
        return tuple(str(v) for v in value) if isinstance(value, list | tuple) else ()

    def weight(self, *path: str, default: float = 0.0) -> float:
        value = self.get("weights", *path, default=default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def patterns(self, name: str, *path: str) -> tuple[re.Pattern[str], ...]:
        """Compiled regexes of a `*_patterns` (or `patterns`) list."""
        return self._patterns.get((name, ".".join(path)), ())

    def rules(self, name: str, *path: str) -> tuple[Rule, ...]:
        """Compiled entries of a list of mappings carrying `pattern`."""
        return self._rules.get((name, ".".join(path)), ())

    def group(self, name: str) -> PathList:
        group = self.path_groups.get(name)
        if group is None:
            return PathList(name=name, patterns=(), basenames=())
        return group

    def binary_set(self, name: str) -> frozenset[str]:
        return self.binaries.get(name, frozenset())

    def search_any(self, name: str, *path: str, subject: str) -> re.Match[str] | None:
        for rx in self.patterns(name, *path):
            m = rx.search(subject)
            if m:
                return m
        return None


# --------------------------------------------------------------------------- loading


def _merge(base: Any, overlay: Any) -> Any:
    """Additive merge: mappings recurse, lists append (deduplicated), scalars are overridden."""
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = dict(base)
        for key, value in overlay.items():
            out[key] = _merge(base[key], value) if key in base else copy.deepcopy(value)
        return out
    if isinstance(base, list) and isinstance(overlay, list):
        out_list = list(base)
        for item in overlay:
            if item not in out_list:
                out_list.append(copy.deepcopy(item))
        return out_list
    return copy.deepcopy(overlay)


def _read(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: a list file must be a mapping")
    return data


def _walk(node: Any, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, (*prefix, str(key)))
    else:
        yield prefix, node


def _compile_all(
    raw: dict[str, dict[str, Any]],
) -> tuple[
    dict[tuple[str, str], tuple[re.Pattern[str], ...]], dict[tuple[str, str], tuple[Rule, ...]]
]:
    patterns: dict[tuple[str, str], tuple[re.Pattern[str], ...]] = {}
    rules: dict[tuple[str, str], tuple[Rule, ...]] = {}
    for name, data in raw.items():
        for path, value in _walk(data):
            if not path or not isinstance(value, list) or not value:
                continue
            key = (name, ".".join(path))
            last = path[-1]
            if all(isinstance(v, str) for v in value) and (
                last == "patterns" or last.endswith("_patterns")
            ):
                try:
                    patterns[key] = tuple(re.compile(v, re.IGNORECASE) for v in value)
                except re.error as exc:
                    raise ValueError(f"{name}.{'.'.join(path)}: bad pattern: {exc}") from exc
            elif all(isinstance(v, dict) and "pattern" in v for v in value):
                try:
                    rules[key] = tuple(
                        Rule(re.compile(str(v["pattern"]), re.IGNORECASE), dict(v)) for v in value
                    )
                except re.error as exc:
                    raise ValueError(f"{name}.{'.'.join(path)}: bad pattern: {exc}") from exc
    return patterns, rules


def _version_of(data: dict[str, Any]) -> str:
    return str(data.get("version", "0"))


def load_lists_from(base_dir: Path, overlay: Path | None) -> Lists:
    """Load (and compile) the lists from `base_dir`, merging `overlay` when given."""
    raw: dict[str, dict[str, Any]] = {}
    versions: list[str] = []
    for name in LIST_NAMES:
        base_path = base_dir / f"{name}.yaml"
        data = _read(base_path) if base_path.exists() else {}
        version = _version_of(data)
        if overlay is not None:
            over_path = overlay / f"{name}.yaml"
            if over_path.exists():
                over = _read(over_path)
                over_version = _version_of(over)
                over.pop("version", None)
                data = _merge(data, over)
                version = f"{version}+{over_version}"
        raw[name] = data
        versions.append(f"{name}={version}")

    path_groups = compile_groups(raw.get("sensitive_paths", {}))
    binaries = {
        key: frozenset(str(b).lower() for b in raw.get("sensitive_paths", {}).get(key) or ())
        for key in BINARY_LISTS
    }
    patterns, rules = _compile_all(raw)
    return Lists(
        version=";".join(versions),
        raw=raw,
        path_groups=path_groups,
        binaries=binaries,
        _patterns=patterns,
        _rules=rules,
    )


def overlay_dir() -> Path | None:
    value = os.environ.get(OVERLAY_ENV, "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_dir() else None


@lru_cache(maxsize=4)
def _cached(overlay: str | None) -> Lists:
    return load_lists_from(LISTS_DIR, Path(overlay) if overlay else None)


def load_lists(overlay: Path | str | None | ellipsis = ...) -> Lists:  # noqa: F821
    """The compiled lists, cached per overlay directory. With no argument the overlay comes from
    `SENTROOK_LISTS_DIR`; pass `None` to force the base lists only."""
    if overlay is ...:
        over = overlay_dir()
    else:
        over = Path(overlay).expanduser() if overlay else None
    return _cached(str(over.resolve()) if over else None)


def clear_cache() -> None:
    _cached.cache_clear()


__all__ = [
    "BINARY_LISTS",
    "LISTS_DIR",
    "LIST_NAMES",
    "OVERLAY_ENV",
    "Lists",
    "Rule",
    "clear_cache",
    "load_lists",
    "load_lists_from",
    "overlay_dir",
]
