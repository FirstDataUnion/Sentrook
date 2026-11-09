"""Steering markers in untrusted content, as data: `steering.yaml` beside this module.

An untrusted input steers the agent when it speaks to the agent as an AI (rather than to whoever reads
a document) or asks it to keep something from the owner. Preparation marks every host named in such an
input as steered and keeps the mark in the state token, so it holds on later steps; AIRA floors a
command that fetches code from a steered host and runs it. Plain instructions in a document (a setup
file, a ticket, a skill's prerequisites) carry no marker, so code run from them stays scored.

Every regex is compiled at load, so a bad entry fails at load and not on the scan that reaches it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

STEERING_PATH = Path(__file__).with_name("steering.yaml")


@dataclass(frozen=True)
class Markers:
    version: str
    families: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...]


@lru_cache(maxsize=1)
def load_markers() -> Markers:
    data = yaml.safe_load(STEERING_PATH.read_text(encoding="utf-8")) or {}
    families = tuple(
        (str(name), tuple(re.compile(p, re.IGNORECASE) for p in patterns or ()))
        for name, patterns in (data.get("families") or {}).items()
    )
    return Markers(version=str(data.get("version", "0")), families=families)


def steering_marks(text: str) -> list[str]:
    """The marker families `text` matches, in list order; empty for plain content."""
    if not text:
        return []
    return [
        name for name, patterns in load_markers().families if any(p.search(text) for p in patterns)
    ]


__all__ = ["STEERING_PATH", "Markers", "load_markers", "steering_marks"]
