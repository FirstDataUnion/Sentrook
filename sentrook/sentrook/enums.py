"""Enumerations shared across the pipeline, and the tolerant-enum base every wire enum uses.

Forward compatibility (skeleton, Conventions): unknown enum values are tolerated and treated as the
enum's fallback member (`other` or `unknown`), never rejected. Additive fields never bump the major
version. `TolerantStrEnum` implements that: a subclass names its fallback in `__fallback__`, and any
value outside the member set validates to it. The exported JSON Schemas still list the known values,
so a fixture linter can be strict while the scanner stays tolerant.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class TolerantStrEnum(StrEnum):
    """A `StrEnum` whose unknown values resolve to a declared fallback member."""

    __fallback__: str

    @classmethod
    def _missing_(cls, value: Any):  # noqa: ANN206 (enum protocol)
        fallback = getattr(cls, "__fallback__", None)
        if fallback is None:
            return None
        if isinstance(value, str):
            lowered = value.strip().lower()
            for member in cls:
                if member.value == lowered:
                    return member
        return cls._value2member_map_[fallback]  # type: ignore[return-value]


class Enforce(StrEnum):
    """Minimum outcome a floor guarantees whatever the plugin's thresholds are."""

    BLOCK = "block"
    REVIEW = "review"


class ProbeStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


class ScanStatus(StrEnum):
    """`ok`: every enabled probe returned. `degraded`: a probe failed or coverage dropped, but a score
    was computed. `error`: no usable score (preparation failed)."""

    OK = "ok"
    DEGRADED = "degraded"
    ERROR = "error"


class SessionFlag(StrEnum):
    """Sticky per-session flags, read by the context probe at the start of a step and written only at
    the end of convergence from probes' `flags_set`."""

    TAINTED = "tainted"
    HOLDS_SENSITIVE = "holds_sensitive"
    ESCALATING = "escalating"


class ProbeStep(StrEnum):
    """The five probes. Also the keys of `SENTROOK_PROBES` (the ablation switch)."""

    JEV_EXPOSURE = "jev_exposure"
    JEV_CALL = "jev_call"
    AIRA = "aira"
    ENTITY_ORACLE = "entity_oracle"
    CONTEXT = "context"
