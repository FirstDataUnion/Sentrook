"""The convergence parameter set: every tunable number in one versioned JSON file
under `converge/params/`, named in `metadata.versions.convergence`. The oracle and context probe
tables live here too (`oracle`, `context` sections override the probes' dataclass defaults)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from ..probes.context import ContextParams
from ..probes.oracle import OracleParams

PARAMS_DIR = Path(__file__).resolve().parent / "params"


@dataclass(frozen=True)
class ConvergenceParams:
    name: str = "conv-v1"
    u: float = 0.25
    certainty: str = (
        "mean"  # informational: the Jev call probe computes the mean; "min" is kept for tuning
    )
    consequence: str = "max"  # max | mean
    taint_floor: float = 0.3
    agreement_high: float = 0.6
    agreement_low: float = 0.3
    coverage_penalty: dict[str, float] = field(
        default_factory=lambda: {"error": 0.5, "timeout": 0.6, "skipped": 1.0}
    )
    request_named_relief: bool = True
    request_named_owner_only: bool = True
    request_named_roles: tuple[str, ...] = ("data_destination", "recipient")
    reason_min_value: float = 0.2
    oracle: OracleParams = field(default_factory=OracleParams)
    context: ContextParams = field(default_factory=ContextParams)
    jev_taint_threshold: float = 0.5


def _override(dc, section: dict[str, Any]):
    known = {f.name for f in fields(dc)}
    return replace(dc, **{k: v for k, v in section.items() if k in known})


def load_params(name: str | Path = "conv-v1") -> ConvergenceParams:
    path = Path(name)
    if path.suffix != ".json" or not path.exists():
        path = PARAMS_DIR / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    agreement = raw.get("agreement") or {}
    rnr = raw.get("request_named_relief") or {}
    oracle = _override(OracleParams(name=f"{raw['name']}/oracle"), raw.get("oracle") or {})
    context = _override(ContextParams(name=f"{raw['name']}/context"), raw.get("context") or {})
    return ConvergenceParams(
        name=raw["name"],
        u=float(raw.get("u", 0.25)),
        certainty=str(raw.get("certainty", "mean")),
        consequence=str(raw.get("consequence", "max")),
        taint_floor=float(raw.get("taint_floor", 0.3)),
        agreement_high=float(agreement.get("high", 0.6)),
        agreement_low=float(agreement.get("low", 0.3)),
        coverage_penalty={
            **{"error": 0.5, "timeout": 0.6, "skipped": 1.0},
            **(raw.get("coverage_penalty") or {}),
        },
        request_named_relief=bool(rnr.get("enabled", True)),
        request_named_owner_only=bool(rnr.get("owner_only", True)),
        request_named_roles=tuple(rnr.get("roles") or ("data_destination", "recipient")),
        reason_min_value=float(raw.get("reason_min_value", 0.2)),
        oracle=oracle,
        context=context,
        jev_taint_threshold=float((raw.get("jev") or {}).get("taint_threshold", 0.5)),
    )
