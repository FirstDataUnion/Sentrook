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
    #: The taint floor when the request brings new untrusted content but no exposure judgement came back (the probe
    #: failed, timed out or did not run): nobody looked at that content. None: `taint_floor`.
    taint_floor_unjudged: float | None = None
    agreement_high: float = 0.6
    agreement_low: float = 0.3
    coverage_penalty: dict[str, float] = field(
        default_factory=lambda: {"error": 0.5, "timeout": 0.6, "skipped": 1.0}
    )
    request_named_relief: bool = True
    request_named_owner_only: bool = True
    request_named_roles: tuple[str, ...] = ("data_destination", "recipient")
    #: Host-generated trigger kinds (`scheduled`, `heartbeat`, `subagent`) whose task text names a destination
    #: the way an owner's request does. Empty: owner turns only.
    request_named_trigger_kinds: tuple[str, ...] = ()
    #: A `known_good` oracle verdict on a destination or recipient relieves it like a grant.
    known_good_relief: bool = True
    #: Known-good relief also for a destination that content the agent read supplied, when the library
    #: match is exact, this scan's exposure is below the taint threshold and the session is not tainted.
    known_good_content_relief: bool = False
    #: A destination or recipient the owner's own configuration supplied on an earlier scan (the token's trusted
    #: set) is relieved of the library's distrust.
    owner_config_relief: bool = False
    #: In an attended owner session (a message turn from the owner, on the main agent, not in a group chat), set the
    #: response's verdict ceiling to review unless the call carries an independent strong signal (`converge.attended`).
    #: The `relaxable` mark comes from the same check and the settings below in every parameter set, on or off.
    attended_owner_cap: bool = False
    #: A key argument's untrusted origin, as scaled by its role, that counts as a strong signal.
    attended_owner_untrusted_origin_min: float = 0.6
    #: The sensitivity of a source a send carries that counts as sensitive data leaving.
    attended_owner_sent_sensitivity_min: float = 0.6
    #: A look-alike of a vouched-for entry or of a host, package or person the owner named is a strong signal;
    attended_owner_lookalike: bool = True
    #: so is a retry of an action the owner denied, at or above this value (None: not a strong signal);
    attended_owner_retry_min: float | None = 0.8
    #: and, off unless set, this request's new untrusted content judged to instruct the agent (exposure at or
    #: above the first value) while the call is judged not to follow from the owner's request (misalignment at or above the second).
    attended_owner_injection_exposure_min: float | None = None
    attended_owner_injection_misalignment_min: float = 0.0
    #: The credential-home relief (`prepare.credential_home`): a key read from the agent's env file and sent only to
    #: the provider API host the entity library lists for its name is not charged as sensitive data sent.
    credential_home: bool = False
    #: With the relief, the model's call-level sensitivity is held to this value: the level below credentials (the
    #: call question sets' "personal or business data", 2 of 3), since the credential no longer counts.
    credential_home_model_sensitivity_cap: float = 2 / 3
    #: With the relief, also relieve the provider host's distrust and untrusted origin (off by default).
    credential_home_relieve_host: bool = False
    reason_min_value: float = 0.2
    oracle: OracleParams = field(default_factory=OracleParams)
    context: ContextParams = field(default_factory=ContextParams)
    jev_taint_threshold: float = 0.5


def _override(dc, section: dict[str, Any]):
    """The section's known keys replace the dataclass defaults (a dict value replaces the whole dict, so a file
    lists every key of it). A JSON list becomes a tuple, the type of every list-valued parameter."""
    known = {f.name for f in fields(dc)}
    return replace(
        dc,
        **{k: tuple(v) if isinstance(v, list) else v for k, v in section.items() if k in known},
    )


def load_params(name: str | Path = "conv-v1") -> ConvergenceParams:
    path = Path(name)
    if path.suffix != ".json" or not path.exists():
        path = PARAMS_DIR / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    agreement = raw.get("agreement") or {}
    rnr = raw.get("request_named_relief") or {}
    kgr = raw.get("known_good_relief") or {}
    ocr = raw.get("owner_config_relief") or {}
    aoc = raw.get("attended_owner_cap") or {}
    chr_ = raw.get("credential_home") or {}
    oracle = _override(OracleParams(name=f"{raw['name']}/oracle"), raw.get("oracle") or {})
    context_section = dict(raw.get("context") or {})
    lineage = context_section.pop("lineage", None)
    if isinstance(lineage, dict):  # `context.lineage.<key>` sets `ContextParams.lineage_<key>`
        context_section.update({f"lineage_{k}": v for k, v in lineage.items()})
    context = _override(ContextParams(name=f"{raw['name']}/context"), context_section)
    return ConvergenceParams(
        name=raw["name"],
        u=float(raw.get("u", 0.25)),
        certainty=str(raw.get("certainty", "mean")),
        consequence=str(raw.get("consequence", "max")),
        taint_floor=float(raw.get("taint_floor", 0.3)),
        taint_floor_unjudged=(
            None if raw.get("taint_floor_unjudged") is None else float(raw["taint_floor_unjudged"])
        ),
        agreement_high=float(agreement.get("high", 0.6)),
        agreement_low=float(agreement.get("low", 0.3)),
        coverage_penalty={
            **{"error": 0.5, "timeout": 0.6, "skipped": 1.0},
            **(raw.get("coverage_penalty") or {}),
        },
        request_named_relief=bool(rnr.get("enabled", True)),
        request_named_owner_only=bool(rnr.get("owner_only", True)),
        request_named_roles=tuple(rnr.get("roles") or ("data_destination", "recipient")),
        request_named_trigger_kinds=tuple(rnr.get("trigger_kinds") or ()),
        known_good_relief=bool(kgr.get("enabled", True)),
        known_good_content_relief=bool(kgr.get("content_destinations", False)),
        owner_config_relief=bool(ocr.get("enabled", False)),
        attended_owner_cap=bool(aoc.get("enabled", False)),
        attended_owner_untrusted_origin_min=float(aoc.get("untrusted_origin_min", 0.6)),
        attended_owner_sent_sensitivity_min=float(aoc.get("sent_sensitivity_min", 0.6)),
        attended_owner_lookalike=bool(aoc.get("lookalike", True)),
        attended_owner_retry_min=(
            None if aoc.get("retry_min", 0.8) is None else float(aoc.get("retry_min", 0.8))
        ),
        attended_owner_injection_exposure_min=(
            None
            if (aoc.get("fresh_injection") or {}).get("exposure_min") is None
            else float(aoc["fresh_injection"]["exposure_min"])
        ),
        attended_owner_injection_misalignment_min=float(
            (aoc.get("fresh_injection") or {}).get("misalignment_min", 0.0)
        ),
        credential_home=bool(chr_.get("enabled", False)),
        credential_home_model_sensitivity_cap=float(chr_.get("model_sensitivity_cap", 2 / 3)),
        credential_home_relieve_host=bool(chr_.get("relieve_host", False)),
        reason_min_value=float(raw.get("reason_min_value", 0.2)),
        oracle=oracle,
        context=context,
        jev_taint_threshold=float((raw.get("jev") or {}).get("taint_threshold", 0.5)),
    )
