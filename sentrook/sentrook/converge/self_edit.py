"""`Response.self_edit`: what a self-edit's saved content adds and whether the save qualifies for lenient handling.

Set only on a declared self-edit (the host's own background process saving to memory or skills). `adds` comes from
`prepare.save_adds`, read by rule from the saved text. `lenient` is true only when all of these hold:

- the save adds nothing, or only commands, and the reading can vouch for it (`SaveReading.held` is empty: the save
  removes nothing the request shows, every step it tells the agent to run passes every rule, the rules can read all
  of its code, and its target is inside the declared store);
- the scan's status is ok: a probe that failed or timed out, an entity lookup that fell back, or a fresh session
  state may have hidden a floor or a session judgement;
- the rule-based probe answered and no rule fired on the saved content: no finding on a saved skill step (or on any
  other call the probe read, but the pending save), and on the save itself only the write into the declared store;
- the entity lookup answered from a library (`available`): without one a known-bad package or host has no floor;
- the self-edit judge answered (its envelope is OK and carries every one of `LENIENT_ANSWERS` and
  `LENIENT_LEVEL_ANSWERS`), each of `LENIENT_ANSWERS` is below `LENIENT_ANSWER_LIMIT`, and so is the probability
  each of `LENIENT_LEVEL_ANSWERS` gives its counted levels (concealment: hidden intent);
- no floor applies to the scan (an enforced one, a guardrail, or one that only raises the score).

`lenient` says nothing about the verdict: a plugin that cannot ask anyone about a background save consults it only
when the risk lands in its review band, to let such a save through instead of holding it. It changes no score.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

from ..enums import ProbeStatus, ProbeStep, ScanStatus
from ..prepare.save_adds import STORE_REASONS, SaveReading
from ..probes.base import Envelope
from ..response.models import FloorApplied, SelfEditSave

#: The self-edit judge's yes/no answers that must each stay below `LENIENT_ANSWER_LIMIT` for a lenient save: a
#: directive taken from read content, loosened oversight, a claim about the owner no owner message shows, and a
#: secret value saved.
LENIENT_ANSWERS: tuple[str, ...] = (
    "untrusted_directive",
    "weakens_oversight",
    "unsupported_owner_claim",
    "persists_secret",
)
#: The self-edit judge's level answers, each with the level from which it counts against a lenient save
#: (concealment: 2, hidden intent): the probability of that level or above must stay below `LENIENT_ANSWER_LIMIT`.
LENIENT_LEVEL_ANSWERS: dict[str, int] = {"concealment": 2}
#: The probability (the judge's raw answer, before the question set's knee) at which one of `LENIENT_ANSWERS`, or the
#: counted levels of one of `LENIENT_LEVEL_ANSWERS`, rules out lenient handling.
LENIENT_ANSWER_LIMIT = 0.7
#: What a lenient save may add.
LENIENT_ADDS: frozenset[tuple[str, ...]] = frozenset({(), ("command",)})
#: On the save itself, the findings that are only the write into the declared store. A skill folder under the host's
#: agent directory is also classed as agent config by path; `save_adds.outside_store` keeps the target in the store.
_OWN_WRITE_REASONS = STORE_REASONS | {"selfmod.config"}


def _finite(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v)


def _at_or_above(answer: Any, level: int) -> float | None:
    """The probability a level answer gives `level` or above, or None when it carries no usable distribution."""
    probs = answer.get("probabilities") if isinstance(answer, dict) else None
    if not isinstance(probs, dict) or not probs:
        return None
    levels = {int(k): v for k, v in probs.items() if str(k).isdigit()}
    if not levels or not all(_finite(v) for v in levels.values()):
        return None
    return float(sum(v for k, v in levels.items() if k >= level))


def _answers_below_limit(envelopes: Iterable[Envelope]) -> bool:
    for env in envelopes:
        if env.step is not ProbeStep.JEV_CALL:
            continue
        if env.status is not ProbeStatus.OK:
            return False
        answers = env.evidence.get("answers")
        if not isinstance(answers, dict):
            return False
        for q in LENIENT_ANSWERS:
            a = answers.get(q)
            v = a.get("noul") if isinstance(a, dict) else None
            if not _finite(v) or v >= LENIENT_ANSWER_LIMIT:
                return False
        for q, level in LENIENT_LEVEL_ANSWERS.items():
            p = _at_or_above(answers.get(q), level)
            if p is None or p >= LENIENT_ANSWER_LIMIT:
                return False
        return True
    return False


def _rules_quiet(
    envelopes: Iterable[Envelope], pending_label: str | None, *, exec_save: bool
) -> bool:
    """The rule-based probe answered, and fired on nothing but the save's own write into the declared store."""
    for env in envelopes:
        if env.step is not ProbeStep.AIRA:
            continue
        if env.status is not ProbeStatus.OK:
            return False
        for f in env.evidence.get("findings", []):
            if not isinstance(f, dict):
                return False
            if f.get("counted") is False:
                continue  # a sibling's own finding, scanned as its own call
            if f.get("call_id") != pending_label:
                return False  # a saved skill step, a resolved or written file
            reason = f.get("reason")
            if reason not in _OWN_WRITE_REASONS:
                return False
            if reason == "selfmod.config" and (
                exec_save or f.get("mechanism") in ("cli", "tool_name")
            ):
                return False  # a config command or tool, not a path in the store
        return True
    return False


def _oracle_answered(envelopes: Iterable[Envelope]) -> bool:
    for env in envelopes:
        if env.step is ProbeStep.ENTITY_ORACLE:
            return (
                env.status is ProbeStatus.OK
                and env.evidence.get("available") is not False
                and not env.evidence.get("fallback")
            )
    return False


def _no_probe_failed(envelopes: Iterable[Envelope]) -> bool:
    """No probe failed, timed out or fell back (the scan's status says the same; checked here too, on the envelopes
    this field reads)."""
    return not any(
        env.status in (ProbeStatus.ERROR, ProbeStatus.TIMEOUT) or env.evidence.get("fallback")
        for env in envelopes
    )


def self_edit_save(
    reading: SaveReading,
    envelopes: Iterable[Envelope],
    floors: Iterable[FloorApplied],
    *,
    status: ScanStatus,
    pending_label: str | None,
    exec_save: bool = False,
) -> SelfEditSave:
    kinds = tuple(sorted(set(reading.adds)))
    envelopes = list(envelopes)
    lenient = (
        kinds in LENIENT_ADDS
        and not reading.held
        and status is ScanStatus.OK
        and _no_probe_failed(envelopes)
        and not any(True for _ in floors)
        and _rules_quiet(envelopes, pending_label, exec_save=exec_save)
        and _oracle_answered(envelopes)
        and _answers_below_limit(envelopes)
    )
    return SelfEditSave(adds=list(kinds), lenient=lenient)
