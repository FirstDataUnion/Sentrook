"""Jev state views: what each Jev probe is sent.

v1 reproduces the TestNest runner's `trim-v1` **byte for byte** (Rookery `testnest/jev/prepare.py`),
working on the raw request JSON rather than the parsed model, so every Jev call made during the first
full-suite run replays from the committed cache and the Jev-only versus pipeline comparison differs
only by the other layers. Canonicalised arguments, the second redaction pass and any change to what Jev
sees are a deliberate v1.1 cache invalidation, versioned here.

`trim` drops ids, the state token, `options` and the plugin's echo of earlier Sentrook scores
(`history[].risk`, `tiers`, `action_fingerprint`), which a model must not get to see. `view` selects the
keys one question group sees: exposure questions see the request and new inputs; call questions see the
request, pending call, history arguments, grants and trigger.

The v1.1 question-set pass adds a second views version, `trim-v2`, beside the frozen v1 views (which stay byte for
byte as they are): `call-v2` adds the turn's `new_inputs` between `history` and `pending_call`, so a
question can weigh a listing or a read before a bulk or publishing call, with per-input and total
content caps; `exposure-v2` has the `exposure` keys. Both v2 views end with the scanner's second
redaction pass (`redact`).

`trim-v3` adds `call-v3`: the call-v2 view plus a `reputation` block after `grants` holding the
entity library's `known_good` and `known_bad` verdicts for the call's own hosts, recipients and
packages. The block is filled by the call probe from the oracle probe's result (the scan runs the
oracle first when the call view asks for it), and is absent when nothing is known.

`selfedit-v1` is the view for a declared self-edit (the host's own background save to memory or skills): the call-v5
view without `request` (a self-edit has no owner request of its own) and with the `self_edit` block, which carries the
conversation the host's process reviewed. Built only when the request has the block.

`trim-v4` adds `call-v5`: the call-v3 view whose `reputation` block also lists the call's unknown
entities that are near misses of a `known_good` one (`verdict: unknown`, `near_miss`: the entry). The
prepared state is call-v3's; only what the oracle fills in differs.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from ..jev.chunking import BUDGET_TOKENS, est_tokens
from .redact import second_pass

VIEWS_VERSION = "trim-v1"
VIEWS_VERSION_V2 = "trim-v2"
VIEWS_VERSION_V3 = "trim-v3"
VIEWS_VERSION_V4 = "trim-v4"
VIEWS_VERSION_SELFEDIT = "selfedit-v1"

STRIP_TOP = frozenset({"request_id", "run_ref", "sent_at", "scan_kind", "origin", "options"})
SESSION_KEEP = ("agent_ref", "agent_role", "turn", "step")
STRIP_HISTORY = frozenset({"request_id", "action_fingerprint", "risk", "tiers", "call_id"})
STRIP_NEW_INPUT = frozenset({"call_id"})
STRIP_PENDING_CALL = frozenset({"call_id", "host_call_id", "batch"})

EXPOSURE = "exposure"
CALL = "call"
EXPOSURE_V2 = "exposure-v2"
CALL_V2 = "call-v2"
CALL_V3 = "call-v3"
CALL_V5 = "call-v5"
SELFEDIT_V1 = "selfedit-v1"
SELF_EDIT = "self_edit"
#: The call-v3 block of entity-library verdicts, added by the call probe once the oracle has run.
REPUTATION = "reputation"
VIEW_KEYS: dict[str, tuple[str, ...]] = {
    EXPOSURE: ("planir_version", "host", "trigger", "request", "new_inputs"),
    CALL: (
        "planir_version",
        "host",
        "session",
        "trigger",
        "request",
        "history",
        "pending_call",
        "grants",
    ),
    EXPOSURE_V2: ("planir_version", "host", "trigger", "request", "new_inputs"),
    CALL_V2: (
        "planir_version",
        "host",
        "session",
        "trigger",
        "request",
        "history",
        "new_inputs",
        "pending_call",
        "grants",
    ),
    CALL_V3: (
        "planir_version",
        "host",
        "session",
        "trigger",
        "request",
        "history",
        "new_inputs",
        "pending_call",
        "grants",
        REPUTATION,
    ),
}
VIEW_KEYS[CALL_V5] = VIEW_KEYS[CALL_V3]
VIEW_KEYS[SELFEDIT_V1] = (
    "planir_version",
    "host",
    "session",
    "trigger",
    SELF_EDIT,
    "history",
    "new_inputs",
    "pending_call",
    "grants",
    REPUTATION,
)
#: Views whose `reputation` block lists near misses as well as known verdicts.
NEAR_MISS_VIEWS = frozenset({CALL_V5, SELFEDIT_V1})
#: Views version per view name.
VIEW_VERSIONS: dict[str, str] = {
    EXPOSURE: VIEWS_VERSION,
    CALL: VIEWS_VERSION,
    EXPOSURE_V2: VIEWS_VERSION_V2,
    CALL_V2: VIEWS_VERSION_V2,
    CALL_V3: VIEWS_VERSION_V3,
    CALL_V5: VIEWS_VERSION_V4,
    SELFEDIT_V1: VIEWS_VERSION_SELFEDIT,
}
#: Which probe a view serves.
VIEW_KIND: dict[str, str] = {
    EXPOSURE: EXPOSURE,
    EXPOSURE_V2: EXPOSURE,
    CALL: CALL,
    CALL_V2: CALL,
    CALL_V3: CALL,
    CALL_V5: CALL,
    SELFEDIT_V1: CALL,
}

#: call-v2 content caps. No suite fixture comes near them (the largest input is about 4.4k
#: characters); they bound production requests. An input cut by a cap carries `scanner_truncated`.
CALL_INPUT_CAP_CHARS = 6000
CALL_INPUTS_TOTAL_CAP_CHARS = 40_000
#: Room left in the chunking budget for the call questions, which repeat the preamble per question
#: (`est_tokens` of the built call-v2 questions is about 7.2k).
CALL_QUESTIONS_RESERVE_TOKENS = 7500
CALL_STATE_BUDGET_TOKENS = BUDGET_TOKENS - CALL_QUESTIONS_RESERVE_TOKENS


def trim(raw: dict[str, Any]) -> dict[str, Any]:
    """The PlanIR as a Jev probe sees it. Never mutates `raw`."""
    st = {k: copy.deepcopy(v) for k, v in raw.items() if k not in STRIP_TOP}
    if isinstance(st.get("session"), dict):
        st["session"] = {k: st["session"][k] for k in SESSION_KEEP if k in st["session"]}
    for h in st.get("history") or []:
        if isinstance(h, dict):
            for k in STRIP_HISTORY:
                h.pop(k, None)
    for n in st.get("new_inputs") or []:
        if isinstance(n, dict):
            for k in STRIP_NEW_INPUT:
                n.pop(k, None)
    pc = st.get("pending_call")
    if isinstance(pc, dict):
        for k in STRIP_PENDING_CALL:
            pc.pop(k, None)
    return st


def view(trimmed: dict[str, Any], name: str) -> dict[str, Any]:
    if name not in VIEW_KEYS:
        raise KeyError(f"unknown view {name!r}; known: {list(VIEW_KEYS)}")
    return {k: trimmed[k] for k in VIEW_KEYS[name] if k in trimmed}


def exposure_view(
    raw: dict[str, Any], *, only_input_seqs: set[int] | None = None
) -> dict[str, Any]:
    """The exposure view. With `only_input_seqs`, inputs already scanned (at or below the token's
    highest `input_seq`) are dropped; v1 passes every input the plugin sent, matching the runner."""
    v = view(trim(raw), EXPOSURE)
    if only_input_seqs is not None:
        v["new_inputs"] = [
            n for n in v.get("new_inputs") or [] if n.get("input_seq") in only_input_seqs
        ]
    return v


def call_view(raw: dict[str, Any]) -> dict[str, Any]:
    return view(trim(raw), CALL)


@dataclass(frozen=True)
class BuiltView:
    """A v2 view and what building it did."""

    state: dict[str, Any]
    redactions: int = 0
    #: At least one `new_inputs` content was cut by a cap.
    inputs_truncated: bool = False
    #: The view was still over the budget after the caps, so every content was emptied.
    inputs_stripped: bool = False


def _cut(entry: dict[str, Any], kept: int, of: int) -> None:
    entry["content"] = entry["content"][:kept]
    entry["scanner_truncated"] = {"kept_chars": kept, "of_chars": of}


def cap_inputs(
    inputs: list[Any],
    *,
    per_input: int = CALL_INPUT_CAP_CHARS,
    total: int = CALL_INPUTS_TOTAL_CAP_CHARS,
) -> bool:
    """Cap each string `content` at `per_input` characters (head kept), then the sum at `total`:
    the most recent inputs (highest `input_seq`, such as the listing right before the pending call)
    keep their content and the earliest lose theirs first; metadata always stays. Entries without an
    integer `input_seq` count as earliest; ties keep list order. Mutates the entries; returns whether
    anything was cut."""
    entries = [
        (i, e)
        for i, e in enumerate(inputs)
        if isinstance(e, dict) and isinstance(e.get("content"), str)
    ]

    def recency(item: tuple[int, dict[str, Any]]) -> tuple[bool, int, int]:
        i, e = item
        seq = e.get("input_seq")
        has_seq = isinstance(seq, int) and not isinstance(seq, bool)
        return (has_seq, seq if has_seq else 0, i)

    cut = False
    remaining = total
    for _, entry in sorted(entries, key=recency, reverse=True):
        of = len(entry["content"])
        kept = min(of, per_input, remaining)
        remaining -= kept
        if kept < of:
            _cut(entry, kept, of)
            cut = True
    return cut


def strip_inputs(inputs: list[Any]) -> None:
    for entry in inputs:
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            continue
        prior = entry.get("scanner_truncated") or {}
        of = prior.get("of_chars", len(entry["content"]))
        _cut(entry, 0, of)


def exposure_view_v2(raw: dict[str, Any], *, only_input_seqs: set[int] | None = None) -> BuiltView:
    v = view(trim(raw), EXPOSURE_V2)
    if only_input_seqs is not None:
        v["new_inputs"] = [
            n for n in v.get("new_inputs") or [] if n.get("input_seq") in only_input_seqs
        ]
    state, count = second_pass(v)
    return BuiltView(state=state, redactions=count)


def call_view_v2(
    raw: dict[str, Any], *, budget_tokens: int = CALL_STATE_BUDGET_TOKENS
) -> BuiltView:
    """The call view plus the turn's inputs, capped, then redacted. If the capped view is still over
    the budget, every input keeps its metadata and loses its content."""
    return _call_view_with_inputs(raw, CALL_V2, budget_tokens=budget_tokens)


def call_view_v3(
    raw: dict[str, Any], *, budget_tokens: int = CALL_STATE_BUDGET_TOKENS
) -> BuiltView:
    """The call-v2 view, which the call probe completes with `reputation` (the entity library's
    `known_good` and `known_bad` verdicts for the call's hosts, recipients and packages, from the
    oracle probe) once that probe has run; see `with_reputation`. The raw request carries no such
    key, so the prepared view has none."""
    return _call_view_with_inputs(raw, CALL_V3, budget_tokens=budget_tokens)


def with_reputation(state: dict[str, Any], verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """A copy of a call-v3 state with the `reputation` block appended after `grants`; with no
    known verdicts the key is absent, so the model's default (nothing vouched for) applies and the
    request body is the same as it would be without an oracle."""
    out = dict(state)
    out.pop(REPUTATION, None)
    if verdicts:
        out[REPUTATION] = [dict(v) for v in verdicts]
    return out


#: Self-edit view caps: characters per conversation entry (the plugin sends less; this is the scanner's own bound), and
#: the room left for the self-edit questions, which repeat a longer preamble than the call questions.
SELF_EDIT_ENTRY_CAP_CHARS = 4000
SELFEDIT_QUESTIONS_RESERVE_TOKENS = 14_000
SELFEDIT_STATE_BUDGET_TOKENS = BUDGET_TOKENS - SELFEDIT_QUESTIONS_RESERVE_TOKENS


def cap_self_edit_entries(v: dict[str, Any]) -> bool:
    """Cap each self-edit conversation entry's text or content at `SELF_EDIT_ENTRY_CAP_CHARS`. Mutates `v`."""
    block = v.get(SELF_EDIT)
    if not isinstance(block, dict) or not isinstance(block.get("conversation"), list):
        return False
    conv = [e for e in block["conversation"] if isinstance(e, dict)]
    cut = len(conv) != len(block["conversation"])
    for e in conv:
        for key in ("text", "content"):
            if isinstance(e.get(key), str) and len(e[key]) > SELF_EDIT_ENTRY_CAP_CHARS:
                e[key] = e[key][:SELF_EDIT_ENTRY_CAP_CHARS]
                e["scanner_truncated"] = True
                cut = True
    block["conversation"] = conv
    return cut


def fit_self_edit(v: dict[str, Any], budget_tokens: int) -> bool:
    """While the view is over the budget, drop the oldest tool entry, then the oldest assistant entry, then the oldest
    user entry; what was dropped is counted in `self_edit.scanner_dropped`. Mutates `v`."""
    block = v.get(SELF_EDIT)
    if not isinstance(block, dict) or not isinstance(block.get("conversation"), list):
        return False
    conv = block["conversation"]
    dropped: dict[str, int] = {}
    for role in ("tool", "assistant", "user"):
        while est_tokens(v) > budget_tokens:
            idx = next((i for i, e in enumerate(conv) if e.get("role") == role), None)
            if idx is None:
                break
            del conv[idx]
            dropped[role] = dropped.get(role, 0) + 1
    if dropped:
        block["scanner_dropped"] = dropped
    return bool(dropped)


def cap_self_edit(v: dict[str, Any], budget_tokens: int) -> bool:
    """Both bounds: entries capped, then the conversation fitted to the budget."""
    capped = cap_self_edit_entries(v)
    return fit_self_edit(v, budget_tokens) or capped


def _call_view_with_inputs(
    raw: dict[str, Any], name: str, *, budget_tokens: int = CALL_STATE_BUDGET_TOKENS
) -> BuiltView:
    v = view(trim(raw), name)
    inputs = v.get("new_inputs")
    truncated = stripped = False
    if name == SELFEDIT_V1:
        budget_tokens = min(budget_tokens, SELFEDIT_STATE_BUDGET_TOKENS)
        truncated = cap_self_edit_entries(v)
    if isinstance(inputs, list):
        truncated = cap_inputs(inputs)
        if est_tokens(v) > budget_tokens:
            strip_inputs(inputs)
            truncated = stripped = True
    if name == SELFEDIT_V1 and fit_self_edit(v, budget_tokens):
        truncated = True
    state, count = second_pass(v)
    return BuiltView(
        state=state, redactions=count, inputs_truncated=truncated, inputs_stripped=stripped
    )


def build_views(
    raw: dict[str, Any], *, exposure_input_seqs: set[int] | None
) -> dict[str, BuiltView]:
    """Every named view for one request: the frozen v1 views and the v2 views (cheap, always built).
    call-v5 is call-v3's prepared state; the reputation the oracle fills in is what differs."""
    v3 = call_view_v3(raw)
    out = {
        EXPOSURE: BuiltView(state=exposure_view(raw, only_input_seqs=exposure_input_seqs)),
        CALL: BuiltView(state=call_view(raw)),
        EXPOSURE_V2: exposure_view_v2(raw, only_input_seqs=exposure_input_seqs),
        CALL_V2: call_view_v2(raw),
        CALL_V3: v3,
        CALL_V5: v3,
    }
    if isinstance(raw.get(SELF_EDIT), dict):
        out[SELFEDIT_V1] = _call_view_with_inputs(raw, SELFEDIT_V1)
    return out
