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
conversation the host's process reviewed. Built only when the request has the block. `selfedit-v2` is the same view with
the conversation's and the inputs' reads of the agent's own skill library marked `source: own_store` by the scanner
(`own_store.py`), so the questions can tell the store as it stands from content the agent read.

`trim-v4` adds `call-v5`: the call-v3 view whose `reputation` block also lists the call's unknown
entities that are near misses of a `known_good` one (`verdict: unknown`, `near_miss`: the entry). The
prepared state is call-v3's; only what the oracle fills in differs.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from ..jev.chunking import BUDGET_TOKENS, est_tokens
from .own_store import mark_own_store
from .redact import second_pass

VIEWS_VERSION = "trim-v1"
VIEWS_VERSION_V2 = "trim-v2"
VIEWS_VERSION_V3 = "trim-v3"
VIEWS_VERSION_V4 = "trim-v4"
VIEWS_VERSION_SELFEDIT = "selfedit-v1"
VIEWS_VERSION_SELFEDIT_V2 = "selfedit-v2"

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
SELFEDIT_V2 = "selfedit-v2"
#: The views for a declared self-edit; each is built only when the request has the `self_edit` block.
SELFEDIT_VIEWS = frozenset({SELFEDIT_V1, SELFEDIT_V2})
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
VIEW_KEYS[SELFEDIT_V2] = VIEW_KEYS[SELFEDIT_V1]
#: Views whose `reputation` block lists near misses as well as known verdicts.
NEAR_MISS_VIEWS = frozenset({CALL_V5, SELFEDIT_V1, SELFEDIT_V2})
#: Views version per view name.
VIEW_VERSIONS: dict[str, str] = {
    EXPOSURE: VIEWS_VERSION,
    CALL: VIEWS_VERSION,
    EXPOSURE_V2: VIEWS_VERSION_V2,
    CALL_V2: VIEWS_VERSION_V2,
    CALL_V3: VIEWS_VERSION_V3,
    CALL_V5: VIEWS_VERSION_V4,
    SELFEDIT_V1: VIEWS_VERSION_SELFEDIT,
    SELFEDIT_V2: VIEWS_VERSION_SELFEDIT_V2,
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
    SELFEDIT_V2: CALL,
}

#: call-v2 content caps. No suite fixture comes near them (the largest input is about 4.4k
#: characters); they bound production requests. An input cut by a cap carries `scanner_truncated`.
CALL_INPUT_CAP_CHARS = 6000
CALL_INPUTS_TOTAL_CAP_CHARS = 40_000
#: Room left in the chunking budget for the call questions, which repeat the preamble per question, when the
#: caller does not say which set it sends. It covers every shipped call set (a test pins it); the scanner sizes the
#: budget from the set it is configured with instead (`state_budget_tokens`).
CALL_QUESTIONS_RESERVE_TOKENS = 12_000
CALL_STATE_BUDGET_TOKENS = BUDGET_TOKENS - CALL_QUESTIONS_RESERVE_TOKENS


def state_budget_tokens(built_questions: dict[str, Any]) -> int:
    """The budget for a state sent with these built questions: what they leave of the chunking budget."""
    return BUDGET_TOKENS - est_tokens(built_questions)


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
    #: The view was still over the budget without any input content, so every content was emptied.
    inputs_stripped: bool = False
    #: History steps whose long arguments were cut, and oldest steps dropped, to fit the budget.
    history_cut: int = 0
    history_dropped: int = 0

    @property
    def history_trimmed(self) -> bool:
        return bool(self.history_cut or self.history_dropped)


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
        current = len(entry["content"])
        kept = min(current, per_input, remaining)
        remaining -= kept
        if kept < current:
            # an entry cut before keeps the size it arrived with
            _cut(entry, kept, _prior_cut(entry).get("of_chars", current))
            cut = True
    return cut


def strip_inputs(inputs: list[Any]) -> None:
    for entry in inputs:
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            continue
        of = _prior_cut(entry).get("of_chars", len(entry["content"]))
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
SELFEDIT_QUESTIONS_RESERVE_TOKENS = 15_000
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
    """While the view is over the budget, drop the oldest history step (the conversation carries the calls that
    matter, with their results), then the oldest tool entry, then the oldest assistant entry, and the owner's and
    other people's messages last; what was dropped is counted in `self_edit.scanner_dropped`. Mutates `v`."""
    block = v.get(SELF_EDIT)
    if not isinstance(block, dict) or not isinstance(block.get("conversation"), list):
        return False
    conv = block["conversation"]
    dropped: dict[str, int] = {}
    history = v.get("history")
    while isinstance(history, list) and history and est_tokens(v) > budget_tokens:
        history.pop(0)
        dropped["history"] = dropped.get("history", 0) + 1
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


#: Fitting an over-budget call view: a history step's argument strings longer than this keep only their head, and this
#: many of the most recent steps are kept (cut, not dropped) until the inputs have been fitted.
HISTORY_ARG_KEEP_CHARS = 400
HISTORY_KEEP_STEPS = 3


def _prior_cut(entry: dict[str, Any]) -> dict[str, Any]:
    prior = entry.get("scanner_truncated")
    return prior if isinstance(prior, dict) else {}


def _shorten(value: Any) -> tuple[Any, int, int]:
    """`value` with every string longer than `HISTORY_ARG_KEEP_CHARS` cut to its head, and the characters kept and
    the original length summed over the strings that were cut."""
    if isinstance(value, str):
        if len(value) > HISTORY_ARG_KEEP_CHARS:
            return value[:HISTORY_ARG_KEEP_CHARS], HISTORY_ARG_KEEP_CHARS, len(value)
        return value, 0, 0
    kept = of = 0
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, x in value.items():
            out[k], k_kept, k_of = _shorten(x)
            kept, of = kept + k_kept, of + k_of
        return out, kept, of
    if isinstance(value, list):
        items = []
        for x in value:
            y, k_kept, k_of = _shorten(x)
            items.append(y)
            kept, of = kept + k_kept, of + k_of
        return items, kept, of
    return value, 0, 0


def cut_history_arguments(v: dict[str, Any], budget_tokens: int) -> int:
    """While the view is over the budget, cut the long argument strings of its history steps, oldest step first (the
    step stays: tool, kind, decision and the strings' heads). A cut step carries `scanner_truncated`: the characters
    kept and the original length, over the strings cut. Mutates `v`; returns how many steps were cut."""
    history = v.get("history")
    if not isinstance(history, list):
        return 0
    cut = 0
    for step in history:
        if est_tokens(v) <= budget_tokens:
            break
        if not isinstance(step, dict) or "arguments" not in step:
            continue
        args, kept, of = _shorten(step["arguments"])
        if of:
            step["arguments"] = args
            step["scanner_truncated"] = {"kept_chars": kept, "of_chars": of}
            cut += 1
    return cut


def drop_history(v: dict[str, Any], budget_tokens: int, *, keep: int) -> int:
    """While the view is over the budget, drop its oldest history step, keeping at least the last `keep`. The earliest
    step left carries `scanner_dropped_earlier`, how many steps before it the scanner dropped (the plugin's own
    window may have left out more). Mutates `v`; returns how many steps were dropped."""
    history = v.get("history")
    if not isinstance(history, list):
        return 0
    dropped = 0
    while len(history) > keep and est_tokens(v) > budget_tokens:
        step = history.pop(0)
        dropped += 1
        # the dropped step's own marker counts the steps dropped before it
        earlier = step.get("scanner_dropped_earlier") if isinstance(step, dict) else None
        carried = 1 + (earlier if isinstance(earlier, int) else 0)
        # marked before the next size check, so the marker itself is inside the budget
        if history and isinstance(history[0], dict):
            history[0]["scanner_dropped_earlier"] = carried
    return dropped


def fill_inputs(v: dict[str, Any], capped: list[Any], budget_tokens: int) -> tuple[bool, bool]:
    """Set `v["new_inputs"]` to `capped` with the largest contents' total that fits the budget: the most recent inputs
    keep their content and the earliest lose theirs first, as with the total cap. Returns whether anything was cut
    and whether every content was emptied (the view does not fit even without them)."""
    total = sum(
        len(e["content"])
        for e in capped
        if isinstance(e, dict) and isinstance(e.get("content"), str)
    )

    def build(target: int) -> tuple[bool, bool]:
        inputs = copy.deepcopy(capped)
        cut = cap_inputs(inputs, total=target)
        v["new_inputs"] = inputs
        return cut, est_tokens(v) <= budget_tokens

    cut, fits = build(total)
    if fits:
        return cut, False
    cut, fits = build(0)
    if not fits:
        return cut, total > 0
    # the view's size grows with the total, so bisect for the largest total that fits
    lo, hi = 0, total
    while hi - lo > 1:
        mid = (lo + hi) // 2
        _, fits = build(mid)
        lo, hi = (mid, hi) if fits else (lo, mid)
    cut, _ = build(lo)
    return cut, lo == 0 and total > 0


@dataclass(frozen=True)
class _Fitted:
    inputs_cut: bool = False
    inputs_stripped: bool = False
    history_cut: int = 0
    history_dropped: int = 0


def _fit_call_view(v: dict[str, Any], budget_tokens: int) -> _Fitted:
    """Fit an over-budget call view, least useful first: the history steps' long arguments (oldest first), then the
    oldest steps (keeping the last `HISTORY_KEEP_STEPS`), then the inputs' content (the most recent kept longest),
    then the remaining steps, with the inputs refilled into any room that leaves. A view still over the budget with
    no input content and no history is sent as it is."""
    inputs = v.get("new_inputs")
    capped = copy.deepcopy(inputs) if isinstance(inputs, list) else None
    cut = stripped = False
    history_cut = cut_history_arguments(v, budget_tokens)
    dropped = drop_history(v, budget_tokens, keep=HISTORY_KEEP_STEPS)
    if capped is not None and est_tokens(v) > budget_tokens:
        cut, stripped = fill_inputs(v, capped, budget_tokens)
    if est_tokens(v) > budget_tokens:
        dropped += drop_history(v, budget_tokens, keep=0)
        if capped is not None:
            cut, stripped = fill_inputs(v, capped, budget_tokens)
    return _Fitted(cut, stripped, history_cut, dropped)


def _call_view_with_inputs(raw: dict[str, Any], name: str, *, budget_tokens: int) -> BuiltView:
    """A call view (or a self-edit view) with the turn's inputs, capped, fitted to the budget, then redacted. The
    self-edit views keep their own fitting: their conversation goes after the inputs."""
    v = view(trim(raw), name)
    if name == SELFEDIT_V2:
        mark_own_store(v)
    inputs = v.get("new_inputs")
    truncated = stripped = False
    fitted = _Fitted()
    if name not in SELFEDIT_VIEWS:
        if isinstance(inputs, list):
            truncated = cap_inputs(inputs)
        if est_tokens(v) > budget_tokens:
            fitted = _fit_call_view(v, budget_tokens)
            truncated = truncated or fitted.inputs_cut
            stripped = fitted.inputs_stripped
    else:
        truncated = cap_self_edit_entries(v)
        if isinstance(inputs, list):
            truncated = cap_inputs(inputs)
            if est_tokens(v) > budget_tokens:
                strip_inputs(inputs)
                truncated = stripped = True
        if fit_self_edit(v, budget_tokens):
            truncated = True
    state, count = second_pass(v)
    return BuiltView(
        state=state,
        redactions=count,
        inputs_truncated=truncated,
        inputs_stripped=stripped,
        history_cut=fitted.history_cut,
        history_dropped=fitted.history_dropped,
    )


def build_views(
    raw: dict[str, Any],
    *,
    exposure_input_seqs: set[int] | None,
    call_budget_tokens: int | None = None,
    selfedit_budget_tokens: int | None = None,
) -> dict[str, BuiltView]:
    """Every named view for one request: the frozen v1 views and the v2 views (cheap, always built).
    call-v5 is call-v3's prepared state; the reputation the oracle fills in is what differs. The call
    views (call-v2, call-v3, call-v5) are built to `call_budget_tokens` and the self-edit views (selfedit-v1,
    selfedit-v2) to `selfedit_budget_tokens`: the room the question set that sends them leaves, or the default
    reserves when not given."""
    call_budget = CALL_STATE_BUDGET_TOKENS if call_budget_tokens is None else call_budget_tokens
    v3 = call_view_v3(raw, budget_tokens=call_budget)
    out = {
        EXPOSURE: BuiltView(state=exposure_view(raw, only_input_seqs=exposure_input_seqs)),
        CALL: BuiltView(state=call_view(raw)),
        EXPOSURE_V2: exposure_view_v2(raw, only_input_seqs=exposure_input_seqs),
        CALL_V2: call_view_v2(raw, budget_tokens=call_budget),
        CALL_V3: v3,
        CALL_V5: v3,
    }
    if isinstance(raw.get(SELF_EDIT), dict):
        selfedit_budget = (
            SELFEDIT_STATE_BUDGET_TOKENS
            if selfedit_budget_tokens is None
            else selfedit_budget_tokens
        )
        for name in (SELFEDIT_V1, SELFEDIT_V2):
            out[name] = _call_view_with_inputs(raw, name, budget_tokens=selfedit_budget)
    return out
