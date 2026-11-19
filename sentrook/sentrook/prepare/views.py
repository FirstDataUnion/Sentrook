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

`trim-v5` changes `call-v5` only: an input cut by a cap or by the over-budget fill keeps two thirds head and one third
tail with a marker between them, as the plugins cut inputs, instead of the head alone. When nothing is cut the
prepared state is still call-v3's.

`trim-v6` changes `call-v5` only: an over-budget view cuts the request text first, to `REQUEST_KEEP_CHARS`, head and
tail, before any history or input is cut.

`trim-v7` changes `call-v5` only: the over-budget fill sends an input whole whenever the room allows it whole, instead
of settling on a slightly smaller total that cuts it (a whole input carries no marker and no record, so it can take
less room than the same input cut by a few characters).

`trim-v9` adds `call-v7`: the call-v5 view whose `pending_call` keeps a `batch` block when the agent issued other
calls in the same step. `batch.siblings` lists those calls (tool, kind, provider and arguments, redacted, then long
values cut head and tail, so a cut never splits a secret), and the call probe adds `batch.resolved`: the pending command as it runs once the files those siblings write
are read into it (`sibling_join`), so the judge sees the value a `$(cat file)` or a config read actually supplies. The
block has a size: lists, objects and nesting in a sibling's values are bounded, the siblings and the resolved commands
each fit a character cap, and the trailing ones left out are counted (`siblings_omitted`, `resolved_omitted`); the view
is fitted leaving room for `resolved`, which the probe adds after the fit. Its
`reputation` block also lists the call's destinations that the owner's own configuration supplied (`verdict:
owner_config`). A request with no batch and no such entity gives the call-v5 state unchanged.

`trim-v8` changes `call-v5` only: a cut never splits a secret. Each cut point moves out of anything the second
redaction pass would replace, with the context that identifies it (`redact.protected_spans`), so a secret is kept
whole, and replaced, or cut away whole; `kept_chars` reports what was really kept.

What the call probe adds after the fit has a bound, and its room is kept free: the `reputation` block holds at most
`REPUTATION_MAX_ENTRIES` entries within `REPUTATION_CAP_CHARS` (known_bad kept first, then near misses, then
known_good, then owner_config; the rest counted in `reputation_omitted`), and every view that carries the block is
fitted to its budget less `REPUTATION_RESERVE_TOKENS`. A view the second redaction pass grows past its budget (a
placeholder is longer than a short secret) is fitted again to a budget smaller by the growth. A view with room to
spare is unchanged: the budgets are sizing, not part of the views version.
"""

from __future__ import annotations

import copy
import functools
import math
import re
from dataclasses import dataclass
from typing import Any

from ..jev.chunking import BUDGET_TOKENS, CHARS_PER_TOKEN, est_tokens
from ..jev.questions import QuestionSet, canonical_json
from .own_store import mark_own_store
from .redact import protected_spans, redact_text, second_pass, secret_spans

VIEWS_VERSION = "trim-v1"
VIEWS_VERSION_V2 = "trim-v2"
VIEWS_VERSION_V3 = "trim-v3"
VIEWS_VERSION_V8 = "trim-v8"
VIEWS_VERSION_V9 = "trim-v9"
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
CALL_V7 = "call-v7"
SELFEDIT_V1 = "selfedit-v1"
SELFEDIT_V2 = "selfedit-v2"
#: The views for a declared self-edit; each is built only when the request has the `self_edit` block.
SELFEDIT_VIEWS = frozenset({SELFEDIT_V1, SELFEDIT_V2})
SELF_EDIT = "self_edit"
#: The call-v3 block of entity-library verdicts, added by the call probe once the oracle has run.
REPUTATION = "reputation"
#: How many entries the block left out when it was capped; absent when nothing was.
REPUTATION_OMITTED = "reputation_omitted"
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
VIEW_KEYS[CALL_V7] = VIEW_KEYS[CALL_V3]
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
NEAR_MISS_VIEWS = frozenset({CALL_V5, CALL_V7, SELFEDIT_V1, SELFEDIT_V2})
#: Views whose cut inputs keep head and tail (two thirds head, one third tail, a marker between), as the plugins cut
#: them, so the end of a long page or file still reaches the judge. The other views keep the head, as before.
HEAD_TAIL_VIEWS = frozenset({CALL_V5, CALL_V7})
#: Views whose fitting cuts a long request text first, head and tail, when the view is over the budget. The other views
#: never cut the request.
REQUEST_FIT_VIEWS = frozenset({CALL_V5, CALL_V7})
#: Views version per view name.
VIEW_VERSIONS: dict[str, str] = {
    EXPOSURE: VIEWS_VERSION,
    CALL: VIEWS_VERSION,
    EXPOSURE_V2: VIEWS_VERSION_V2,
    CALL_V2: VIEWS_VERSION_V2,
    CALL_V3: VIEWS_VERSION_V3,
    CALL_V5: VIEWS_VERSION_V8,
    CALL_V7: VIEWS_VERSION_V9,
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
    CALL_V7: CALL,
    SELFEDIT_V1: CALL,
    SELFEDIT_V2: CALL,
}

#: Views whose `pending_call` keeps the batch: the calls issued in the same step, and (from the call probe) the
#: pending command resolved through what they write.
BATCH_VIEWS = frozenset({CALL_V7})
#: Views whose `reputation` block lists the destinations the owner's own configuration supplied.
OWNER_CONFIG_VIEWS = frozenset({CALL_V7})
#: A sibling's argument value longer than this is cut, head and tail; at most this many siblings are listed.
BATCH_ARG_CAP_CHARS = 1500
BATCH_MAX_SIBLINGS = 8
#: Bounds on what one sibling's values can hold: items kept per list, keys per object, and how deep lists and objects
#: nest before the rest is replaced by a marker.
BATCH_MAX_ITEMS = 20
BATCH_MAX_DEPTH = 4
#: A sibling that does not fit the room left is tried once more with these tighter bounds before it is left out.
BATCH_ARG_SHORT_CHARS = 200
BATCH_SHORT_ITEMS = 5
#: The listed siblings, and the resolved commands, as serialised JSON, stay within these: the trailing ones that do
#: not fit are left out and counted (`siblings_omitted`, `resolved_omitted`), so the judge knows the batch is partial.
#: The call view is fitted to its budget less the room `resolved` can take, since the probe adds it afterwards.
BATCH_SIBLINGS_CAP_CHARS = 6000
BATCH_RESOLVED_CAP_CHARS = 2000
BATCH_RESOLVED_RESERVE_TOKENS = math.ceil((BATCH_RESOLVED_CAP_CHARS + 64) / CHARS_PER_TOKEN)
BATCH = "batch"
SIBLING_KEEP = ("tool", "tool_kind", "provider", "arguments")

#: call-v2 content caps. No suite fixture comes near them (the largest input is about 4.4k
#: characters); they bound production requests. An input cut by a cap carries `scanner_truncated`.
CALL_INPUT_CAP_CHARS = 6000
CALL_INPUTS_TOTAL_CAP_CHARS = 40_000
#: Room left in the chunking budget for the call questions (with their preamble or preamble blocks) when the
#: caller does not say which set it sends. It covers every shipped call set (a test pins it); the scanner sizes the
#: budget from the set it is configured with instead (`set_state_budget_tokens`).
CALL_QUESTIONS_RESERVE_TOKENS = 12_000
CALL_STATE_BUDGET_TOKENS = BUDGET_TOKENS - CALL_QUESTIONS_RESERVE_TOKENS


#: The token cost of a shipped question set as the model counts it: the questions plus Jev's own prompt. Measured on
#: uncached TestNest bodies as the intercept of `usage.input_tokens` fitted against the state's size (call-v6: 816
#: bodies, 7,004; call-v7: 1,172 bodies, 11,125; selfedit-v3: 24 bodies, 8,770), rounded up to the next 100. The
#: questions are prose and cost far less than their estimate at 2.5 characters per token (11,476, 19,094 and 14,812).
#: Keyed by the set's name and the first 12 characters of its sha, so a set edited since it was measured falls back to
#: its estimate until measured again. call-v7's key was moved by hand to its sha after a one-clause preamble edit (the
#: batch named as content being judged, about 20 tokens), which the rounding up covers.
#: A set built from blocks sends more or fewer of them depending on the state, so its entry is its largest form, the one
#: `built_questions()` gives with no state. call-v8, measured on 2,490 uncached bodies by the state's blocks: neither
#: conditional block 5,757 (2,125 bodies), reputation only 6,280 (283), batch only 8,105 (79), both 8,612 (3); its
#: entry is the largest form rounded up. In characters of questions JSON the four forms are 23,769, 25,908, 34,713
#: and 36,852.
MEASURED_QUESTION_TOKENS: dict[tuple[str, str], int] = {
    ("call-v6", "9d3bd2610d35"): 7_100,
    ("call-v7", "5832e69408d9"): 11_200,
    ("call-v8", "d8a11ad2bb37"): 8_700,
    ("selfedit-v3", "82c8686c5607"): 8_800,
}
#: The longest answer measured from the call and self-edit sets, in tokens; a test keeps it inside the context.
MEASURED_OUTPUT_TOKENS = 255
#: The densest a large state has measured (characters per token, states over 8,000 characters, rounded down from
#: 2.45) and the largest residual of the fits above, in tokens. A test checks that a state at its full budget at this
#: rate still fits the context with its set's measured cost and the longest answer. The margin is smaller than with
#: estimated reserves: a full-budget call-v6 state reaches the context only if denser than about 2.09 characters per
#: token (before, about 1.64), which dense base64, hex or non-Latin text can be.
MEASURED_DENSEST_STATE_CHARS_PER_TOKEN = 2.4
MEASURED_STATE_RESIDUAL_TOKENS = 750


def state_budget_tokens(built_questions: dict[str, Any]) -> int:
    """The budget for a state sent with these built questions, estimated from their characters: what they leave of
    the chunking budget."""
    return BUDGET_TOKENS - est_tokens(built_questions)


def question_reserve_tokens(qs: QuestionSet) -> int:
    """The room a set's questions take: its measured cost when it has one at its current sha, otherwise the estimate
    from its characters. The state is still estimated at 2.5 characters per token. For a set whose questions depend
    on the state (blocks sent only with a batch or a reputation block), both are for its largest form."""
    measured = MEASURED_QUESTION_TOKENS.get((qs.name, qs.sha[:12]))
    return measured if measured is not None else est_tokens(qs.built_questions())


def set_state_budget_tokens(qs: QuestionSet) -> int:
    """The budget for a state sent with this set: what its questions leave of the chunking budget."""
    return BUDGET_TOKENS - question_reserve_tokens(qs)


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


#: A placeholder the redactors left (`⟦secret:…⟧`): a cut moves out of one rather than split it.
_PLACEHOLDER_RE = re.compile(r"⟦[^⟦⟧]{0,80}⟧")


def _cut_batch_string(value: str, cap: int = BATCH_ARG_CAP_CHARS) -> str:
    """`value` cut to `cap` characters, two thirds head and one third tail with a marker between them. The value must
    be redacted already: the cut points move out of any placeholder, so none is split."""
    if len(value) <= cap:
        return value
    end = cap * 2 // 3
    start = len(value) - (cap - end)
    for m in _PLACEHOLDER_RE.finditer(value):
        s, e = m.span()
        if s < end < e:
            end = s
        if s < start < e:
            start = e
    cut = start - end
    return f"{value[:end]} …[{cut} characters cut]… {value[start:]}"


def _bound_batch_value(value: Any, *, cap: int, items: int, depth: int = 0) -> Any:
    """A copy of `value` with lists and objects kept to their first `items` entries and a marker counting the rest,
    anything nested deeper than `BATCH_MAX_DEPTH` replaced by a marker, and long keys cut. Strings stay whole, so they
    are redacted before any cut."""
    if isinstance(value, list | dict) and depth >= BATCH_MAX_DEPTH:
        return "…[nested value cut]…"
    if isinstance(value, list):
        out = [_bound_batch_value(x, cap=cap, items=items, depth=depth + 1) for x in value[:items]]
        if len(value) > items:
            out.append(f"…[{len(value) - items} more items cut]…")
        return out
    if isinstance(value, dict):
        obj = {
            _cut_batch_string(k, cap) if isinstance(k, str) else k: _bound_batch_value(
                x, cap=cap, items=items, depth=depth + 1
            )
            for k, x in list(value.items())[:items]
        }
        if len(value) > items:
            obj["…"] = f"[{len(value) - items} more keys cut]"
        return obj
    return value


def _cut_batch_strings(value: Any, cap: int) -> Any:
    if isinstance(value, str):
        return _cut_batch_string(value, cap)
    if isinstance(value, list):
        return [_cut_batch_strings(x, cap) for x in value]
    if isinstance(value, dict):
        return {k: _cut_batch_strings(x, cap) for k, x in value.items()}
    return value


def _batch_entry(sib: dict[str, Any], *, cap: int, items: int) -> tuple[dict[str, Any], int]:
    """One sibling as the batch lists it, and the secrets replaced: bounded, redacted (a credential key's value whole,
    other strings by the text rules), then its long strings cut, so a cut never splits a secret."""
    bounded = {
        k: _bound_batch_value(sib[k], cap=cap, items=items) for k in SIBLING_KEEP if k in sib
    }
    redacted, count = second_pass(bounded)
    return _cut_batch_strings(redacted, cap), count


def _json_chars(obj: Any) -> int:
    return len(canonical_json(obj))


def batch_block(raw: dict[str, Any]) -> dict[str, Any] | None:
    """The `pending_call.batch` block a batch view carries: the other calls of the same step, without ids, redacted,
    within `BATCH_SIBLINGS_CAP_CHARS`. Siblings past `BATCH_MAX_SIBLINGS`, or past the first that does not fit even
    with the tighter bounds, are left out and counted in `siblings_omitted`. None when the pending call was issued
    alone."""
    return _batch_block(raw)[0]


def _batch_block(raw: dict[str, Any]) -> tuple[dict[str, Any] | None, int]:
    """`batch_block` and the number of secrets it replaced."""
    pc = raw.get("pending_call")
    batch = pc.get(BATCH) if isinstance(pc, dict) else None
    siblings = batch.get("siblings") if isinstance(batch, dict) else None
    if not isinstance(siblings, list):
        return None, 0
    calls = [sib for sib in siblings if isinstance(sib, dict)]
    if not calls:
        return None, 0
    out: list[dict[str, Any]] = []
    redactions = 0
    for sib in calls[:BATCH_MAX_SIBLINGS]:
        fitted = None
        for cap, items in (
            (BATCH_ARG_CAP_CHARS, BATCH_MAX_ITEMS),
            (BATCH_ARG_SHORT_CHARS, BATCH_SHORT_ITEMS),
        ):
            entry, count = _batch_entry(sib, cap=cap, items=items)
            if _json_chars([*out, entry]) <= BATCH_SIBLINGS_CAP_CHARS:
                fitted = entry
                break
        if fitted is None:
            break
        out.append(fitted)
        redactions += count
    block: dict[str, Any] = {"siblings": out}
    if len(out) < len(calls):
        block["siblings_omitted"] = len(calls) - len(out)
    return block, redactions


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
    #: The request text was cut to fit the budget.
    request_cut: bool = False
    #: The view was over the budget, so it was fitted.
    fitted: bool = False

    @property
    def history_trimmed(self) -> bool:
        return bool(self.history_cut or self.history_dropped)


def _cut(entry: dict[str, Any], kept: int, of: int, *, head_tail: bool = False) -> None:
    """Cut `entry["content"]` to `kept` characters: its head, or with `head_tail` two thirds head and one third tail
    with a marker between them (the marker is not counted in `kept`). The content must be the one that arrived, not
    one already cut, so a head-and-tail cut never nests."""
    content = entry["content"]
    entry["scanner_truncated"] = {"kept_chars": kept, "of_chars": of}
    if not head_tail or kept == 0:
        entry["content"] = content[:kept]
        return
    entry["content"], kept = _head_tail(content, kept, of)
    entry["scanner_truncated"]["kept_chars"] = kept
    if kept:
        entry["scanner_truncated"]["kept"] = "head_tail"


# Secret-safe cuts. The spans are found once per string (the over-budget fill cuts the same input many times); the
# caches are cleared after each build, so no request's text outlives it here.
@functools.lru_cache(maxsize=32)
def _protected_spans(text: str) -> tuple[tuple[int, int], ...]:
    return tuple(protected_spans(text))


@functools.lru_cache(maxsize=32)
def _secret_spans(text: str) -> tuple[tuple[int, int], ...]:
    return tuple(secret_spans(text))


def _safe_end(text: str, end: int) -> int:
    """A head's end moved back out of any protected span it falls inside."""
    return next((s for s, e in _protected_spans(text) if s < end < e), end)


def _safe_start(text: str, start: int) -> int:
    """A tail's start moved forward out of any protected span it falls inside."""
    return next((e for s, e in _protected_spans(text) if s < start < e), start)


def _marker(cut_chars: int) -> str:
    return f"\n…[sentrook: {cut_chars} characters cut]…\n"


def _secure_cut(text: str, end: int, start: int, of: int) -> tuple[int, int]:
    """Cut points that keep every kept secret recognisable. Outside a secret's span, the text before it can still
    decide whether the second pass sees it (a rule that reads the characters before its match, or a cue the cut makes
    live whose match runs over the next one). So the cut string, `text[:end]`, the marker and `text[start:]`, is
    redacted, and while a secret the whole text would replace is still there in clear, the cut point on its side
    moves past it. Each move drops a secret from the kept part, so this ends."""
    secrets = _secret_spans(text)
    if not secrets:
        return end, start
    while True:
        kept = end + len(text) - start
        joined = text[:end] + (_marker(of - kept) if start < len(text) else "") + text[start:]
        redacted, _ = redact_text(joined)
        clear = next(
            ((s, e) for s, e in secrets if (e <= end or s >= start) and text[s:e] in redacted),
            None,
        )
        if clear is None:
            return end, start
        s, e = clear
        spans = _protected_spans(text)
        if e <= end:
            end = min(s, next((ps for ps, pe in spans if ps <= s < pe), s))
        else:
            start = max(e, next((pe for ps, pe in spans if ps < e <= pe), e))


def clear_cut_caches() -> None:
    _protected_spans.cache_clear()
    _secret_spans.cache_clear()


def _head_tail(text: str, kept: int, of: int) -> tuple[str, int]:
    """`text` cut to at most `kept` characters, two thirds head and one third tail, with a marker between them saying
    how many of the `of` characters were cut, and the characters really kept. No cut leaves a kept secret
    unrecognisable (see `_safe_end` and `_secure_cut`), so fewer than `kept` may be kept; none kept gives an empty
    string. `0 < kept < len(text)`."""
    head = kept * 2 // 3
    end = _safe_end(text, head)
    start = _safe_start(text, len(text) - (kept - head))
    end, start = _secure_cut(text, end, start, of)
    kept = end + len(text) - start
    if kept == 0:
        return "", 0
    return text[:end] + _marker(of - kept) + text[start:], kept


def cap_inputs(
    inputs: list[Any],
    *,
    per_input: int = CALL_INPUT_CAP_CHARS,
    total: int = CALL_INPUTS_TOTAL_CAP_CHARS,
    head_tail: bool = False,
) -> bool:
    """Cap each string `content` at `per_input` characters (head kept, or head and tail with `head_tail`; see
    `_cut`), then the sum at `total` (counting the characters kept, not the markers):
    the most recent inputs (highest `input_seq`, such as the listing right before the pending call)
    keep their content and the earliest lose theirs first; metadata always stays. Entries without an
    integer `input_seq` count as earliest; ties keep list order. Mutates the entries; returns whether
    anything was cut."""
    cut = False
    remaining = total
    for entry in _most_recent_first(inputs):
        current = len(entry["content"])
        kept = min(current, per_input, remaining)
        remaining -= kept
        if kept < current:
            # an entry cut before keeps the size it arrived with
            _cut(entry, kept, _prior_cut(entry).get("of_chars", current), head_tail=head_tail)
            cut = True
    return cut


def _most_recent_first(inputs: list[Any]) -> list[dict[str, Any]]:
    """The entries with string content, most recent first: highest integer `input_seq` first, entries without one last,
    ties in reverse list order (the order the caps fill)."""
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

    return [e for _, e in sorted(entries, key=recency, reverse=True)]


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


def with_resolved(state: dict[str, Any], commands: list[str]) -> dict[str, Any]:
    """A copy of a batch view's state with `pending_call.batch.resolved`: the pending command as it runs once the
    files its siblings write are read into it, each redacted whole and then cut (so a cut never splits a secret), within
    `BATCH_RESOLVED_CAP_CHARS`: the trailing commands that do not fit are left out and counted in `resolved_omitted`.
    Unchanged when the join resolved nothing or the state has no batch."""
    pc = state.get("pending_call")
    if not commands or not isinstance(pc, dict) or not isinstance(pc.get(BATCH), dict):
        return state
    resolved: list[str] = []
    for c in commands:
        item = _cut_batch_string(redact_text(c)[0])
        if _json_chars([*resolved, item]) > BATCH_RESOLVED_CAP_CHARS:
            break
        resolved.append(item)
    block = {**pc[BATCH], "resolved": resolved}
    if len(resolved) < len(commands):
        block["resolved_omitted"] = len(commands) - len(resolved)
    out = dict(state)
    out["pending_call"] = dict(pc)
    out["pending_call"][BATCH] = block
    return out


#: The `reputation` block's bound. Entries per call over replayed beta traffic (3,174 calls):
#: 6 calls have a block, at most 3 entries; over the suite (1,753 cases): 194, at most 2, the longest entry 130
#: characters of JSON. The cap keeps eight entries of 200 characters, so a long host or address still fits.
REPUTATION_MAX_ENTRIES = 8
REPUTATION_CAP_CHARS = 1_600
#: The room a view carrying the block keeps free for it: the cap, the block's key and the omitted count.
REPUTATION_RESERVE_TOKENS = math.ceil((REPUTATION_CAP_CHARS + 64) / CHARS_PER_TOKEN)


def _reputation_rank(entry: dict[str, Any]) -> int:
    """Which entries a capped block keeps first: known_bad, then near misses of a known_good entry, then known_good,
    then the rest (owner_config)."""
    verdict = entry.get("verdict")
    if verdict == "known_bad":
        return 0
    if "near_miss" in entry:
        return 1
    return 2 if verdict == "known_good" else 3


#: Over the cap, an entry longer than its share of the block has its long values cut head and tail to fit it, so any
#: `REPUTATION_MAX_ENTRIES` entries fit together and a long known_bad host is shortened, never dropped.
REPUTATION_ENTRY_CAP_CHARS = (
    REPUTATION_CAP_CHARS - REPUTATION_MAX_ENTRIES - 1
) // REPUTATION_MAX_ENTRIES
_REPUTATION_CUT = "…"


#: An entry's fields that are never cut: what the entry is about and its verdict.
_REPUTATION_FIXED = frozenset({"kind", "verdict"})
_REPUTATION_MIN_KEEP = 9


def _shorten_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """`entry` with its long string values cut, two thirds head and one third tail around `…`, until it fits
    `REPUTATION_ENTRY_CAP_CHARS` or nothing more can be cut. The longest value is cut first, down to the next longest,
    so the excess is shared between long values; `kind` and `verdict` are never cut. The registrable end of a host or
    address stays in the tail."""
    out = dict(entry)
    while (excess := _json_chars(out) - REPUTATION_ENTRY_CAP_CHARS) > 0:
        lengths = sorted(
            (
                (len(x), k)
                for k, x in out.items()
                if isinstance(x, str) and k not in _REPUTATION_FIXED
            ),
            reverse=True,
        )
        if not lengths or lengths[0][0] <= _REPUTATION_MIN_KEEP:
            break
        longest, key = lengths[0]
        tied = sum(1 for n, _ in lengths if n == longest)
        second = next((n for n, _ in lengths if n < longest), 0)
        # values tied for longest share the excess; the longest alone is cut no shorter than the next
        new_len = max(_REPUTATION_MIN_KEEP, longest - -(-excess // tied), second)
        if new_len >= longest:
            new_len = max(_REPUTATION_MIN_KEEP, longest - 1)
        value = out[key]
        head = (new_len - 1) * 2 // 3
        cut = value[:head] + _REPUTATION_CUT + value[len(value) - (new_len - 1 - head) :]
        before = _json_chars(out)
        out[key] = cut
        if _json_chars(out) >= before:
            out[key] = value
            break
    return out


def cap_reputation(verdicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The entries a `reputation` block keeps: all of them, unchanged, when they fit `REPUTATION_MAX_ENTRIES` and
    `REPUTATION_CAP_CHARS`; otherwise the highest-ranked (`_reputation_rank`, then their order), each shortened to
    `REPUTATION_ENTRY_CAP_CHARS` where longer, up to the first that does not fit, in their original order."""
    entries = [dict(v) for v in verdicts]
    if len(entries) <= REPUTATION_MAX_ENTRIES and _json_chars(entries) <= REPUTATION_CAP_CHARS:
        return entries
    entries = [_shorten_entry(e) for e in entries]
    kept: list[int] = []
    for i in sorted(range(len(entries)), key=lambda i: (_reputation_rank(entries[i]), i)):
        if len(kept) == REPUTATION_MAX_ENTRIES:
            break
        if _json_chars([entries[j] for j in sorted([*kept, i])]) > REPUTATION_CAP_CHARS:
            break
        kept.append(i)
    return [entries[i] for i in sorted(kept)]


def with_reputation(state: dict[str, Any], verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """A copy of a call-v3 state with the `reputation` block appended after `grants`; with no
    known verdicts the key is absent, so the model's default (nothing vouched for) applies and the
    request body is the same as it would be without an oracle. The block is capped (`cap_reputation`); the entries
    left out are counted in `reputation_omitted`."""
    out = dict(state)
    out.pop(REPUTATION, None)
    out.pop(REPUTATION_OMITTED, None)
    if verdicts:
        kept = cap_reputation(verdicts)
        if kept:
            out[REPUTATION] = kept
        if len(kept) < len(verdicts):
            out[REPUTATION_OMITTED] = len(verdicts) - len(kept)
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
    other people's messages last; what was dropped is counted in `self_edit.scanner_dropped`, written before each next
    size check so the count is inside the budget. Mutates `v`."""
    block = v.get(SELF_EDIT)
    if not isinstance(block, dict) or not isinstance(block.get("conversation"), list):
        return False
    conv = block["conversation"]
    dropped: dict[str, int] = {}

    def count(kind: str) -> None:
        dropped[kind] = dropped.get(kind, 0) + 1
        block["scanner_dropped"] = dropped

    history = v.get("history")
    while isinstance(history, list) and history and est_tokens(v) > budget_tokens:
        history.pop(0)
        count("history")
    for role in ("tool", "assistant", "user"):
        while est_tokens(v) > budget_tokens:
            idx = next((i for i, e in enumerate(conv) if e.get("role") == role), None)
            if idx is None:
                break
            del conv[idx]
            count(role)
    return bool(dropped)


def cap_self_edit(v: dict[str, Any], budget_tokens: int) -> bool:
    """Both bounds: entries capped, then the conversation fitted to the budget."""
    capped = cap_self_edit_entries(v)
    return fit_self_edit(v, budget_tokens) or capped


#: Fitting an over-budget call view: a history step's argument strings longer than this keep only their head, and this
#: many of the most recent steps are kept (cut, not dropped) until the inputs have been fitted.
HISTORY_ARG_KEEP_CHARS = 400
HISTORY_KEEP_STEPS = 3
#: Fitting an over-budget call-v5 view: a request text longer than this is cut to it first, head and tail.
REQUEST_KEEP_CHARS = 4000


def cut_request_text(v: dict[str, Any]) -> bool:
    """Cut a `request.text` longer than `REQUEST_KEEP_CHARS` to that many characters, two thirds head and one third
    tail with a marker between them; the request carries `scanner_truncated`. A request just over the keep size is
    left whole when the marker and the record would make it no smaller. Mutates `v`; returns whether it cut."""
    req = v.get("request")
    if not isinstance(req, dict) or not isinstance(req.get("text"), str):
        return False
    text = req["text"]
    if len(text) <= REQUEST_KEEP_CHARS:
        return False
    cut = dict(req)
    cut["text"], kept = _head_tail(text, REQUEST_KEEP_CHARS, len(text))
    cut["scanner_truncated"] = {"kept_chars": kept, "of_chars": len(text)}
    if kept:
        cut["scanner_truncated"]["kept"] = "head_tail"
    if est_tokens(cut) >= est_tokens(req):
        return False
    v["request"] = cut
    return True


def _prior_cut(entry: dict[str, Any]) -> dict[str, Any]:
    prior = entry.get("scanner_truncated")
    return prior if isinstance(prior, dict) else {}


def _shorten(value: Any, secret_safe: bool = False) -> tuple[Any, int, int]:
    """`value` with every string longer than `HISTORY_ARG_KEEP_CHARS` cut to its head (with `secret_safe`, an end that
    does not split a secret: see `_safe_end`), and the characters kept and the original length summed over the strings
    that were cut."""
    if isinstance(value, str):
        if len(value) > HISTORY_ARG_KEEP_CHARS:
            end = HISTORY_ARG_KEEP_CHARS
            if secret_safe:
                end, _ = _secure_cut(value, _safe_end(value, end), len(value), len(value))
            return value[:end], end, len(value)
        return value, 0, 0
    kept = of = 0
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, x in value.items():
            out[k], k_kept, k_of = _shorten(x, secret_safe)
            kept, of = kept + k_kept, of + k_of
        return out, kept, of
    if isinstance(value, list):
        items = []
        for x in value:
            y, k_kept, k_of = _shorten(x, secret_safe)
            items.append(y)
            kept, of = kept + k_kept, of + k_of
        return items, kept, of
    return value, 0, 0


def cut_history_arguments(
    v: dict[str, Any], budget_tokens: int, *, secret_safe: bool = False
) -> int:
    """While the view is over the budget, cut the long argument strings of its history steps, oldest step first (the
    step stays: tool, kind, decision and the strings' heads; with `secret_safe`, no cut splits a secret). A cut step
    carries `scanner_truncated`: the characters kept and the original length, over the strings cut. Mutates `v`;
    returns how many steps were cut."""
    history = v.get("history")
    if not isinstance(history, list):
        return 0
    cut = 0
    for step in history:
        if est_tokens(v) <= budget_tokens:
            break
        if not isinstance(step, dict) or "arguments" not in step:
            continue
        args, kept, of = _shorten(step["arguments"], secret_safe)
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


def fill_inputs(
    v: dict[str, Any], arrived: list[Any], budget_tokens: int, *, head_tail: bool = False
) -> tuple[bool, bool]:
    """Set `v["new_inputs"]` to the inputs as they `arrived`, capped, with the largest contents' total that fits the
    budget: the most recent inputs keep their content and the earliest lose theirs first, as with the total cap. Every
    attempt cuts from what arrived, so a head-and-tail cut never nests. Returns whether anything was cut and whether
    every content was emptied (the view does not fit even without them)."""
    total = min(
        CALL_INPUTS_TOTAL_CAP_CHARS,
        sum(
            min(len(e["content"]), CALL_INPUT_CAP_CHARS)
            for e in arrived
            if isinstance(e, dict) and isinstance(e.get("content"), str)
        ),
    )

    def build(target: int) -> tuple[bool, bool]:
        inputs = copy.deepcopy(arrived)
        cut = cap_inputs(inputs, total=target, head_tail=head_tail)
        v["new_inputs"] = inputs
        return cut, est_tokens(v) <= budget_tokens

    cut, fits = build(total)
    if fits:
        return cut, False
    cut, fits = build(0)
    if not fits and not head_tail:
        return cut, total > 0
    lo, hi = 0, total
    if head_tail:
        # The view shrinks where an input becomes whole (its marker and record drop out) and grows with the total
        # between those points, so each stretch is smallest at its start. Take the largest such point that fits, then
        # search up to the next one. Emptying every input is not always smallest (a short result such as "ok" takes
        # less room whole than emptied with its record), so the inputs are stripped only when no point fits.
        points: list[int] = []
        running = 0
        for entry in _most_recent_first(arrived):
            running += min(len(entry["content"]), CALL_INPUT_CAP_CHARS)
            if 0 < running < total and (not points or running > points[-1]):
                points.append(running)
        for point in reversed(points):
            if build(point)[1]:
                lo, fits = point, True
                break
        if not fits:
            cut, _ = build(0)
            return cut, total > 0
        hi = next((p for p in points if p > lo), total)
    # between lo (fits) and hi (does not), the view's size grows with the total: bisect
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
    request_cut: bool = False


def _fit_call_view(
    v: dict[str, Any],
    arrived: list[Any] | None,
    budget_tokens: int,
    *,
    head_tail: bool = False,
    cut_request: bool = False,
) -> _Fitted:
    """Fit an over-budget call view, least useful first: with `cut_request`, a long request text (see
    `cut_request_text`); the history steps' long arguments (oldest first), then the oldest steps (keeping the last
    `HISTORY_KEEP_STEPS`), then the inputs' content (the most recent kept longest), then the remaining steps, with the
    inputs refilled into any room that leaves. A view still over the budget with no input content and no history is
    sent as it is. `arrived` is the inputs before any cap."""
    cut = stripped = False
    request_cut = cut_request and cut_request_text(v)
    history_cut = cut_history_arguments(v, budget_tokens, secret_safe=head_tail)
    dropped = drop_history(v, budget_tokens, keep=HISTORY_KEEP_STEPS)
    if arrived is not None and est_tokens(v) > budget_tokens:
        cut, stripped = fill_inputs(v, arrived, budget_tokens, head_tail=head_tail)
    if est_tokens(v) > budget_tokens:
        dropped += drop_history(v, budget_tokens, keep=0)
        if arrived is not None:
            cut, stripped = fill_inputs(v, arrived, budget_tokens, head_tail=head_tail)
    return _Fitted(cut, stripped, history_cut, dropped, request_cut)


#: How many times a view the second redaction pass grew past its budget is fitted again.
REDACTION_REFITS = 3


def _call_view_with_inputs(
    raw: dict[str, Any],
    name: str,
    *,
    budget_tokens: int,
    shrink_tokens: int = 0,
    refits: int = REDACTION_REFITS,
) -> BuiltView:
    """A call view (or a self-edit view) with the turn's inputs, capped, fitted to the budget, then redacted. The
    self-edit views keep their own fitting: their conversation goes after the inputs. If the redaction grew the view
    past its budget, it is built again fitted to its unredacted size less the growth (`shrink_tokens` below the budget),
    up to `refits` times."""
    given_budget = budget_tokens
    v = view(trim(raw), name)
    batch_redactions = 0
    if REPUTATION in VIEW_KEYS[name]:
        # the call probe adds the (capped) `reputation` block after the fit: keep its room free
        budget_tokens -= REPUTATION_RESERVE_TOKENS
    if name in BATCH_VIEWS and isinstance(v.get("pending_call"), dict):
        batch, batch_redactions = _batch_block(raw)
        if batch is not None:
            v["pending_call"][BATCH] = batch
            # the call probe adds `resolved` after the fit: keep its room free
            budget_tokens -= BATCH_RESOLVED_RESERVE_TOKENS
    sent_budget = budget_tokens
    budget_tokens -= shrink_tokens
    if name == SELFEDIT_V2:
        mark_own_store(v)
    inputs = v.get("new_inputs")
    truncated = stripped = over_budget = False
    fitted = _Fitted()
    if name not in SELFEDIT_VIEWS:
        head_tail = name in HEAD_TAIL_VIEWS
        arrived = copy.deepcopy(inputs) if isinstance(inputs, list) else None
        if isinstance(inputs, list):
            truncated = cap_inputs(inputs, head_tail=head_tail)
        if est_tokens(v) > budget_tokens:
            over_budget = True
            fitted = _fit_call_view(
                v,
                arrived,
                budget_tokens,
                head_tail=head_tail,
                cut_request=name in REQUEST_FIT_VIEWS,
            )
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
    over = est_tokens(state) - sent_budget
    unredacted = est_tokens(v)
    if over > 0 and refits > 0 and est_tokens(state) > unredacted:
        # placeholders longer than the secrets they replace took the view over its budget: fit it tighter, to what it
        # was before the redaction less the overshoot (the fit budget alone may be far above the view), and less what
        # the fitter itself overshot its target by (only when it ran out of entries to drop)
        target = min(budget_tokens, unredacted) - over - max(0, unredacted - budget_tokens)
        return _call_view_with_inputs(
            raw,
            name,
            budget_tokens=given_budget,
            shrink_tokens=sent_budget - target,
            refits=refits - 1,
        )
    return BuiltView(
        state=state,
        redactions=count + batch_redactions,
        inputs_truncated=truncated,
        inputs_stripped=stripped,
        history_cut=fitted.history_cut,
        history_dropped=fitted.history_dropped,
        request_cut=fitted.request_cut,
        fitted=over_budget,
    )


def build_views(
    raw: dict[str, Any],
    *,
    exposure_input_seqs: set[int] | None,
    call_budget_tokens: int | None = None,
    selfedit_budget_tokens: int | None = None,
) -> dict[str, BuiltView]:
    """Every named view for one request: the frozen v1 views and the v2 views (cheap, always built).
    call-v5 is call-v3's prepared state except when inputs are cut (call-v5 keeps head and tail) or the view is over
    the budget (call-v5 cuts a long request first); the reputation the oracle fills in also differs. The call views (call-v2, call-v3, call-v5) are built to `call_budget_tokens` and the self-edit views (selfedit-v1,
    selfedit-v2) to `selfedit_budget_tokens`: the room the question set that sends them leaves, or the default
    reserves when not given."""
    try:
        return _build_views(raw, exposure_input_seqs, call_budget_tokens, selfedit_budget_tokens)
    finally:
        clear_cut_caches()


def _build_views(
    raw: dict[str, Any],
    exposure_input_seqs: set[int] | None,
    call_budget_tokens: int | None,
    selfedit_budget_tokens: int | None,
) -> dict[str, BuiltView]:
    call_budget = CALL_STATE_BUDGET_TOKENS if call_budget_tokens is None else call_budget_tokens
    v3 = call_view_v3(raw, budget_tokens=call_budget)
    out = {
        EXPOSURE: BuiltView(state=exposure_view(raw, only_input_seqs=exposure_input_seqs)),
        CALL: BuiltView(state=call_view(raw)),
        EXPOSURE_V2: exposure_view_v2(raw, only_input_seqs=exposure_input_seqs),
        CALL_V2: call_view_v2(raw, budget_tokens=call_budget),
        CALL_V3: v3,
        # the same state unless an input was cut or the view was fitted, which call-v5 does its own way
        CALL_V5: _call_view_with_inputs(raw, CALL_V5, budget_tokens=call_budget)
        if v3.inputs_truncated or v3.fitted
        else v3,
    }
    # call-v5's state unless the pending call has batch siblings, which only call-v7 shows
    out[CALL_V7] = (
        _call_view_with_inputs(raw, CALL_V7, budget_tokens=call_budget)
        if batch_block(raw) is not None
        else out[CALL_V5]
    )
    if isinstance(raw.get(SELF_EDIT), dict):
        selfedit_budget = (
            SELFEDIT_STATE_BUDGET_TOKENS
            if selfedit_budget_tokens is None
            else selfedit_budget_tokens
        )
        for name in (SELFEDIT_V1, SELFEDIT_V2):
            out[name] = _call_view_with_inputs(raw, name, budget_tokens=selfedit_budget)
    return out
