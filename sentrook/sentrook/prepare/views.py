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
"""

from __future__ import annotations

import copy
from typing import Any

VIEWS_VERSION = "trim-v1"

STRIP_TOP = frozenset({"request_id", "run_ref", "sent_at", "scan_kind", "origin", "options"})
SESSION_KEEP = ("agent_ref", "agent_role", "turn", "step")
STRIP_HISTORY = frozenset({"request_id", "action_fingerprint", "risk", "tiers", "call_id"})
STRIP_NEW_INPUT = frozenset({"call_id"})
STRIP_PENDING_CALL = frozenset({"call_id", "host_call_id", "batch"})

EXPOSURE = "exposure"
CALL = "call"
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
}


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
