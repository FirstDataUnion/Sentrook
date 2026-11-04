"""From a scan response to allow / review / block, and the text a human sees.

The plugin decides from `risk` and its local lines (review at `review_at`, block at `block_at`), then
takes the stricter of that and the scanner's `enforced` floor. In observe mode the decision is recorded
but never applied.
"""

from __future__ import annotations

import math
import re
from typing import Any

_RANK = {"allow": 0, "review": 1, "block": 2}
_PLACEHOLDER = re.compile(r"\{(E\d+)\}")
REVIEW_MESSAGE_MAX = 300


def decide(resp: dict[str, Any], review_at: float, block_at: float) -> str:
    risk = float(resp.get("risk") or 0)
    verdict = "block" if risk >= block_at else "review" if risk >= review_at else "allow"
    floor = resp.get("enforced")
    if floor in _RANK and _RANK[floor] > _RANK[verdict]:
        verdict = floor
    return verdict


def tiers_of(resp: dict[str, Any]) -> dict[str, float | None]:
    tree = resp.get("tree") if isinstance(resp.get("tree"), dict) else {}

    def score(name: str) -> float | None:
        v = (tree.get(name) or {}).get("score") if isinstance(tree.get(name), dict) else None
        return float(v) if isinstance(v, (int, float)) else None

    return {
        "suspicion": score("suspicion"),
        "consequence": score("consequence"),
        "confidence": score("confidence"),
    }


def describe(resp: dict[str, Any], tool: str) -> str:
    desc = resp.get("tool_description") if isinstance(resp.get("tool_description"), dict) else {}
    template = desc.get("template")
    if not isinstance(template, str) or not template:
        return f"Runs {tool}"
    entities = resp.get("entities") if isinstance(resp.get("entities"), dict) else {}
    return _PLACEHOLDER.sub(
        lambda m: str((entities.get(m.group(1)) or {}).get("display") or m.group(1)), template
    )


def _reason_codes(resp: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if isinstance(code, str) and code and code not in seen:
            seen.append(code)
    return seen


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def scores_line(resp: dict[str, Any]) -> str:
    """The tree's tier scores on the 0-100 scale of `risk`; empty when the response has none.
    A score that is not a finite number is left out; the rest are held to 0-1."""
    parts = [
        f"{name} {round(min(max(v, 0.0), 1.0) * 100)}"
        for name, v in tiers_of(resp).items()
        if v is not None and math.isfinite(v)
    ]
    return f"Scores: {', '.join(parts)}." if parts else ""


def _fit(head: str, desc: str, codes: list[str], tail: str, limit: int) -> str:
    """`head`, the description, up to 3 reason codes and `tail` within `limit`. Reason codes go
    first, then the description is shortened; `head` and `tail` always stay."""
    tail = f" {tail}" if tail else ""
    for k in range(min(3, len(codes)), -1, -1):
        why = f" Why: {', '.join(codes[:k])}." if k else ""
        text = f"{head}{desc}.{why}{tail}"
        if len(text) <= limit:
            return text
    return f"{head}{_clip(desc, limit - len(head) - len(tail) - 1)}.{tail}"


def review_message(resp: dict[str, Any], tool: str) -> str:
    risk = round(float(resp.get("risk") or 0))
    head = f"Sentrook (risk {risk}): "
    return _fit(
        head, describe(resp, tool), _reason_codes(resp), scores_line(resp), REVIEW_MESSAGE_MAX
    )


# What the agent is told about a block. It names a coarse category only, never the reason codes, the
# risk score, the entities or the tool description: those would tell a steered agent which detector to
# rephrase around. The human sees the detail in the review prompt, `why` and the traffic log.
BLOCK_CATEGORIES: dict[str, str] = {
    "sensitive_data": "it reads or sends sensitive data, such as credentials or personal data",
    "untrusted_code": "it runs or installs code from a source that is not trusted",
    "concealment": "it hides what it does, or hides information from the user",
    "agent_setup": (
        "it changes the agent's own setup, such as its configuration, memory, plugins, skills or "
        "scheduled jobs"
    ),
    "safety_controls": (
        "it changes Sentrook's or the host's safety settings, which only the user may change"
    ),
    "destructive": "it deletes or overwrites data in a way that is hard to undo",
    "privileges": "it changes privileges on this machine",
    "remote_account": (
        "it makes a lasting change to an account, a payment or access rights on a remote service"
    ),
    "general": "it does not look safe in the context of this session",
}

# Reason codes whose category differs from their domain's, or whose domain has none.
_CATEGORY_BY_CODE: dict[str, str] = {
    "floor.untrusted_code_execution": "untrusted_code",
    "floor.guardrail_tampering": "safety_controls",
    "selfmod.host_approvals": "safety_controls",
    "remote.delete": "destructive",
    "remote.force_push": "destructive",
    "sensitivity.session_holds_sensitive": "sensitive_data",
    "jev.sensitivity": "sensitive_data",
    "jev.self_modification": "agent_setup",
    "jev.concealment": "concealment",
    "lineage.secret_carried_to_send": "sensitive_data",
    "lineage.moved_into_destroyed_tree": "destructive",
    "lineage.listing_marks_irreplaceable": "destructive",
    "lineage.listing_marks_live_table": "destructive",
    "lineage.filter_silences_security_notices": "concealment",
}

# Domains that say what kind of harm a call does. Domains that say why a call is suspect (exposure,
# origin, reputation, retry, trigger) or how sure the scan is (coverage, agreement) have no category.
_CATEGORY_BY_DOMAIN: dict[str, str] = {
    "path": "sensitive_data",
    "exfil": "sensitive_data",
    "send": "sensitive_data",
    "artefact": "sensitive_data",
    "code": "untrusted_code",
    "conceal": "concealment",
    "selfmod": "agent_setup",
    "guardrail": "safety_controls",
    "destroy": "destructive",
    "priv": "privileges",
    "remote": "remote_account",
}


def block_category(resp: dict[str, Any]) -> str:
    """The category of the first reason, in contribution order, that has one; `general` when none
    does."""
    reasons = resp.get("reasons")
    if not isinstance(reasons, list):
        return "general"
    for r in reasons:
        code = r.get("code") if isinstance(r, dict) else None
        if not isinstance(code, str) or not code:
            continue
        category = _CATEGORY_BY_CODE.get(code) or _CATEGORY_BY_DOMAIN.get(code.split(".", 1)[0])
        if category:
            return category
    return "general"


def block_reason(resp: dict[str, Any]) -> str:
    return (
        "Sentrook security block: this tool call did not run because "
        f"{BLOCK_CATEGORIES[block_category(resp)]}. Do not retry it, rephrase it or try to reach the "
        "same result another way unless the user explicitly tells you to. Tell the user what was "
        "blocked and why, and ask how they want to proceed."
    )
