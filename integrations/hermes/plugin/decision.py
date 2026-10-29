"""From a scan response to allow / review / block, and the text a human sees.

The plugin decides from `risk` and its local lines (review at `review_at`, block at `block_at`), then
takes the stricter of that and the scanner's `enforced` floor. In observe mode the decision is recorded
but never applied.
"""

from __future__ import annotations

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


def _reasons(resp: dict[str, Any], limit: int) -> str:
    return ", ".join(_reason_codes(resp)[:limit])


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def scores_line(resp: dict[str, Any]) -> str:
    """The tree's tier scores on the 0-100 scale of `risk`; empty when the response has none."""
    parts = [f"{name} {round(v * 100)}" for name, v in tiers_of(resp).items() if v is not None]
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


def block_reason(resp: dict[str, Any], tool: str) -> str:
    risk = round(float(resp.get("risk") or 0))
    why = _reasons(resp, 5)
    floor = " (enforced)" if resp.get("enforced") == "block" else ""
    return _clip(
        f"Sentrook blocked this tool call{floor}, risk {risk}/100: {describe(resp, tool)}."
        + (f" Reasons: {why}." if why else "")
        + " Do not retry it in another form; ask the user if it is needed.",
        500,
    )
