"""The read-only dashboard's model: recent scans and each scan's risk tree, from the traffic log.

It holds only what the scanner returned (risk, the tier and leaf scores, floors, relief, reason codes and
texts, entity display strings) plus the plugin's own labels for what it did. The PlanIR as sent, the call's
arguments, `reasons[].detail` and failure details are never included, as with `/sentrook why`. The OpenClaw
plugin builds the same model for the same log (fixtures/traffic-log/dashboard).

`dashboard/plugin_api.py` serves it to the Hermes dashboard tab; the page cannot change anything.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import grants, snooze
from .config import PluginConfig
from .history import (
    HISTORY_DEFAULT,
    HISTORY_MAX,
    _response,
    _text,
    action_of,
    recent_scans,
    review_of,
)

MODEL_VERSION = 1

#: The leaves of each tier, in the order the page shows them; any other numeric key follows, sorted.
TIERS: list[tuple[str, list[str]]] = [
    (
        "suspicion",
        [
            "misalignment",
            "concealment",
            "overreach",
            "distrust",
            "request_origin",
            "retry_after_denial",
            "untrusted_origin",
            "exposure",
            "session_exposure",
        ],
    ),
    ("consequence", ["sensitivity", "reach", "irreversibility", "self_modification"]),
    ("confidence", ["agreement", "coverage", "model_certainty"]),
]

#: Plugin marks on a scan record worth showing next to the action.
FLAGS = ["snoozed", "relaxed", "hold", "notice", "skill_review", "self_edit", "host_process"]

_LIMIT = re.compile(r"[0-9]{1,4}")
_ENTITY_NUM = re.compile(r"[0-9]+")

CMD = "/sentrook {}".format


def _number(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return v


def _unit(v: Any) -> float | None:
    n = _number(v)
    return None if n is None else min(max(n, 0), 1)


def _str(v: Any, limit: int) -> str | None:
    return _text(v, limit) if isinstance(v, str) and v.strip() else None


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: Any) -> list[dict[str, Any]]:
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _step(v: Any) -> int | None:
    """A whole-number step, as JavaScript's Number.isInteger reads it (3.0 counts)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return None


def _tiers(tree: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for name, known in TIERS:
        t = _obj(tree.get(name))
        extra = sorted(
            k for k, v in t.items() if k != "score" and k not in known and _number(v) is not None
        )
        out.append(
            {
                "name": name,
                "score": _unit(t.get("score")),
                "leaves": [{"name": leaf, "value": _unit(t.get(leaf))} for leaf in known + extra],
            }
        )
    return out


def _entity_order(key: str) -> tuple[float, str]:
    tail = key[1:]
    return (int(tail) if _ENTITY_NUM.fullmatch(tail) else math.inf, key)


def bucket_of(scan: dict[str, Any], action: str) -> str:
    """Which total a scan counts towards."""
    if _response(scan) is None:
        return "scan_error"
    if action.startswith("blocked"):
        return "blocked"
    if action.startswith(("review", "held")):
        return "review"
    if action.startswith("observed"):
        return "observed"
    return "allowed"


def scan_model(scan: dict[str, Any], resolution: dict[str, Any] | None) -> dict[str, Any]:
    resp = _response(scan)
    r = resp or {}
    action = action_of(scan, resolution)
    entities = _obj(r.get("entities"))
    step = scan.get("step")
    enforced = r.get("enforced")
    return {
        "id": str(scan.get("request_id")),
        "ts": scan.get("ts") if isinstance(scan.get("ts"), str) else None,
        "session": _str(scan.get("session_ref"), 80),
        "tool": _str(scan.get("tool"), 80),
        "step": _step(step),
        "mode": _str(scan.get("mode"), 20),
        "action": action,
        "review": review_of(action, resolution),
        "bucket": bucket_of(scan, action),
        "flags": [f for f in FLAGS if scan.get(f) is True],
        "failure": (_str(_obj(scan.get("failure")).get("kind"), 40) or "unknown")
        if resp is None
        else None,
        "risk": _number(r.get("risk")),
        "enforced": enforced if enforced in ("review", "block") else None,
        "ceiling": _str(r.get("ceiling"), 20),
        "tiers": [] if resp is None else _tiers(_obj(r.get("tree"))),
        "floors": [
            {
                "floor": _str(f.get("floor"), 80),
                "min_risk": _unit(f.get("min_risk")),
                "subject": _str(f.get("subject"), 12),
            }
            for f in _list(r.get("floors_applied"))
        ],
        "relief": [
            {
                "effect": _str(f.get("effect"), 80),
                "grant_ref": _str(f.get("grant_ref"), 40),
                "subject": _str(f.get("subject"), 12),
            }
            for f in _list(r.get("relief_applied"))
        ],
        "reasons": [
            {
                "code": _text(x["code"], 80),
                "signal": _str(x.get("signal"), 60),
                "subject": _str(x.get("subject"), 12),
                "text": _str(x.get("text"), 200),
            }
            for x in _list(r.get("reasons"))
            if isinstance(x.get("code"), str) and x["code"]
        ],
        "entities": [
            {
                "id": _text(k, 12),
                "kind": _str(_obj(entities[k]).get("kind"), 20),
                "display": _text(entities[k]["display"], 200),
            }
            for k in sorted(entities, key=_entity_order)
            if isinstance(_obj(entities[k]).get("display"), str)
        ],
    }


def scans_model(path: Path, enabled: bool, limit: int) -> dict[str, Any]:
    """The scans part of the model; both plugins build the same JSON for the same log."""
    scans = [scan_model(s, res) for s, res in recent_scans(path, limit)] if enabled else []
    totals = {"blocked": 0, "review": 0, "observed": 0, "allowed": 0, "scan_error": 0}
    for s in scans:
        totals[s["bucket"]] = totals.get(s["bucket"], 0) + 1
    return {
        "version": MODEL_VERSION,
        "log": "on" if enabled else "off",
        "limit": limit,
        "scans": scans,
        "totals": totals,
    }


def limit_of(raw: str | None) -> int:
    """`?n=` from the page's limit buttons: the history default when absent or malformed, at most the max."""
    if not raw or not _LIMIT.fullmatch(raw) or int(raw) < 1:
        return HISTORY_DEFAULT
    return min(int(raw), HISTORY_MAX)


def build_model(cfg: PluginConfig, limit: int, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    model = scans_model(cfg.traffic_log_path, cfg.traffic_log_enabled, limit)
    try:
        grants_text = grants.format_grants(cfg, grants.load(cfg.state_dir), now, CMD, None)
    except Exception:  # noqa: BLE001 - the page still shows the scans
        grants_text = "Grants could not be read."
    try:
        snooze_text = snooze.status_line(snooze.load(cfg.state_dir), now)
    except Exception:  # noqa: BLE001 - the page still shows the scans
        snooze_text = "Snooze state could not be read."
    return {
        **model,
        "host": "hermes",
        "lines": {"review_at": cfg.review_at, "block_at": cfg.block_at},
        "mode": cfg.mode,
        "state": {"grants": grants_text, "snooze": snooze_text},
        "commands": {
            "history": "/sentrook history",
            "why": "/sentrook why <id>",
            "grants": "/sentrook grants",
            "snooze": "/sentrook snooze",
        },
    }
