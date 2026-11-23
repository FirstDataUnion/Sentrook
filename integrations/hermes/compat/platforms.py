"""Prints the session platform values this Hermes uses that the plugin classifies neither as attended nor as not
attended (`intent.ATTENDED_PLATFORMS`, `NOT_ATTENDED_PLATFORMS`, `LOCAL_PLATFORMS`). Exit 0 when every value is
classified, 1 when one is not, 2 when the values cannot be read.

    python platforms.py <dir holding the plugin as a package named sentrook>

Run with Hermes's own Python from the Hermes source root (`gateway` importable), as container_check.sh does. The
values are the gateway's `Platform` enum, the bundled platform plugins (by directory, which is the platform value), and the
session surfaces Hermes itself names as not a messaging channel or as unattended for approvals. A platform Hermes
names only in a call (the curator's runs, the gateway's resume runs) is not found here; those are listed by hand.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def hermes_platforms() -> set[str]:
    from gateway.config import Platform

    values: set[Any] = {member.value for member in Platform}
    scan = getattr(Platform, "_scan_bundled_plugin_platforms", None)
    if scan is not None:
        # The directory names are the platform values; the aliases are plugin manifest names (`discord-platform`).
        values |= set(scan()[0])
    else:  # a Hermes without the helper: the bundled plugin directories
        import gateway

        platforms_dir = Path(gateway.__file__).resolve().parent.parent / "plugins" / "platforms"
        if platforms_dir.is_dir():
            values |= {d.name for d in platforms_dir.iterdir() if (d / "__init__.py").exists()}
    for module, name in (
        ("gateway.session_context", "NON_MESSAGING_SESSION_SURFACES"),
        ("tools.approval_context", "_UNATTENDED_APPROVAL_PLATFORMS"),
    ):
        try:
            values |= set(getattr(__import__(module, fromlist=[name]), name))
        except (ImportError, AttributeError):
            pass
    return {str(v).strip().lower() for v in values}


def classified(intent: Any) -> frozenset[str]:
    return intent.ATTENDED_PLATFORMS | intent.NOT_ATTENDED_PLATFORMS | intent.LOCAL_PLATFORMS


def unclassified(values: Iterable[str], known: Iterable[str]) -> list[str]:
    return sorted(set(values) - set(known))


def main(argv: list[str]) -> int:
    sys.path.insert(0, argv[1])
    try:
        from sentrook import intent

        values = hermes_platforms()
    except Exception as exc:  # noqa: BLE001
        print(f"cannot read the platform values: {type(exc).__name__}: {exc}")
        return 2
    if not values:
        print("cannot read the platform values: none found")
        return 2
    missing = unclassified(values, classified(intent))
    if missing:
        print(
            f"unclassified {', '.join(missing)}: this Hermes has session platforms the plugin counts neither as "
            "attended nor as not attended. Check whether a human answers Hermes's approval prompts there, then add "
            "each to ATTENDED_PLATFORMS or NOT_ATTENDED_PLATFORMS in integrations/hermes/plugin/intent.py."
        )
        return 1
    print(f"all {len(values)} platform values classified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
