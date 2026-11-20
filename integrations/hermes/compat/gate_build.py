"""Prints the digest of this Hermes's background-review memory gate (the plugin's `staging.gate_build`) and whether
the plugin lists it as verified. Exit 0 when verified, 1 when not, 2 when it cannot be computed.

    python gate_build.py <dir holding the plugin as a package named sentrook>

Run with Hermes's own Python from the Hermes source root (`tools` importable), as container_check.sh does.
"""

import sys

sys.path.insert(0, sys.argv[1])

try:
    import tools.memory_tool as mt

    from sentrook import staging

    digest = staging.gate_build(mt)
except Exception as exc:  # noqa: BLE001
    print(f"cannot compute the gate digest: {type(exc).__name__}: {exc}")
    sys.exit(2)
if digest in staging.VERIFIED_GATES:
    print(f"verified {digest} ({staging.VERIFIED_GATES[digest]})")
    sys.exit(0)
print(
    f"not verified {digest}: this Hermes's background-review memory gate is not on the plugin's list, so the "
    "plugin holds destructive memory changes from the background review instead of leaving them to Hermes. Check "
    "that its gate still stages every such change of an unattended review, then add the digest to "
    "VERIFIED_GATES in integrations/hermes/plugin/staging.py."
)
sys.exit(1)
