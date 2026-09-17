"""Labels for which Layer-2 matcher evaluated a rule hit."""

from __future__ import annotations

from enum import Enum


class L2PassKind(str, Enum):
    """How a rule condition was structurally matched against PlanIR.

    Replaces the design-doc shorthand 2a/2b/2c with self-describing wire values.
    JSON field remains ``pass`` on ScanResult matched_rules entries.
    """

    # Imminent-tool gate: does a pending step use the expected tool name?
    # Example rule: AIRA-010 (pending_tool: exec).
    PENDING_TOOL = "pending_tool"

    # Ordered trajectory: tool + executed/pending per slot, no argument regex.
    # Example rules: AIRA-020/030 (single-slot contiguous exec/write args).
    SEQUENCE = "sequence"

    # Ordered subsequence: all slots must match in order; intervening steps allowed.
    # Example rule: AIRA-001 (web_fetch executed → exec pending with noise between).
    SEQUENCE_WITH_GAP = "sequence_with_gap"

    # Trajectory match that also checks regex patterns on step arguments.
    # Example rules: AIRA-020 (curl|bash), AIRA-030 (/etc/ path).
    SEQUENCE_ARGS = "sequence_args"

    # AND combinator: every child condition had to match.
    ALL = "all"

    # OR combinator: at least one child condition had to match.
    ANY = "any"

    # Negated child: rule matches only when the inner condition does not.
    NONE = "none"

    # Plan-level intent classification (user, cron, heartbeat, subagent, system).
    INTENT_KIND = "intent_kind"

    # Per-path classification of the pending exec step, with an **explicit**
    # quantifier (`any` / `every` / `none`). Separate from SEQUENCE_ARGS because
    # it reasons over structure rather than matching a regex against a
    # stringified arg — the matcher drops dicts, so a flat field could not carry
    # it (F27).
    PATHS = "paths"

    # Reserved for Phase 4: **provenance** between steps, in either of two arms.
    # Referential — a sensitive path or URL from an executed step reappears in
    # the pending argv (`cat ~/.ssh/id_rsa` then `curl -d @~/.ssh/id_rsa`).
    # Value-provenance — the same `[REDACTED:<hex>]` marker appears in an
    # executed step's `result_summary` *and* in a pending outbound argument,
    # meaning the agent read something and pasted the bytes onward. The second
    # arm is the shape that dominates real exfiltration and the referential arm
    # cannot see it: there is no shared reference, only the same value twice.
    # Not implemented.
    DATAFLOW = "dataflow"

    UNKNOWN = "unknown"
