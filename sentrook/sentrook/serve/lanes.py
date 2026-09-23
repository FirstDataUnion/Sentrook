"""Which lane a review landed in — one definition, two readers.

§5.2's `sentrook_scan_lane_total`, and the fatigue report's three-lane
counterfactual, are the same question asked live and asked over a log. They
were not the same answer: the report carried its own copy of the read-only
head list, written before the allow families existed as an *approximation* of
them, with a comment saying the real families would replace it. They did not,
and the copy drifted — `sed` stayed after Phase 3b dropped it, `pip3` was
never added, `git branch` and `git remote` stayed after 3b excluded them, and
nothing handled a command whose heads span two families. On the corpus the two
disagreed about **33 of 342** pending-exec rows.

That matters more than a tidiness complaint, because the counterfactual is
what sizes the "library allow rule versus host allowlist" investment split.

So the lane is read off **what actually matched**, which is the only
definition that cannot drift from the rules: an `AIRA-9NN` family matched, or
a rule that names a consequence did, or nothing but the catch-all did.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: Lanes the **scanner** can determine. `host_allowlist` and `script_bind` are
#: not here and cannot be: both are decided in the plugin *after* the scan
#: returns, so a scan-time metric cannot see them. The fatigue report, which
#: reads operator-log rows written after that decision, reports them as well —
#: and says so where it does.
SCANNER_LANES: tuple[str, ...] = ("generic_safe", "consequence", "unknown", "no_argv")

#: The allow families. Matching one means the read-only lane covered it.
_ALLOW_FAMILY = re.compile(r"\AAIRA-9\d\d\Z")

#: The catch-all. Its whole definition is "exec whose consequence no rule can
#: name", so a review holding nothing else *is* the unknown lane.
UNKNOWN_LANE_RULE = "AIRA-010"


def classify_lane(matched_rule_ids: Iterable[str], *, has_argv: bool = True) -> str:
    """Which lane this decision landed in.

    Precedence matters and runs the other way from intuition. A command whose
    consequence a rule can name is **correctly** reviewed and no lane may skip
    it, so `consequence` wins over `generic_safe` — a family matching
    alongside a consequence rule means the family did not suppress it, which
    is the family declining rather than covering.

    `no_argv` is kept separate rather than folded into `unknown`: a row with
    no command text is unclassifiable, not uncovered, and folding it would
    inflate the "needs new coverage" figure and understate every lane.
    """
    if not has_argv:
        return "no_argv"
    ids = {str(rule_id) for rule_id in matched_rule_ids}
    consequence = {
        rule_id
        for rule_id in ids
        if rule_id != UNKNOWN_LANE_RULE and not _ALLOW_FAMILY.match(rule_id)
    }
    if consequence:
        return "consequence"
    if any(_ALLOW_FAMILY.match(rule_id) for rule_id in ids):
        return "generic_safe"
    return "unknown"
