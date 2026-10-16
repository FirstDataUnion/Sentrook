"""Input trust classification (preparation step 4).

The plugin reports facts; Sentrook classifies trust with one open policy. Starting policy (skeleton
section 2, to be revised with TestNest): all `tool_result` content is untrusted (even `ls` output can
carry injected filenames); a `message` is trusted only when its sender is `owner` or `trusted`; a
`subagent_reply` is untrusted; `request.text` is trusted. An input kind the scanner does not know is
untrusted.
"""

from __future__ import annotations

from enum import StrEnum

from ..planir.models import InputKind, NewInput, SenderRelation


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


def classify(inp: NewInput) -> Trust:
    if inp.kind is InputKind.MESSAGE:
        relation = inp.sender.relation if inp.sender else SenderRelation.UNKNOWN
        if relation in (SenderRelation.OWNER, SenderRelation.TRUSTED):
            return Trust.TRUSTED
        return Trust.UNTRUSTED
    return Trust.UNTRUSTED
