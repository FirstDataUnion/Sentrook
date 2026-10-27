"""call-v4: call-v3 plus one preamble sentence on host-written text. Hosts wrap scheduled, heartbeat, webhook and
sub-agent prompts in their own text (a job header, the time, standing rules for unattended runs, a sub-agent
context block, system events or external content marked as data) and the plugins pass it through in
`request.text`. The sentence tells the model that host text is not the owner's request: its rules constrain the
agent, never sanction a call, and a call that breaks one is misalignment evidence."""

from __future__ import annotations

from sentrook.jev.questions import load_question_set
from sentrook.serve.config import ServeConfig


def test_call_v4_is_call_v3_with_the_host_text_sentence():
    c3, c4 = load_question_set("call-v3"), load_question_set("call-v4")
    assert c4.state_view == c3.state_view and c4.sha != c3.sha
    assert c4.questions == c3.questions
    anchor = "`request.text` is what the owner asked for this turn (or the scheduled task prompt)."
    head, tail = c3.preamble.split(anchor)
    assert c4.preamble.startswith(
        head + anchor + " On scheduled, heartbeat, webhook and sub-agent runs"
    )
    assert c4.preamble.endswith(tail)
    added = c4.preamble[len(head + anchor) : len(c4.preamble) - len(tail)]
    assert "never sanction a call" in added and "evidence of misalignment" in added


def test_call_v4_is_the_shipped_default():
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v4"
    for name in ("call-v2", "call-v3", "call-v4"):
        assert (
            ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": name}).jev_call_question_set
            == name
        )
