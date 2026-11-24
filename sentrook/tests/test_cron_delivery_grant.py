"""A cron job's own delivery target, as the OpenClaw plugin sends it on that job's run.

The plugin reads the job's configured delivery (`discord` to `1519377377082216448`) and sends it as a destination
grant `discord:<channel id>`, scoped to the run's session. The scanner needs nothing new for it: the grant relieves
the run's send to that channel as any destination grant does, and nothing else.
"""

from __future__ import annotations

import pytest
from test_channel_bindings import REVIEW_AT, cron_send, scan

CHANNEL = "1519377377082216448"
RUN_SESSION = "s_cron_daily_brief"


def job_delivery(session_ref: str = RUN_SESSION) -> dict:
    return {
        "grant_ref": "cron_delivery:561a1f55-c5e9-41fb-930b-1ee7b8e31373",
        "kind": "destination",
        "pattern": f"discord:{CHANNEL}",
        "scope": "session",
        "session_ref": session_ref,
    }


def codes(resp) -> set[str]:
    return {r.code for r in resp.reasons}


@pytest.mark.parametrize("target", [f"channel:{CHANNEL}", CHANNEL])
def test_the_runs_send_to_its_jobs_delivery_channel_is_relieved(target):
    """Must fire: the send to the job's own channel, as the message tool writes it or as the bare id."""
    unrelieved = scan(cron_send("discord", target, []))
    resp = scan(cron_send("discord", target, [job_delivery()]))

    assert "relief.destination_grant" in codes(resp)
    assert resp.tree.suspicion.distrust is None
    assert resp.tree.suspicion.untrusted_origin is None
    assert resp.risk < REVIEW_AT <= unrelieved.risk


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(f"channel:{int(CHANNEL) + 1}", id="another-channel"),
        pytest.param(f"user:{CHANNEL}", id="direct-message"),
        pytest.param(f"dm:{CHANNEL}", id="dm"),
    ],
)
def test_a_send_anywhere_else_is_not_relieved(target):
    """Must stay silent: another channel, or a direct message to a person with the same id."""
    unrelieved = scan(cron_send("discord", target, []))
    resp = scan(cron_send("discord", target, [job_delivery()]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unrelieved.risk)


def test_the_grant_lapses_outside_the_run_it_was_sent_for():
    """Must stay silent: the grant is scoped to the job's run; another session's send keeps its distrust."""
    target = f"channel:{CHANNEL}"
    unrelieved = scan(cron_send("discord", target, []))
    resp = scan(cron_send("discord", target, [job_delivery("s_another_run")]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unrelieved.risk)
