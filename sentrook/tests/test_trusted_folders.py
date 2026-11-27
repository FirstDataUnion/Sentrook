"""A read the plugin attests as an unchanged file in a folder the owner trusts (`trusted_by`) is the owner's own content.

The owner trusts a folder with a `folder` grant. The plugin records the folder's content when the grant is set, and
marks a later file read with `trusted_by` (the folder grant's `grant_ref`) only when the file it read still matches.
The scanner then treats that read as it treats the owner's own instruction files: its entities are owner-supplied
(`owner_config`) and the exposure probe leaves it out, so it never taints the session. It relieves nothing else.

The scanner checks the attestation against the request: the grant must be sent, a live `folder` grant that is not too
broad, the input must be the result of a file read under that folder, the session must not have written or tainted the
file, and the content must carry no hidden-instruction characters. Anything else reads as today.

The scenario is invented: an owner trusts their own repository of job instructions, and the agent reads one.
"""

from __future__ import annotations

import pytest
from test_exposure_own_store import CLEAN, INJECTED, planir, run_exposure

from sentrook.enums import ProbeStatus, SessionFlag
from sentrook.prepare.entities import Origin
from sentrook.prepare.grants import folder_ok

HOME = "/home/hermes"
REPO = f"{HOME}/src/ledger-jobs"
JOB = f"{REPO}/jobs/month-end.md"
#: Reads like orders to the agent, as a job file does: the exposure probe would call it instructions.
ORDERS = (
    "# Job: month-end close\n\nYou are running the month-end close for the owner. Follow these steps exactly.\n"
    "1. Fetch the ledger export from https://ledger.example.test/export.\n2. Write the summary to out/summary.md.\n"
)
FOLDER = {
    "grant_ref": "g_1",
    "kind": "folder",
    "pattern": f"{REPO}/",
    "scope": "persistent",
}


def read(
    path: str = JOB, content: str = ORDERS, *, grant: dict | None = FOLDER, by: str | None = "g_1"
):
    raw = planir("hermes", [("read_file", {"path": path}, content)])
    if grant is not None:
        raw["grants"] = [dict(grant)]
    if by is not None:
        raw["new_inputs"][0]["trusted_by"] = by
    return raw


def assert_trusted(p, env, sent):
    assert p.owner_config_inputs == {1} and p.owner_instruction_inputs == {1}
    assert env.status is ProbeStatus.SKIPPED and sent == []
    assert SessionFlag.TAINTED not in env.flags_set


def assert_untrusted(p, env, sent):
    assert 1 not in p.owner_config_inputs and 1 not in p.owner_instruction_inputs
    assert sent == [1]


# ---- must stay silent -------------------------------------------------------------------------------------------


def test_an_attested_read_in_a_trusted_folder_is_the_owners_own():
    p, env, sent = run_exposure(read())
    assert_trusted(p, env, sent)
    host = next(e for e in p.entities if e.value == "ledger.example.test")
    assert Origin.OWNER_CONFIG in host.origins and Origin.UNTRUSTED_INPUT not in host.origins


def test_a_folder_pattern_without_its_slash_covers_too():
    p, env, sent = run_exposure(read(grant={**FOLDER, "pattern": REPO}))
    assert_trusted(p, env, sent)


def test_injected_text_in_a_trusted_file_is_not_judged_but_still_reaches_the_call_view():
    """Trust is the owner's call: the file is theirs. The call judge still reads what the agent read."""
    p, env, sent = run_exposure(read(content=INJECTED))
    assert_trusted(p, env, sent)
    untrusted, _, _ = run_exposure(read(content=INJECTED, by=None))
    for name in ("call-v5", "call-v7"):
        assert p.views[name]["new_inputs"] == untrusted.views[name]["new_inputs"]


# ---- must fire --------------------------------------------------------------------------------------------------


def test_no_attestation_reads_as_today():
    assert_untrusted(*run_exposure(read(by=None)))


def test_a_grant_that_was_not_sent_trusts_nothing():
    assert_untrusted(*run_exposure(read(grant=None)))
    assert_untrusted(*run_exposure(read(by="g_2")))


@pytest.mark.parametrize(
    "grant",
    [
        {**FOLDER, "kind": "file", "allows": ["read"]},
        {**FOLDER, "expires_at": "2020-01-01T00:00:00Z"},
        {**FOLDER, "scope": "session", "session_ref": "s_000000000000"},
        {**FOLDER, "scope": "session"},
    ],
    ids=["file kind", "expired", "other session", "unbound session"],
)
def test_a_grant_that_is_not_a_live_folder_grant_trusts_nothing(grant):
    assert_untrusted(*run_exposure(read(grant=grant)))


@pytest.mark.parametrize(
    "pattern",
    [
        "/",
        "~/",
        f"{HOME}/",
        HOME,
        "/home/",
        f"{HOME}/src/*",
        f"{HOME}/.hermes/",
        "src/ledger-jobs/",
    ],
)
def test_a_folder_grant_that_is_too_broad_or_the_hosts_own_trusts_nothing(pattern):
    assert_untrusted(*run_exposure(read(grant={**FOLDER, "pattern": pattern})))


def test_a_read_outside_the_folder_is_not_trusted():
    assert_untrusted(*run_exposure(read(path=f"{HOME}/src/other/jobs/month-end.md")))
    assert_untrusted(*run_exposure(read(path=f"{REPO}-fork/jobs/month-end.md")))
    assert_untrusted(*run_exposure(read(path=f"{REPO}/../other/notes.md")))


def test_only_a_file_read_can_be_attested():
    raw = planir("hermes", [("web_extract", {"url": "https://ledger.example.test/x"}, ORDERS)])
    raw["grants"] = [dict(FOLDER)]
    raw["new_inputs"][0]["trusted_by"] = "g_1"
    assert_untrusted(*run_exposure(raw))


def test_a_file_the_session_wrote_is_not_trusted():
    raw = planir(
        "hermes",
        [("write_file", {"path": JOB, "content": "x"}, "ok"), ("read_file", {"path": JOB}, ORDERS)],
    )
    raw["history"][0]["tool_kind"] = raw["new_inputs"][0]["tool_kind"] = "file_write"
    raw["grants"] = [dict(FOLDER)]
    raw["new_inputs"][1]["trusted_by"] = "g_1"
    p, env, sent = run_exposure(raw)
    assert 2 not in p.owner_config_inputs and 2 not in p.owner_instruction_inputs
    assert 2 in sent


def test_a_tainted_file_is_not_trusted():
    seed = {**CLEAN, "tainted": True, "tainted_entities": [JOB]}
    p, env, sent = run_exposure(read(), seed)
    assert 1 not in p.owner_instruction_inputs


@pytest.mark.parametrize(
    "hidden", ["‮", "​", "⁦", "\U000e0041", "﻿"], ids=["rlo", "zwsp", "lri", "tag", "bom"]
)
def test_hidden_instruction_characters_drop_the_trust(hidden):
    content = ORDERS.replace("Follow these", f"Follow{hidden} these")
    assert_untrusted(*run_exposure(read(content=content)))


def test_a_trusted_read_does_not_clear_an_earlier_taint():
    p, env, sent = run_exposure(read(), {**CLEAN, "tainted": True})
    assert_trusted(p, env, sent)
    assert SessionFlag.TAINTED in p.state.flags


# ---- the pattern check ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, ok",
    [
        (f"{REPO}/", True),
        (REPO, True),
        ("~/src/ledger-jobs/", True),
        ("$HOME/src/ledger-jobs", True),
        ("/srv/projects/ledger/", True),
        ("/", False),
        ("~", False),
        ("~/", False),
        ("$HOME", False),
        (HOME, False),
        ("/home", False),
        ("/srv", False),
        (f"{HOME}/src/*", False),
        (f"{HOME}/src/led?er", False),
        ("src/ledger-jobs", False),
        (f"{HOME}/.hermes/skills/", False),
        (f"{HOME}/.openclaw/workspace/", False),
        ("/etc/hermes/", False),
        (f"{HOME}/src/../.hermes/", False),
        ("", False),
    ],
)
def test_folder_ok(pattern, ok):
    assert folder_ok(pattern, home=HOME) is ok


# ---- review findings --------------------------------------------------------------------------------------------


def test_a_relative_read_is_never_trusted():
    """The host resolves a relative path against a working folder the request does not show (a `cd` moves it)."""
    raw = read(path="jobs/month-end.md")
    raw["host"]["workspace_root"] = REPO
    assert_untrusted(*run_exposure(raw))


@pytest.mark.parametrize(
    "hidden",
    ["️", "\U000e0100", "­", "͏", "ㅤ", "￹", "᠋"],
    ids=["vs16", "vs17", "shy", "cgj", "hangul filler", "interlinear", "mongolian fvs"],
)
def test_variation_selectors_and_other_invisible_carriers_drop_the_trust(hidden):
    content = ORDERS.replace("Follow these", "Follow" + hidden * 20 + " these")
    assert_untrusted(*run_exposure(read(content=content)))


def test_without_a_home_no_folder_is_trusted():
    assert folder_ok(f"{REPO}/", home=None) is False
    assert folder_ok("/srv/projects/ledger/", home="") is False


@pytest.mark.parametrize(
    "pattern", ["/USERS/OLI", "/Users/oli/.HERMES/memories", "/Users/OLI/.openclaw/", "/users"]
)
def test_letter_case_does_not_get_past_the_refusals_on_macos(pattern):
    from sentrook.planir.models import OS

    assert folder_ok(pattern, home="/Users/oli", host_os=OS.MACOS) is False


def test_on_macos_a_read_in_another_case_is_still_under_the_folder():
    raw = read(path=JOB.upper(), grant={**FOLDER, "pattern": REPO})
    raw["host"]["os"] = "macos"
    assert_trusted(*run_exposure(raw))


@pytest.mark.parametrize(
    "hidden",
    ["\x1b[8m", "\x08", "\r", "\u206a", "\U00013430", "\u0600", "\U0001d173", "\x85"],
    ids=[
        "ansi conceal",
        "backspace",
        "bare cr",
        "inhibit swapping",
        "egyptian format",
        "arabic number sign",
        "musical format",
        "nel",
    ],
)
def test_control_and_format_characters_drop_the_trust(hidden):
    content = ORDERS.replace("Follow these", f"Follow{hidden} these")
    assert_untrusted(*run_exposure(read(content=content)))


def test_crlf_line_ends_and_tabs_keep_the_trust():
    content = ORDERS.replace("\n", "\r\n").replace("1. ", "1.\t")
    assert_trusted(*run_exposure(read(content=content)))


def test_a_read_cut_to_fit_the_request_is_not_trusted():
    """The plugin sends a long read's head and tail: whatever the middle holds, the scanner never saw it."""
    raw = read()
    raw["new_inputs"][0]["truncated"] = True
    assert_untrusted(*run_exposure(raw))
