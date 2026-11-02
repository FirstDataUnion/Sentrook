"""Near misses in the entity oracle: an unlisted entity one slip away from a `known_good` one (another
TLD, a hyphen, a confusable character, one edit) is reported with the entry it imitates, the oracle probe
gives it the near-miss distrust where it takes data, code or tools, and the call-v5 view lists it under
`reputation`. call-v4 and earlier send exactly what they sent before."""

from __future__ import annotations

import copy
import json

import httpx
import pytest
from test_converge_scan import BENIGN_ANSWERS, KEY, options
from test_jev_probes import ATTACK_ANSWERS, FakeDecider, prepared_for

from sentrook.converge.registry import REASONS
from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import load_question_set
from sentrook.oracle.client import EntityQuery, HttpOracle, Match, SeedOracle, VerdictKind
from sentrook.oracle.near_miss import near_miss_of
from sentrook.prepare.views import CALL_V3, CALL_V5, REPUTATION, VIEW_KEYS
from sentrook.probes.base import Envelope
from sentrook.probes.oracle import EntityOracleProbe, verdicts_for_view
from sentrook.scan import Scanner, ScannerConfig
from sentrook.serve.config import ServeConfig

# The rule's table. Rookery's oracle carries the same rows: keep the
# two in step.
# (kind, query, known_good entries, expected (entry, how) or None)
NEAR_MISS_CASES = [
    # must fire
    (
        "host",
        "reports.cindervale.io",
        ["reports.cindervale.net"],
        ("reports.cindervale.net", "tld"),
    ),
    ("host", "foo.cindervale.co.uk", ["cindervale.com"], ("cindervale.com", "tld")),
    ("host", "sync.fern-mere.net", ["sync.fernmere.net"], ("sync.fernmere.net", "fold")),
    (
        "host",
        "reports.cinder-vale.net",
        ["reports.cindervale.net"],
        ("reports.cindervale.net", "fold"),
    ),
    ("host", "get.q7-mlrth.net", ["get.q7-mirth.net"], ("get.q7-mirth.net", "fold")),
    (
        "host",
        "files.tallowrnere.example",
        ["files.tallowmere.example"],
        ("files.tallowmere.example", "fold"),
    ),
    ("host", "cl0ud-sync.io", ["cloud-sync.io"], ("cloud-sync.io", "fold")),
    ("host", "cindervalle.net", ["cindervale.net"], ("cindervale.net", "edit")),
    ("host", "cindervale.io", ["cindervale.org", "cindervale.net"], ("cindervale.net", "tld")),
    ("host", "cinder-vale.net", ["cindervale.net", "cinder-vale.org"], ("cinder-vale.org", "tld")),
    (
        "mcp_server",
        "npm:@brindlfen/runner-mcp@2.1.0",
        ["npm:@brindlefen/runner-mcp@2.1.0"],
        ("npm:@brindlefen/runner-mcp@2.1.0", "edit"),
    ),
    (
        "mcp_server",
        "npm:@moss-barrow/build-mcp@1.0.4",
        ["npm:@mossbarrow/build-mcp@1.0.4"],
        ("npm:@mossbarrow/build-mcp@1.0.4", "fold"),
    ),
    (
        "mcp_server",
        "npm:@quench1ane/desk-mcp@0.9.2",
        ["npm:@quenchlane/desk-mcp@0.9.2"],
        ("npm:@quenchlane/desk-mcp@0.9.2", "fold"),
    ),
    ("package", "npm:expresss", ["npm:express"], ("npm:express", "edit")),
    ("package", "pypi:requestss", ["pypi:requests"], ("pypi:requests", "edit")),
    ("plugin", "openclaw-tallow-sync", ["openclaw-tallowsync"], ("openclaw-tallowsync", "fold")),
    (
        "recipient",
        "lists@mail.hallow-mere.net",
        ["lists@mail.hallowmere.net"],
        ("lists@mail.hallowmere.net", "fold"),
    ),
    (
        "recipient",
        "lists@mail.hallowmere.io",
        ["lists@mail.hallowmere.net"],
        ("lists@mail.hallowmere.net", "tld"),
    ),
    ("recipient", "@relay-keel", ["@relay.keel"], ("@relay.keel", "fold")),
    # must stay silent
    ("host", "reports.cindervale.net", ["reports.cindervale.net"], None),
    ("host", "api.cindervale.net", ["reports.cindervale.net"], None),
    ("host", "cindervale.net", ["reports.cindervale.net"], None),
    ("host", "reports.cindervale.io", ["cindervale.io", "reports.cindervale.net"], None),
    ("host", "pypl.org", ["pypi.org"], None),
    ("host", "10.0.0.12", ["10.0.0.13"], None),
    ("host", "totally.unrelated.net", ["reports.cindervale.net"], None),
    ("host", "cindervale.net", [], None),
    (
        "mcp_server",
        "npm:@brindlefen/runner-mcp@2.2.0",
        ["npm:@brindlefen/runner-mcp@2.1.0"],
        None,
    ),
    ("mcp_server", "https://mcp.cindervale.io/sse", ["https://mcp.cindervale.net/sse"], None),
    ("package", "pypi:requestss", ["npm:requests"], None),
    ("package", "npm:lefty", ["npm:left"], None),
    ("package", "npm:@acme/cli", ["npm:@acme/clj"], None),
    ("recipient", "alice@mail.hallow-mere.net", ["lists@mail.hallowmere.net"], None),
    ("recipient", "lists@mail.hallowmere.net", ["@relay.keel"], None),
    ("recipient", "@relay", ["@relay.keel"], None),
    ("channel", "slack:#rel-ops", ["slack:#relops"], None),
    ("host", "build02.acme-internal.net", ["build01.acme-internal.net"], None),
    ("host", "build02internal.net", ["build01internal.net"], None),
    ("recipient", "+15551234568", ["+15551234567"], None),
    ("host", "cl0udsync.io", ["cloudsync.io"], ("cloudsync.io", "fold")),
    ("host", "cloudsync2.io", ["cloudsync.io"], ("cloudsync.io", "edit")),
    ("package", "docker:node:22", ["docker:node:20"], None),
    ("package", "docker:node:22-alpine", ["docker:node:20-alpine"], None),
    ("package", "docker:ghcr.io/acme/app:1.3", ["docker:ghcr.io/acme/app:1.2"], None),
    ("package", "docker:localhost:5000/postgres:16", ["docker:localhost:5000/postgres:15"], None),
    ("package", "docker:node@sha256:abc123", ["docker:node:20"], None),
    ("package", "docker:pstgres:16", ["docker:postgres:15"], ("docker:postgres:15", "edit")),
    ("package", "pypi:python_dateutil@2.8", ["pypi:python-dateutil"], None),
    ("mcp_server", "pypi:mcp_server_fetch", ["pypi:mcp-server-fetch"], None),
    (
        "mcp_server",
        "pypi:mcp-server-fetcch",
        ["pypi:mcp-server-fetch"],
        ("pypi:mcp-server-fetch", "edit"),
    ),
]


@pytest.mark.parametrize("kind,query,listed,expected", NEAR_MISS_CASES)
def test_near_miss_rule(kind, query, listed, expected):
    assert near_miss_of(kind, query, listed) == expected


def test_against_a_popular_package_only_fold_counts():
    popular = {"pypi:pillow"}
    assert near_miss_of("package", "pypi:willow", ["pypi:pillow"]) == ("pypi:pillow", "edit")
    assert near_miss_of("package", "pypi:willow", ["pypi:pillow"], popular) is None
    assert near_miss_of("package", "pypi:pil-low", ["pypi:pillow"], popular) == (
        "pypi:pillow",
        "fold",
    )
    assert near_miss_of("package", "pypi:pi11ow", ["pypi:pillow"], popular) == (
        "pypi:pillow",
        "fold",
    )
    # another entry that is not popular still takes an edit
    assert near_miss_of("package", "pypi:willow", ["pypi:pillow", "pypi:wilow"], popular) == (
        "pypi:wilow",
        "edit",
    )


# --------------------------------------------------------------------------- the clients


def _seed(*entries):
    return {"entities": [dict(e) for e in entries]}


def test_seed_oracle_reports_a_near_miss_of_a_known_good_entry():
    o = SeedOracle(
        _seed(
            {"kind": "host", "value": "reports.cindervale.io", "verdict": "unknown"},
            {
                "kind": "host",
                "value": "Reports.Cindervale.net",
                "verdict": "known_good",
                "tier": "org",
            },
            {
                "kind": "host",
                "value": "paste.cindervale.org",
                "verdict": "unknown",
                "distrust": 0.6,
            },
            {"kind": "host", "value": "bad-cindervale.net", "verdict": "known_bad"},
        )
    )
    r = o.lookup(
        [
            EntityQuery("host", "reports.cindervale.io"),
            EntityQuery("host", "reports.cindervale.net"),
            EntityQuery("host", "paste.cindervale.org"),
            EntityQuery("host", "bad-cindervale.net"),
            EntityQuery("host", "elsewhere.example"),
        ]
    )
    near = r.get("host", "reports.cindervale.io")
    assert near.verdict is VerdictKind.UNKNOWN and near.match is Match.NEAR_MISS
    assert near.near_miss == {
        "value": "reports.cindervale.net",
        "verdict": "known_good",
        "tier": "org",
        "how": "tld",
    }
    good = r.get("host", "reports.cindervale.net")
    assert good.match is Match.EXACT and good.near_miss is None
    # a watched entry is an exact answer; a known_bad entry is never a near-miss target
    watched = r.get("host", "paste.cindervale.org")
    assert watched.match is Match.EXACT and watched.near_miss is None and watched.distrust == 0.6
    bad = r.get("host", "bad-cindervale.net")
    assert bad.verdict is VerdictKind.KNOWN_BAD and bad.match is Match.EXACT
    none = r.get("host", "elsewhere.example")
    assert none.match is Match.NONE and none.near_miss is None


def test_seed_oracle_near_miss_of_a_known_bad_entry_is_none():
    o = SeedOracle(_seed({"kind": "package", "value": "npm:pellam-loggr", "verdict": "known_bad"}))
    v = o.lookup([EntityQuery("package", "npm:pellam-logger")]).get("package", "npm:pellam-logger")
    assert v.verdict is VerdictKind.UNKNOWN and v.match is Match.NONE and v.near_miss is None


def _http_oracle(payload: dict) -> HttpOracle:
    o = HttpOracle("http://rookery.test")
    o._http = httpx.Client(
        base_url="http://rookery.test",
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload)),
    )
    return o


def test_http_oracle_reads_match_and_near_miss():
    near = {"value": "reports.cindervale.net", "verdict": "known_good", "how": "tld"}
    o = _http_oracle(
        {
            "verdicts": [
                {
                    "kind": "host",
                    "value": "reports.cindervale.io",
                    "verdict": "unknown",
                    "match": "near_miss",
                    "near_miss": near,
                },
                {"kind": "host", "value": "a.example", "verdict": "known_good", "match": "exact"},
                {"kind": "host", "value": "b.example", "verdict": "unknown", "match": "near_miss"},
                {"kind": "host", "value": "c.example", "verdict": "unknown", "match": "sideways"},
                {"kind": "host", "value": "d.example", "verdict": "unknown"},
            ],
            "library_snapshot": "lib-v3-abc",
        }
    )
    r = o.lookup([EntityQuery("host", v) for v in ("reports.cindervale.io", "a.example")])
    v = r.get("host", "reports.cindervale.io")
    assert v.match is Match.NEAR_MISS and v.near_miss == near
    assert r.get("host", "a.example").match is Match.EXACT
    # a near miss without its entry is not one; an unknown match value and an older Rookery say nothing
    assert (
        r.get("host", "b.example").match is Match.NONE
        and r.get("host", "b.example").near_miss is None
    )
    assert r.get("host", "c.example").match is None
    assert r.get("host", "d.example").match is None


# --------------------------------------------------------------------------- the probe


def _lookalike_seed(attack_case, distrust=None):
    """The worked attack sends to cl0ud-sync.io; the library vouches for cloud-sync.io."""
    entry = {"kind": "host", "value": "cl0ud-sync.io", "verdict": "unknown"}
    if distrust is not None:
        entry["distrust"] = distrust
    return _seed(entry, {"kind": "host", "value": "cloud-sync.io", "verdict": "known_good"})


def _host_contribution(env, value):
    ent_id = next(k for k, v in env.evidence["entities"].items() if v["value"] == value)
    return ent_id, next(
        c for c in env.contributions if c.signal == "suspicion.distrust" and c.subject == ent_id
    )


def test_probe_gives_a_near_miss_destination_the_near_miss_distrust(attack_case):
    p = prepared_for(attack_case)
    env = EntityOracleProbe(SeedOracle(_lookalike_seed(attack_case))).run(p)
    ent_id, c = _host_contribution(env, "cl0ud-sync.io")
    assert c.value == 0.9 and c.reason == "reputation.near_miss_host"
    info = env.evidence["entities"][ent_id]
    assert info["verdict"] == "unknown" and info["match"] == "near_miss"
    assert info["near_miss"] == {"value": "cloud-sync.io", "verdict": "known_good", "how": "fold"}
    assert not env.floors  # distrust only, never a floor
    # still unknown: coverage is lowered as for any unknown destination
    cov = [c for c in env.contributions if c.signal == "confidence.coverage"]
    assert cov[0].value == 0.8
    assert "reputation.near_miss_host" in REASONS


def test_probe_without_a_near_miss_keeps_the_unknown_distrust(attack_case):
    p = prepared_for(attack_case)
    seed = _seed({"kind": "host", "value": "cl0ud-sync.io", "verdict": "unknown"})
    env = EntityOracleProbe(SeedOracle(seed)).run(p)
    _, c = _host_contribution(env, "cl0ud-sync.io")
    assert c.value == 0.5 and c.reason == "reputation.unknown_host_as_data_destination"
    # a watched entry keeps its own distrust: it is an exact answer
    env = EntityOracleProbe(SeedOracle(_lookalike_seed(attack_case, distrust=0.4))).run(p)
    _, c = _host_contribution(env, "cl0ud-sync.io")
    assert c.value == 0.4 and c.reason == "reputation.unknown_host_as_data_destination"


def test_probe_near_miss_read_from_keeps_the_unknown_distrust(twin_case):
    # The twin only reads from the look-alike here: a data source is not a near-miss role.
    p = prepared_for(twin_case)
    host = next(e for e in p.entities if e.kind.value == "host" and e.value == "backup.mycorp.com")
    from sentrook.prepare.entities import Role

    host.roles.clear()
    host.roles.add(Role.DATA_SOURCE)
    seed = _seed({"kind": "host", "value": "backup.mycorp.io", "verdict": "known_good"})
    env = EntityOracleProbe(SeedOracle(seed)).run(p)
    ent_id, c = _host_contribution(env, "backup.mycorp.com")
    assert env.evidence["entities"][ent_id]["match"] == "near_miss"
    assert c.value == 0.2 and c.reason == "reputation.unknown_host_as_data_source"


# --------------------------------------------------------------------------- the call-v5 view


def _envelope(entities: dict) -> Envelope:
    return Envelope(
        step=ProbeStep.ENTITY_ORACLE,
        versions={},
        status=ProbeStatus.OK,
        latency_ms=0.0,
        evidence={"entities": entities},
    )


def test_verdicts_for_view_lists_near_misses_only_when_asked():
    env = _envelope(
        {
            "E1": {
                "kind": "host",
                "value": "reports.cindervale.io",
                "verdict": "unknown",
                "match": "near_miss",
                "near_miss": {
                    "value": "reports.cindervale.net",
                    "verdict": "known_good",
                    "how": "tld",
                },
            },
            "E2": {"kind": "host", "value": "z.example", "verdict": "known_good", "match": "exact"},
            "E3": {"kind": "host", "value": "u.example", "verdict": "unknown", "match": "none"},
        }
    )
    assert verdicts_for_view(env) == [
        {"kind": "host", "value": "z.example", "verdict": "known_good"}
    ]
    assert verdicts_for_view(env, near_miss=True) == [
        {
            "kind": "host",
            "value": "reports.cindervale.io",
            "verdict": "unknown",
            "near_miss": "reports.cindervale.net",
        },
        {"kind": "host", "value": "z.example", "verdict": "known_good"},
    ]


def _scan(case, call_question_set, answers):
    dec = FakeDecider(answers)
    jev = JevConfig(exposure_question_set="exposure-v2", call_question_set=call_question_set)
    res = Scanner(ScannerConfig(token_key=KEY, decider=dec, jev=jev)).scan(
        case["fixture"], options(case)
    )
    return res, [b for b in dec.bodies if "pending_call" in b["state"]]


def test_call_v5_sends_the_near_miss_and_call_v4_does_not(attack_case):
    case = copy.deepcopy(attack_case)
    case["oracle_seed"] = _lookalike_seed(attack_case)
    res, [body] = _scan(case, "call-v5", ATTACK_ANSWERS)
    assert body["state"][REPUTATION] == [
        {
            "kind": "host",
            "value": "cl0ud-sync.io",
            "verdict": "unknown",
            "near_miss": "cloud-sync.io",
        }
    ]
    call_env = next(e for e in res.envelopes if e.step is ProbeStep.JEV_CALL)
    assert call_env.evidence["view"] == CALL_V5 and call_env.evidence["reputation_entries"] == 1
    assert res.response.metadata.versions["views"] == "exposure:trim-v2,call:trim-v4"

    # call-v4 sends the call-v3 view exactly as before: no block, since nothing is known_good or bad
    v4, [body4] = _scan(case, "call-v4", ATTACK_ANSWERS)
    assert REPUTATION not in body4["state"]
    assert {k: v for k, v in body["state"].items() if k != REPUTATION} == body4["state"]

    # the probe's score does not depend on the view
    def distrust(r):
        env = next(e for e in r.envelopes if e.step is ProbeStep.ENTITY_ORACLE)
        return sorted((c.reason, c.value) for c in env.contributions)

    assert distrust(res) == distrust(v4)


def test_call_v5_without_a_near_miss_sends_what_call_v4_sends(twin_case):
    case = copy.deepcopy(twin_case)
    case["fixture"]["grants"] = []
    _, [b5] = _scan(case, "call-v5", BENIGN_ANSWERS)
    _, [b4] = _scan(case, "call-v4", BENIGN_ANSWERS)
    assert json.dumps(b5["state"], sort_keys=True) == json.dumps(b4["state"], sort_keys=True)


def test_call_v5_is_call_v4_with_the_near_miss_sentences():
    c4, c5 = load_question_set("call-v4"), load_question_set("call-v5")
    assert c4.state_view == CALL_V3 and c5.state_view == CALL_V5
    assert VIEW_KEYS[CALL_V5] == VIEW_KEYS[CALL_V3]
    anchor = "A host that is not listed there is simply not vouched for."
    assert c4.preamble.endswith(anchor)
    assert c5.preamble.startswith(
        c4.preamble + " An entry with `verdict` `unknown` and a `near_miss`"
    )
    assert list(c5.questions) == list(c4.questions)
    for name, q4 in c4.questions.items():
        q5 = c5.questions[name]
        if name == "supported_by_request":
            assert q5["criteria"] == q4["criteria"]
            assert (
                q5["instructions"].replace(
                    " Nor is a `near_miss` entry: it imitates the `known_good` one and never stands in"
                    " for it.",
                    "",
                )
                == q4["instructions"]
            )
            continue
        assert {k: v for k, v in q5.items() if k != "state_view"} == {
            k: v for k, v in q4.items() if k != "state_view"
        }, name


def test_call_v5_is_the_shipped_default():
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v5"
    for name in ("call-v3", "call-v4", "call-v5"):
        assert (
            ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": name}).jev_call_question_set
            == name
        )


def test_seed_oracle_takes_only_fold_against_a_popular_package():
    o = SeedOracle(
        _seed(
            {"kind": "package", "value": "pypi:pillow", "verdict": "known_good", "tier": "popular"}
        )
    )
    r = o.lookup([EntityQuery("package", "pypi:willow"), EntityQuery("package", "pypi:pil_low")])
    assert r.get("package", "pypi:willow").match is Match.NONE
    near = r.get("package", "pypi:pil_low")
    assert near.match is Match.NEAR_MISS and near.near_miss["how"] == "fold"
