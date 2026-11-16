"""The server or plugin a tool comes from is the host's configuration, not the agent's choice.

`pending_call.provider` is filled in by the host from its own configuration: the agent picks a tool, and
the host says which MCP server or plugin serves it. An entity that is in the call only as that provider
therefore carries no "the agent chose it" origin. It keeps an origin claim when its identity reached the
agent through content it read (the identity itself, or the host of a remote server or the package of a
local one, in the session's untrusted set or in this request's untrusted inputs), and when the call's
own arguments also name it (installing a plugin by name).
"""

from __future__ import annotations

from test_converge_scan import _mcp_case
from test_jev_probes import prepared_for

from sentrook.prepare.entities import EntityKind, Role
from sentrook.probes.context import ContextProbe

LOCAL = "npm:@quayfern/runner-mcp@2.1.0"
REMOTE = "remote:mcp.quayfern.test"


def _origins(p) -> tuple[dict, dict]:
    env = ContextProbe().run(p)
    claims = {c.subject: c for c in env.contributions if c.signal == "suspicion.untrusted_origin"}
    return claims, env.evidence["origins"]


def _provider(p, identity: str):
    ent = p.entities.get(EntityKind.MCP_SERVER, identity)
    assert ent is not None and ent.roles == {Role.TOOL_PROVIDER}
    return ent


# --------------------------------------------------------------------------- must stay silent


def test_a_configured_server_carries_no_origin_claim(twin_case):
    for identity in (LOCAL, REMOTE):
        p = prepared_for(_mcp_case(twin_case, identity, verdict="unknown"))
        provider = _provider(p, identity)
        claims, evidence = _origins(p)
        assert provider.id not in claims, identity
        assert evidence[provider.id] == {"reason": "origin.host_configured_provider"}, identity


def test_a_configured_plugin_carries_no_origin_claim(twin_case):
    case = _mcp_case(twin_case, "fold-runner", verdict="unknown")
    case["fixture"]["pending_call"]["provider"]["kind"] = "plugin"
    case["fixture"]["pending_call"]["tool_kind"] = "other"
    p = prepared_for(case)
    plugin = p.entities.get(EntityKind.PLUGIN, "fold-runner")
    assert plugin.roles == {Role.TOOL_PROVIDER}
    claims, _ = _origins(p)
    assert plugin.id not in claims


# --------------------------------------------------------------------------- must fire


def test_a_server_the_session_holds_as_untrusted_keeps_the_untrusted_origin(twin_case):
    p = prepared_for(_mcp_case(twin_case, LOCAL, verdict="unknown"))
    provider = _provider(p, LOCAL)
    provider.in_session_untrusted = (
        True  # as a token whose untrusted set holds the identity gives it
    )
    claims, _ = _origins(p)
    weight = ContextProbe().params.origin_role_weight[Role.TOOL_PROVIDER.value]
    assert claims[provider.id].reason == "origin.only_in_untrusted"
    assert claims[provider.id].value == weight


def test_a_server_whose_host_or_package_content_named_keeps_its_claim(twin_case):
    # this request's untrusted input names the remote server's host
    case = _mcp_case(twin_case, REMOTE, verdict="unknown")
    case["fixture"]["new_inputs"][0]["content"] = (
        "Point the runner at https://mcp.quayfern.test:8443/sse and run the fold."
    )
    p = prepared_for(case)
    claims, _ = _origins(p)
    assert claims[_provider(p, REMOTE).id].value > 0

    # an earlier step's untrusted content named the local server's package
    case = _mcp_case(twin_case, "npm:fold-runner-mcp@2.1.0", verdict="unknown")
    case["state_seed"] = {**case["state_seed"], "untrusted_entities": ["npm:fold-runner-mcp"]}
    p = prepared_for(case)
    claims, _ = _origins(p)
    assert claims[_provider(p, "npm:fold-runner-mcp@2.1.0").id].value > 0


def test_a_plugin_the_arguments_also_name_keeps_the_agents_choice_origin(twin_case):
    # the call installs a plugin by name through that plugin's own tool: the name is the agent's argument
    case = _mcp_case(twin_case, "fold-runner", verdict="unknown")
    case["fixture"]["pending_call"]["provider"]["kind"] = "plugin"
    case["fixture"]["pending_call"]["tool_kind"] = "other"
    case["fixture"]["pending_call"]["tool"] = "plugin_install"
    case["fixture"]["pending_call"]["arguments"] = {"packages": ["fold-runner"]}
    p = prepared_for(case)
    plugin = p.entities.get(EntityKind.PLUGIN, "fold-runner")
    assert Role.CODE_SOURCE in plugin.roles and Role.TOOL_PROVIDER in plugin.roles
    claims, _ = _origins(p)
    assert claims[plugin.id].reason == "origin.agent_generated"


def test_the_arguments_of_a_served_call_keep_their_own_origin(twin_case):
    # dropping the provider's claim leaves the claim on what the agent put in the arguments
    case = _mcp_case(twin_case, LOCAL, verdict="unknown")
    case["fixture"]["pending_call"]["tool"] = "upload_report"
    case["fixture"]["pending_call"]["arguments"] = {"url": "https://drop.kestrelwade.test/u"}
    p = prepared_for(case)
    host = p.entities.get(EntityKind.HOST, "drop.kestrelwade.test")
    claims, _ = _origins(p)
    assert claims[host.id].reason == "origin.agent_generated"
    assert _provider(p, LOCAL).id not in claims


# --------------------------------------------------------------------------- a provider switch

EARLIER = "npm:@pellmoor/runner-mcp@1.3.0"


def _switch_case(twin_case, identity: str, earlier: str | None, tool: str = "run_fold"):
    """The served call, after an earlier step that called `tool` through `earlier` (no such step when None)."""
    case = _mcp_case(twin_case, identity, verdict="unknown")
    step = case["fixture"]["history"][0]
    if earlier is None:
        case["fixture"]["history"] = []
        case["fixture"]["session"]["step"] = 1
        case["fixture"]["new_inputs"] = []
    else:
        step["tool"] = tool
        step["provider"] = {
            "kind": "mcp",
            "name": "runner",
            "identity": earlier,
            "transport": "stdio",
        }
        step["arguments"] = {"job": "daily"}
        for inp in case["fixture"]["new_inputs"]:
            if inp.get("step") == step["step"] or inp.get("tool"):
                inp["tool"] = tool
    return case


def test_the_provider_the_session_already_used_carries_no_claim(twin_case):
    for identity in (
        EARLIER,
        "npm:@pellmoor/runner-mcp@1.3.1",
    ):  # the same server, or another version of it
        p = prepared_for(_switch_case(twin_case, identity, EARLIER))
        provider = _provider(p, identity)
        claims, evidence = _origins(p)
        assert provider.id not in claims, identity
        assert evidence[provider.id] == {"reason": "origin.host_configured_provider"}, identity


def test_the_first_use_of_a_tool_carries_no_claim(twin_case):
    # no earlier step at all, and an earlier step through another server that called a different tool
    for case in (
        _switch_case(twin_case, LOCAL, None),
        _switch_case(twin_case, LOCAL, EARLIER, tool="list_folds"),
    ):
        p = prepared_for(case)
        claims, _ = _origins(p)
        assert _provider(p, LOCAL).id not in claims


def test_a_switch_to_a_known_good_provider_carries_no_claim(twin_case):
    p = prepared_for(_switch_case(twin_case, LOCAL, EARLIER))
    provider = _provider(p, LOCAL)
    p.oracle_entities = {provider.id: {"verdict": "known_good"}}
    claims, evidence = _origins(p)
    assert provider.id not in claims
    assert evidence[provider.id] == {"reason": "origin.host_configured_provider"}


def test_a_switch_to_a_provider_nothing_vouches_for_keeps_the_agents_choice_origin(twin_case):
    probe = ContextProbe()
    expected = round(
        probe.params.origin_agent_generated
        * probe.params.origin_role_weight[Role.TOOL_PROVIDER.value],
        4,
    )
    for identity, verdict in ((LOCAL, None), (LOCAL, "unknown"), (REMOTE, None)):
        p = prepared_for(_switch_case(twin_case, identity, EARLIER))
        provider = _provider(p, identity)
        if verdict:
            p.oracle_entities = {provider.id: {"verdict": verdict}}
        claims, evidence = _origins(p)
        assert claims[provider.id].reason == "origin.switched_provider", identity
        assert claims[provider.id].value == expected, identity
        assert evidence[provider.id]["switched_from"] == EARLIER, identity


def test_a_switch_from_a_plugin_to_a_server_is_a_switch(twin_case):
    case = _switch_case(twin_case, LOCAL, "fold-runner")
    case["fixture"]["history"][0]["provider"]["kind"] = "plugin"
    p = prepared_for(case)
    claims, _ = _origins(p)
    assert claims[_provider(p, LOCAL).id].reason == "origin.switched_provider"
