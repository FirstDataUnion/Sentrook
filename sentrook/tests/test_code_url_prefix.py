"""A request built inside a helper from a URL whose host is written in the code.

Agent code rarely writes the whole URL at the request call. It defines a small helper that joins a written
base (`'https://api.example.com/v1/' + path`) and calls it for every request. The host of such a URL is known
when the written part reaches past the host (the `/` after it, or a `?` or `#`), whatever the rest is, and a
helper defined and called in the same program is read where its requests are written: a URL in a request body
stays a mention. A host the code computes, a request changed after it is built, a helper this reading cannot
see every call of, or one an earlier step left in the interpreter keeps every host a destination."""

from __future__ import annotations

import pytest
from linear_time import FACTOR, assert_linear
from test_aira_detectors import KEY, planir, run
from test_code_literal_urls import _as_text, _chain, _code, _host_roles, _roles
from test_converge_scan import BENIGN_ANSWERS, CLOCK
from test_credential_home import decide, floors
from test_jev_probes import FakeDecider
from test_session_sets import seed

from sentrook.converge import load_params
from sentrook.prepare import entities
from sentrook.prepare.code_reach import CodeReach, python_reach
from sentrook.prepare.entities import Role
from sentrook.scan import Scanner, ScannerConfig, ScanOptions

API = "api.example.com"
APP = "app.example.com"
OTHER = "other.example.net"
ENV = "/home/me/.agent/.env"

READ_KEY = (
    "import os, json, urllib.request\n"
    "key = [l.split('=',1)[1].strip() for l in open(os.path.expanduser('~/.agent/.env'))"
    " if l.startswith('SERVICE_API_KEY=')][0]\n"
)
REQ_HEAD = "def req(p, body=None, method=None):\n"
REQ_BODY = (
    "    r = urllib.request.Request({url}, data=json.dumps(body).encode() if body is not None else None,"
    " method=method, headers={{'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}})\n"
    "    return json.load(urllib.request.urlopen(r))\n"
)
CALLS = (
    "ds = req('databases/abc')['data_sources'][0]['id']\n"
    "r = req('pages', {'parent': {'data_source_id': ds}, "
    f"'children': [{{'text': 'see [docs](https://{APP}/p/123)'}}]}}, 'POST')\n"
    "print(r['id'])\n"
)


def helper(url: str = f"'https://{API}/v1/' + p", calls: str = CALLS) -> str:
    return READ_KEY + REQ_HEAD + REQ_BODY.format(url=url) + calls


HELPER = helper()


# ------------------------------------------------------------------ must stay a mention


def test_the_helper_posting_a_link_aims_only_at_its_api_host():
    assert python_reach(HELPER) == CodeReach(network=True, targets=frozenset({API}))
    p, _ = run(_code(HELPER))
    assert Role.DATA_DESTINATION in _roles(p, API)
    assert _roles(p, APP) == {Role.MENTIONED}


RESOLVED = {
    "f-string with a written prefix": helper("f'https://" + API + "/v1/{p}'"),
    "str.format": helper("'https://" + API + "/v1/{}'.format(p)"),
    "percent format": helper("'https://" + API + "/v1/%s' % p"),
    "a written base name": helper("BASE + p").replace(
        REQ_HEAD, f"BASE = 'https://{API}/v1/'\n" + REQ_HEAD
    ),
    "a query string after the host": helper("'https://" + API + "?path=' + p"),
    "urljoin with a written relative path": (
        "import requests\nfrom urllib.parse import urljoin\n"
        f"requests.post(urljoin('https://{API}/v1/', 'pages'), json={{'u': 'https://{APP}/p'}})"
    ),
    "urllib.parse.urljoin, a base built from a prefix": (
        "import sys, urllib.request\n"
        f"u = urllib.parse.urljoin('https://{API}/v1/' + sys.argv[1], '../pages?x=1')\n"
        f"urllib.request.urlopen(urllib.request.Request(u, data=b'https://{APP}/p'))"
    ),
    # every call passes a URL the code writes
    "the URL as an argument, every call written": (
        "import requests\ndef send(u, body):\n    return requests.post(u, json=body)\n"
        f"send('https://{API}/v1/a', {{'t': 'https://{APP}/p'}})\n"
        f"send(u='https://{API}/v1/b', body={{}})"
    ),
    "a default base": (
        f"import requests\ndef send(p, base='https://{API}/v1/'):\n"
        "    return requests.post(base + p, json={'t': 'https://" + APP + "/p'})\n"
        "send('pages')\nsend('pages/1')"
    ),
    # a helper named like a request call is the program's own function, not a request
    "a helper named post": (
        "import requests\ndef post(p, body):\n"
        f"    return requests.post('https://{API}/v1/' + p, json=body)\n"
        f"post('pages', {{'t': 'https://{APP}/p'}})"
    ),
    "a lambda with a written prefix": (
        "import requests\n"
        f"get = lambda p: requests.get('https://{API}/v1/' + p)\n"
        f"print(get('pages'), 'https://{APP}/p')"
    ),
    # a module-level name shares the helper's local name: each is read in its own scope
    "a local name reused at module level": HELPER.replace(
        "print(r['id'])", "r = r['id']\nprint(r)"
    ),
}


@pytest.mark.parametrize("code", RESOLVED.values(), ids=RESOLVED.keys())
def test_a_written_prefix_names_the_host(code):
    assert python_reach(code) == CodeReach(network=True, targets=frozenset({API}))
    p, _ = run(_code(code))
    assert Role.DATA_DESTINATION not in _roles(p, APP)


# ------------------------------------------------------------------ must fire

FIRES = {
    # the written part stops at the host: the rest could be `.evil.net` or `@evil.net`
    "a prefix that stops at the host": helper(
        f"'https://{API}' + p", calls=CALLS.replace("req(", "req(os.environ['P'] + ", 1)
    ),
    "a computed host": (
        "import requests, sys\nhost = sys.argv[1]\n"
        f"requests.post('https://' + host + '/v1', data='https://{APP}/p')"
    ),
    "an f-string host": helper("f'https://{p}/v1'"),
    "format into the host": helper("'https://{}/v1/'.format(p)"),
    "percent into the host": helper("'https://%s/v1/' % p"),
    "urljoin with an absolute second URL": (
        "import requests\nfrom urllib.parse import urljoin\n"
        f"base = 'https://{API}/v1/'\nrequests.post(urljoin(base, 'https://{OTHER}/x'), data='https://{APP}/p')"
    ),
    "urljoin with a computed second URL": (
        "import requests, sys\nfrom urllib.parse import urljoin\n"
        f"requests.post(urljoin('https://{API}/v1/', sys.argv[1]), data='https://{APP}/p')"
    ),
    "urljoin with a network-path second URL": (
        "import requests\nfrom urllib.parse import urljoin\n"
        f"requests.post(urljoin('https://{API}/v1/', '//{OTHER}/x'), data='https://{APP}/p')"
    ),
    "urljoin with a padded network-path second URL": (
        "import requests\nfrom urllib.parse import urljoin\n"
        f"requests.post(urljoin('https://{API}/v1/', ' //{OTHER}/x'), data='https://{APP}/p')"
    ),
    "a urljoin the program defines": (
        "import requests\ndef urljoin(a, b):\n    return b\n"
        f"requests.post(urljoin('https://{API}/v1/', 'x'), data='https://{OTHER}/p')"
    ),
    # a helper whose URL is a parameter, with a call this reading cannot resolve
    "a helper passed a computed URL": (
        "import requests, sys\ndef send(u):\n    return requests.post(u, data='x')\n"
        f"send('https://{API}/v1/a')\nsend(sys.argv[1])\nprint('https://{APP}/p')"
    ),
    "a helper passed around": (
        "import requests\ndef send(u):\n    return requests.post(u, data='x')\n"
        f"list(map(send, ['https://{API}/v1/a', 'https://{APP}/p']))"
    ),
    "a helper called with unpacked arguments": (
        "import requests\ndef send(u):\n    return requests.post(u, data='x')\n"
        f"send(*['https://{APP}/p'])\nsend('https://{API}/v1/a')"
    ),
    "a decorated helper": (
        "import requests, functools\n@functools.lru_cache\ndef send(u):\n"
        f"    return requests.post(u, data='x')\nsend('https://{API}/v1/a')\nprint('https://{APP}/p')"
    ),
    "a method with the URL as a parameter": (
        "import requests\nclass C:\n    def send(self, u):\n        return requests.post(u, data='x')\n"
        f"C().send('https://{APP}/p')"
    ),
    # the request is changed after the helper builds it
    "full_url changed": helper(f"'https://{API}/v1/' + p").replace(
        "    return json.load", f"    r.full_url = 'https://{OTHER}/x'\n    return json.load"
    ),
    "host changed": helper(f"'https://{API}/v1/' + p").replace(
        "    return json.load", f"    r.host = '{OTHER}'\n    return json.load"
    ),
    # a `Request` of the program's own may return any URL
    "a Request the program defines": (
        f"from urllib.request import urlopen\ndef Request(u):\n    return 'https://{OTHER}/x'\n"
        f"urlopen(Request('https://{API}/v1/', data=b'https://{APP}/p'))"
    ),
    "a Request method of a class": (
        "import urllib.request\nclass K:\n    def Request(self, u):\n"
        f"        return 'https://{OTHER}/x'\n"
        f"urllib.request.urlopen(K().Request('https://{API}/v1/'), data=b'https://{APP}/p')"
    ),
    # a global the helper reads, changed inside another function
    "a global set in another function": (
        f"import requests\nU = 'https://{API}/v1/'\n"
        f"def move():\n    global U\n    U = 'https://' + input()\n"
        "def send(p):\n    return requests.post(U + p, data='x')\n"
        f"move()\nsend('pages')\nprint('https://{APP}/p')"
    ),
}


@pytest.mark.parametrize("code", FIRES.values(), ids=FIRES.keys())
def test_a_host_this_reading_cannot_pin_keeps_every_host(monkeypatch, code):
    reach = python_reach(code)
    assert reach is not None and reach.network and reach.targets is None
    p, env = run(_code(code))
    p_old, _ = _as_text(monkeypatch, code)
    assert _host_roles(p) == _host_roles(p_old)


def test_a_global_set_in_another_function_is_never_left_out():
    code = (
        f"import requests\nU = 'https://{API}/v1/'\n"
        f"def move():\n    global U\n    U = 'https://{OTHER}/x/'\n"
        "def send(p):\n    return requests.post(U + p, data='x')\n"
        f"move()\nsend('pages')\nprint('https://{APP}/p')"
    )
    reach = python_reach(code)
    assert reach is not None and (reach.targets is None or OTHER in reach.targets)


def test_a_name_set_in_an_enclosing_function_is_never_left_out():
    code = (
        "import requests\ndef outer():\n"
        f"    u = 'https://{API}/v1/'\n"
        "    def move():\n        nonlocal u\n"
        f"        u = 'https://{OTHER}/x/'\n"
        "    move()\n    return requests.post(u + 'p', data='x')\n"
        f"outer()\nprint('https://{APP}/p')"
    )
    reach = python_reach(code)
    assert reach is not None and (reach.targets is None or OTHER in reach.targets)


def test_every_written_url_an_argument_takes_is_a_target():
    code = (
        "import requests\ndef send(u):\n    return requests.post(u, data='x')\n"
        f"send('https://{API}/v1/a')\nsend('https://{OTHER}/b')\nprint('https://{APP}/p')"
    )
    assert python_reach(code) == CodeReach(network=True, targets=frozenset({API, OTHER}))


def test_a_helper_defined_at_an_earlier_step_is_not_followed(monkeypatch):
    """The interpreter keeps the helper between calls; its definition is not in the later program, which
    keeps the text reading."""
    define = READ_KEY + REQ_HEAD + REQ_BODY.format(url=f"'https://{API}/v1/' + p")
    assert python_reach(CALLS) == CodeReach(network=True)
    result = _chain(define, CALLS)
    with monkeypatch.context() as m:
        m.setattr(entities, "python_reach", lambda _source: None)
        as_text = _chain(define, CALLS)
    assert _host_roles(result.prepared) == _host_roles(as_text.prepared)
    assert _host_roles(result.prepared)[APP] != {Role.MENTIONED}


def test_reading_helper_calls_grows_linearly():
    """Many calls of one helper, each passing a written URL (see linear_time.py)."""
    head = "import requests\ndef send(u, b):\n    return requests.post(u, json=b)\n"
    unit = "send('https://a{i}.example.net/v1/' + str({i}), {{'t': 'https://b{i}.example.net'}})\n"
    texts = {d: head + "".join(unit.format(i=i) for i in range(2000 // d)) for d in (1, FACTOR)}
    _, large = assert_linear(lambda d: python_reach(texts[d]), unit)
    assert large < 2.0


# ------------------------------------------------------------------ the credential-home check, through a scan

HOME = {
    "kind": "host",
    "value": API,
    "verdict": "known_good",
    "tier": "provider_api",
    "roles": ["data_destination", "data_source"],
    "credential_names": ["SERVICE_API_KEY"],
}
HELD = seed(holds_sensitive=True, sensitive_entities=[ENV])
REQUEST = "Add a page to my notes database linking the docs."


def _scan(code: str, params: str | None = None):
    raw = planir("execute_code", "exec", {"code": code}, platform="hermes", request=REQUEST)
    extra = {} if params is None else {"params": load_params(params)}
    scanner = Scanner(ScannerConfig(token_key=KEY, decider=FakeDecider(BENIGN_ANSWERS), **extra))
    return scanner.scan(
        raw,
        ScanOptions(
            deterministic=True,
            clock=CLOCK,
            salt="testnest",
            state_seed=HELD,
            oracle_seed={"entities": [HOME]},
        ),
    )


@pytest.mark.parametrize("params", ["conv-v7", "conv-v9"])
def test_the_helper_with_a_link_in_its_body_keeps_its_key_home(params):
    res = _scan(HELPER, params)
    assert res.prepared.credential_home_check == "ok"
    assert res.prepared.credential_home is not None
    assert "sensitive_data_sent" not in floors(res)
    assert decide(res.response) != "block"


def test_a_helper_whose_host_is_not_pinned_still_takes_the_floor():
    """The written part stops at the host: the link's host stays a party the key may reach."""
    res = _scan(helper(f"'https://{API}' + p"), "conv-v7")
    assert res.prepared.credential_home is None
    assert res.prepared.credential_home_check == "unlisted_host"
    assert "sensitive_data_sent" in floors(res)
