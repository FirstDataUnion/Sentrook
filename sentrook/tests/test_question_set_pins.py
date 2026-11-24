"""The questions a shipped set sends are pinned byte for byte.

A request body's questions are part of the TestNest cache key and of what a recorded result is attributable to, so a
change to how a set is built (not only to its wording) must not move a shipped set's questions. Each pin is the sha256
of the canonical JSON of the set's built questions, as `build_body` sends them (for a set built from blocks, one per
shape of state). A new set adds its pin; an existing pin never changes.
"""

from __future__ import annotations

import hashlib

import pytest

from sentrook.jev.questions import QUESTIONS_DIR, build_body, canonical_json, load_question_set

#: Sets whose preamble goes, whole, in front of every question: the same questions for every state.
PREAMBLE_SET_PINS = {
    "call-v1": "7b09781e6c42b02bcda5a69472c8d2e862956b6d931e1c8fe3f072e3108551bc",
    "call-v2": "ccbfd98b3cf0c5761e480d8f43bd10b32d86ebb0bdc497c57d4c9ecbc3a79655",
    "call-v3": "c47ab94ce7767d25641ef280dfe315aa62f27ad76d238a0248d2d55e3979f397",
    "call-v4": "593a0dddd39edc0fe802d3a890e0a9c8438aa9ade3f5475e5e75355740cff603",
    "call-v5": "e9b1d5823b345c0449101f65bc51234e32d786e29f181f85ba48119d5a2ececf",
    "call-v6": "839e9b06888515a1466de88c666ba3213be63b42729cfeae1b5e6e2e93187b81",
    "call-v7": "6cd31ca2238ee95cd3956436efa737572263c8bb2189d4649a63ba8658296d08",
    "exposure-v1": "6d319e97680423dc9bed2338c9edb809cd8a180b38a716ecfaf75ad89b2e9421",
    "exposure-v2": "6d319e97680423dc9bed2338c9edb809cd8a180b38a716ecfaf75ad89b2e9421",
    "selfedit-v1": "6ccf116b953b6c6a602e3646d88766a3a9664f7d3a4938d948d718bef8ac7416",
    "selfedit-v2": "2223cdcef1d32ab09b8988b4819a2a1b58169b4196753b12fa32a95b5ac4d16b",
    "selfedit-v3": "6a5ead9cf4bf55da7bb352f2118d969fcb549d7415fffe4f10fcda2383cecc98",
}

#: States of every shape a call view sends: none, a batch, a reputation block, both.
STATES = [
    {"pending_call": {"tool": "exec", "arguments": {"command": "ls"}}},
    {"pending_call": {"tool": "exec", "arguments": {}, "batch": {"siblings": [{"tool": "write"}]}}},
    {"pending_call": {"tool": "exec", "arguments": {}}, "reputation": [{"value": "a.example"}]},
    {
        "pending_call": {"tool": "exec", "arguments": {}, "batch": {"siblings": [{}]}},
        "reputation": [{"value": "a.example"}],
    },
]


def _sha(questions: dict) -> str:
    return hashlib.sha256(canonical_json(questions).encode("utf-8")).hexdigest()


@pytest.mark.parametrize(("name", "pin"), sorted(PREAMBLE_SET_PINS.items()))
def test_a_preamble_set_builds_the_questions_it_always_has(name, pin):
    qs = load_question_set(name)
    assert _sha(qs.built_questions()) == pin
    for state in STATES:
        body = build_body(qs, state, model="m", provider={})
        assert _sha(body["questions"]) == pin


#: Sets built from blocks: the questions depend on whether the state has a batch and a reputation block, one pin per
#: state in `STATES` (none, batch, reputation, both).
BLOCK_SET_PINS = {
    "call-v8": (
        "272d79f27aa5578797eca4b49678d48f26811356739ba23c8bf26acc5ad26af8",
        "ece0f3da107899544ef8f7cc55aff0e5589b3839f08e8fdc0bfc6b8397c3bb58",
        "d9ec48dfebd208ec64fc06484828adfa8f6c613bed1dc1441ed7b884db482a14",
        "180f8075cfee54cc92e12af9768707d95348d49b91d282783bb4bff9f95b97ae",
    ),
    "call-v9": (
        "c02b34878a669a8e5602cc57e0c23dec4fed406450c4518c945c6f34b0f829bc",
        "91f9747e6bc569986617701a9898d61d54b6075051f40be8fb7f23d61b9bca6a",
        "6870687a28854de30b343436434e4b1c3e66c28d1a26e86d6e9778a72acd008c",
        "51c8f929bf71f3f4e678adca2d4c480f8a426ff4bdc9913fdfb447e47d58d794",
    ),
    # without a `services` block, call-v10 sends call-v9's questions byte for byte
    "call-v10": (
        "c02b34878a669a8e5602cc57e0c23dec4fed406450c4518c945c6f34b0f829bc",
        "91f9747e6bc569986617701a9898d61d54b6075051f40be8fb7f23d61b9bca6a",
        "6870687a28854de30b343436434e4b1c3e66c28d1a26e86d6e9778a72acd008c",
        "51c8f929bf71f3f4e678adca2d4c480f8a426ff4bdc9913fdfb447e47d58d794",
    ),  # without a `secrets_sent` block (no placeholder in the pending call), call-v11 sends call-v10's questions
    "call-v11": (
        "c02b34878a669a8e5602cc57e0c23dec4fed406450c4518c945c6f34b0f829bc",
        "91f9747e6bc569986617701a9898d61d54b6075051f40be8fb7f23d61b9bca6a",
        "6870687a28854de30b343436434e4b1c3e66c28d1a26e86d6e9778a72acd008c",
        "51c8f929bf71f3f4e678adca2d4c480f8a426ff4bdc9913fdfb447e47d58d794",
    ),
}

#: Sets with a question sent only with a `services` block (`question_when`): the questions with that block alone and
#: with a batch, a reputation block and the services block (the largest form, which `built_questions()` gives).
SERVICES = [{"host": "a.example", "service": ["A"]}]
SERVICES_STATES = [
    {"pending_call": {"tool": "exec", "arguments": {}}, "services": SERVICES},
    {
        "pending_call": {"tool": "exec", "arguments": {}, "batch": {"siblings": [{}]}},
        "reputation": [{"value": "a.example"}],
        "services": SERVICES,
    },
]
SERVICES_SET_PINS = {
    "call-v10": (
        "a604dae1a919230a612201b3d90a6d4c29344e32acd000dd7ba68278255cb22e",
        "5a3f67d8c2488a6e4a57c3054b306bb0c62dd9003a9deef081437b8269032cc6",
    ),
    "call-v11": (
        "a604dae1a919230a612201b3d90a6d4c29344e32acd000dd7ba68278255cb22e",
        "5a3f67d8c2488a6e4a57c3054b306bb0c62dd9003a9deef081437b8269032cc6",
    ),
}


#: Sets with a block sent only when the pending call carries secret placeholders (`secrets_sent`): the questions with
#: that block alone and with every other block too (the largest form, which `built_questions()` gives).
SECRETS_SENT = ["⟦secret:credential:ab12⟧"]
SECRETS_STATES = [
    {"pending_call": {"tool": "exec", "arguments": {}}, "secrets_sent": SECRETS_SENT},
    {
        "pending_call": {"tool": "exec", "arguments": {}, "batch": {"siblings": [{}]}},
        "reputation": [{"value": "a.example"}],
        "services": SERVICES,
        "secrets_sent": SECRETS_SENT,
    },
]
SECRETS_SET_PINS = {
    "call-v11": (
        "c7cd1e9256b80ceb3e0fd76737c903d1366303c6bf1aa00e52bef838ad2b95d2",
        "f14a9bafaa4fd073af741e3f3d8f178fc776e8242a6338e492c4fc1781045c29",
    ),
}


@pytest.mark.parametrize(("name", "pins"), sorted(BLOCK_SET_PINS.items()))
def test_a_block_set_builds_the_questions_pinned_for_each_state_shape(name, pins):
    qs = load_question_set(name)
    for state, pin in zip(STATES, pins, strict=True):
        assert _sha(build_body(qs, state, model="m", provider={})["questions"]) == pin
    # with no state, the largest form: every block, as with both a batch and a reputation block (and a services
    # block and a secrets_sent block, for a set that has them)
    largest = (
        SECRETS_SET_PINS[name][-1]
        if name in SECRETS_SET_PINS
        else SERVICES_SET_PINS[name][-1]
        if name in SERVICES_SET_PINS
        else pins[-1]
    )
    assert _sha(qs.built_questions()) == largest


@pytest.mark.parametrize(("name", "pins"), sorted(SERVICES_SET_PINS.items()))
def test_a_set_with_a_services_question_builds_the_questions_pinned_with_the_block(name, pins):
    qs = load_question_set(name)
    for state, pin in zip(SERVICES_STATES, pins, strict=True):
        assert _sha(build_body(qs, state, model="m", provider={})["questions"]) == pin


@pytest.mark.parametrize(("name", "pins"), sorted(SECRETS_SET_PINS.items()))
def test_a_set_with_a_secrets_sent_block_builds_the_questions_pinned_with_it(name, pins):
    qs = load_question_set(name)
    for state, pin in zip(SECRETS_STATES, pins, strict=True):
        assert _sha(build_body(qs, state, model="m", provider={})["questions"]) == pin


def test_every_shipped_set_is_pinned():
    for path in sorted(QUESTIONS_DIR.glob("*.json")):
        qs = load_question_set(path.stem)
        pins = BLOCK_SET_PINS if qs.blocks else PREAMBLE_SET_PINS
        assert path.stem in pins, path.stem
