"""The disclosure paragraph and the wording check (integrations/docs/docs.py)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import docs  # noqa: E402

# --- the disclosure -----------------------------------------------------------------------------------------------


def test_the_disclosure_says_what_every_listing_must():
    plain = docs.plain("Details.")
    assert docs.missing_phrases(plain) == []
    for fact in (
        "run by First International Data Union Ltd",
        "replaced with placeholders first",
        "including other people's, is sent as it is",
        "OpenRouter and TypeSafe (United States)",
        "metadata logs are kept for up to 60 days",
    ):
        assert fact in plain, fact
    # The plugin's details sit between the shared part and the closing sentence.
    assert plain.endswith("Details. Sentrook is a beta and does not guarantee protection.")
    assert plain.startswith("Disclosure: sends each pending tool call")


def test_the_editing_note_is_not_shipped():
    assert "<!--" in docs.DISCLOSURE_FILE.read_text()
    for text in (docs.markdown("x"), docs.plain("x")):
        assert "<!--" not in text and "{{" not in text


def test_the_readme_form_is_wrapped_and_says_the_same():
    md = docs.markdown("Details.")
    assert md.startswith("**Disclosure:** sends")
    assert all(len(line) <= 120 for line in md.splitlines())
    assert " ".join(md.split()).replace("**Disclosure:**", "Disclosure:") == docs.plain("Details.")


def test_the_listing_readme_carries_the_current_disclosure():
    assert docs.sync(check_only=True) == []
    for rel, details in docs.LISTING_DETAILS.items():
        assert docs.markdown(details) in (docs.REPO / rel).read_text(), rel


def test_the_guides_say_what_is_sent():
    assert docs.guide_problems() == []
    for rel in docs.GUIDES:
        sent = " ".join(docs.section((docs.REPO / rel).read_text(), "What is sent").split())
        for fact in (
            "First International Data Union Ltd",
            "Folder paths can identify you",
            "best effort and can miss some",
            "Other personal data, including other people's, is sent as it is",
            "OpenRouter and TypeSafe (United States)",
            "up to 60 days",
        ):
            assert fact in sent, (rel, fact)


def test_a_stale_block_is_replaced_and_a_missing_one_refused():
    stale = f"# Guide\n\n{docs.START}\nold words\n{docs.END}\n\nmore\n"
    assert (
        docs.synced(stale, "x", "D.")
        == f"# Guide\n\n{docs.START}\n{docs.markdown('D.')}\n{docs.END}\n\nmore\n"
    )
    with pytest.raises(ValueError, match="exactly one"):
        docs.synced("# Guide\n", "x", "D.")
    with pytest.raises(ValueError, match="exactly one"):
        docs.synced(stale + stale, "x", "D.")


@pytest.mark.parametrize("phrase", docs.REQUIRED_PHRASES)
def test_a_text_without_a_required_phrase_is_reported(phrase):
    text = docs.plain("D.").replace(phrase, "x").replace(phrase.capitalize(), "x")
    assert docs.missing_phrases(text) == [phrase]


# --- the wording --------------------------------------------------------------------------------------------------


def test_the_shipped_text_never_says_sentrook_changes_by_itself():
    assert docs.wording_problems() == []


@pytest.mark.parametrize(
    "text",
    [
        "Sentrook asks the owner about calls it has not seen before. It asks less once it knows what is routine here.",
        "Sentrook learns what is routine for you.",
        "It improves as you use it.",
        "Sentrook gets smarter with every scan.",
        "It works out your routine on its own.",
        "It works out your routine on its\nown, after a few days.",
        "Learn more about grants. Sentrook then learns your hosts.",
        "Your data is scrubbed before it is sent.",
        "Personal data is anonymised.",
        "Sentrook meticulously checks every call.",
        "Sentrook is fail-closed.",
    ],
)
def test_a_claim_that_sentrook_changes_by_itself_fails(text):
    assert docs.text_problems(text), text


@pytest.mark.parametrize(
    "text",
    [
        "Learn more about grants in the guide.",
        "Apply or discard it, or send `/learn drafts` in a chat with the agent.",
        "After a turn, Hermes reviews what it learned and saves skills.",
        "OpenClaw saves skills and memory on its own (the Skill Workshop review).",
        "The owner sets grants with `/sentrook grant`; nothing else changes what Sentrook asks.",
    ],
)
def test_true_uses_pass(text):
    assert docs.text_problems(text) == []


def test_a_problem_is_reported_on_the_line_it_starts():
    assert docs.text_problems("Grants.\nBindings.\nSentrook learns.\n") == [(3, "learns")]
