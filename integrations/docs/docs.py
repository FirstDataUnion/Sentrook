"""Checks on the text owners read before and after installing a Sentrook plugin.

1. The disclosure paragraph: written once in `disclosure.md`. Each store listing carries it, with that plugin's own
   details in the middle: the Hermes catalog description takes it at release (`plain()`), and the OpenClaw package
   README, which is the ClawHub and npm listing, holds a copy between markers (`sync`). The install guides' "What is
   sent" sections say the same in more detail. A listing or guide that lacks any of `REQUIRED_PHRASES` must not be
   published.
2. Wording: the guides, skills, agent rules, manifests and listing text must not say Sentrook learns, improves or
   changes by itself, nor use words that promise more than redaction does. Today only what the owner sets (bindings
   and grants, by command or by answering Always on a review) carries over; a sentence that says otherwise describes
   behaviour that does not exist.

    python3 integrations/docs/docs.py sync    # copy disclosure.md into the listing README
    python3 integrations/docs/docs.py check   # exit 1 when the copy is out of date or a check fails

Standard library only, so both release scripts can import it.
"""

from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

DISCLOSURE_FILE = HERE / "disclosure.md"

#: What every listing's disclosure must say (case aside).
REQUIRED_PHRASES = ("other personal data", "OpenRouter", "TypeSafe", "beta")

#: The install guides, whose "What is sent" section must say the same.
GUIDES = ("integrations/hermes/README.md", "integrations/openclaw/README.md")

#: README copies of the paragraph -> that plugin's details. The Hermes catalog keeps its details in
#: catalog-entry.yaml (`disclosure_details`).
LISTING_DETAILS = {
    "integrations/openclaw/plugin/README.md": (
        "It mints a short-lived token from identity.firstdataunion.org with the scan credentials kept in "
        "OpenClaw's ~/.openclaw/.env (SENTROOK_SCAN_CLIENT_ID / SENTROOK_SCAN_CLIENT_SECRET). openclaw sentrook "
        "login, run by the user, signs in through identity.firstdataunion.org in a browser, writes those two lines "
        "there and keeps a random id for the machine in ~/.openclaw/sentrook/device-id. With skillReview: allow "
        "(default) the redacted conversation goes with OpenClaw's own background skill and memory saves and is kept "
        "redacted on disk for up to 7 days for that. Apart from those two lines, writes only its own folder "
        "(~/.openclaw/sentrook); runs no "
        "shell commands and starts no background processes; no telemetry beyond the scans."
    ),
}
START = "<!-- disclosure: start (copied from integrations/docs/disclosure.md by docs.py sync; edit it there) -->"
END = "<!-- disclosure: end -->"
BLOCK = re.compile(re.escape(START) + r"\n.*?\n" + re.escape(END), re.S)


def _source() -> str:
    text = DISCLOSURE_FILE.read_text()
    return " ".join(re.sub(r"<!--.*?-->", "", text, flags=re.S).split())


def plain(details: str) -> str:
    """The paragraph as one line of plain text with `details` in its place, for a catalog description."""
    text = _source().replace("{{details}}", " ".join(details.split()))
    return " ".join(text.split())


def markdown(details: str) -> str:
    """The paragraph for a README, wrapped at 120 columns, its first word in bold."""
    text = plain(details)
    if text.startswith("Disclosure:"):
        text = "**Disclosure:**" + text[len("Disclosure:") :]
    return textwrap.fill(text, 120, break_long_words=False, break_on_hyphens=False)


def missing_phrases(text: str) -> list[str]:
    flat = " ".join(text.split()).lower()
    return [p for p in REQUIRED_PHRASES if p.lower() not in flat]


def section(text: str, title: str) -> str:
    m = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", text, flags=re.M | re.S)
    return m[1] if m else ""


def synced(text: str, name: str, details: str) -> str:
    """`text` with the paragraph between the markers replaced by the current one."""
    if len(BLOCK.findall(text)) != 1:
        raise ValueError(f"{name}: needs exactly one disclosure block ({START} ... {END})")
    return BLOCK.sub(lambda _: f"{START}\n{markdown(details)}\n{END}", text)


def sync(check_only: bool = False) -> list[str]:
    """Write the paragraph into each listing README; with `check_only`, only report the ones that differ."""
    stale = []
    for rel, details in LISTING_DETAILS.items():
        path = REPO / rel
        text = path.read_text()
        new = synced(text, rel, details)
        if new != text:
            stale.append(rel)
            if not check_only:
                path.write_text(new)
    return stale


def guide_problems() -> list[str]:
    problems = []
    for rel in GUIDES:
        missing = missing_phrases(section((REPO / rel).read_text(), "What is sent"))
        if missing:
            problems.append(f'{rel}: "What is sent" must disclose {", ".join(missing)}')
    return problems


# --- wording -----------------------------------------------------------------------------------------------------

#: Text an owner or the agent reads about how Sentrook behaves.
WORDING_FILES = (
    "README.md",
    "integrations/hermes/README.md",
    "integrations/openclaw/README.md",
    "integrations/openclaw/plugin/README.md",
    "integrations/skills/*.md",
    "integrations/skills/agent-rules.txt",
    "integrations/*/plugin/skills/*/SKILL.md",
    "integrations/*/plugin/agent-rules.txt",
    "integrations/hermes/plugin/after-install.md",
    "integrations/hermes/plugin/plugin.yaml",
    "integrations/openclaw/plugin/package.json",
    "integrations/openclaw/plugin/openclaw.plugin.json",
    "integrations/hermes/release/catalog-entry.yaml",
    "integrations/hermes/release/catalog-pr-add.md",
    "integrations/docs/disclosure.md",
)

#: Words that describe Sentrook changing by itself (including the phrase the setup skill used to tell the agent),
#: and words that promise more than it does: redaction is best effort and leaves other personal data as it is.
FLAGGED = re.compile(
    r"learn\w*|improv\w*|smarter|on its own|once it knows"
    r"|scrubb\w*|anonymi[sz]\w*|meticulous\w*|fail[- ]closed",
    re.I,
)

#: Uses that are true: the hosts' own background saves and commands, and plain idioms. Matched case-insensitively
#: and blanked before the text is checked, so a flagged word elsewhere in the same sentence still fails.
ALLOWED = (
    "learn more",
    "/learn drafts",  # OpenClaw's own Skill Workshop command
    "hermes reviews what it learned",
    "self-improvement",  # Hermes's background review, by its own name
    "saves to the agent's skills and memory on its own",
    "saves skills and memory on its own",
    "the agent saves on its own",
    "openclaw makes on its own",
    "hermes may approve a prompt on its own",
    "does not count as new on its own",
)


def text_problems(text: str) -> list[tuple[int, str]]:
    """(line number, flagged words) for each claim in `text` that Sentrook changes by itself. Lines are joined
    first, so a phrase wrapped across two lines is still found."""
    starts, parts, pos = [], [], 0
    for line in text.splitlines():
        flat = " ".join(line.split()).lower()
        starts.append(pos)
        parts.append(flat)
        pos += len(flat) + 1
    flat = " ".join(parts)
    for phrase in ALLOWED:
        flat = flat.replace(phrase, " " * len(phrase))
    found = []
    for m in FLAGGED.finditer(flat):
        line = max(i for i, s in enumerate(starts) if s <= m.start())
        found.append((line + 1, m.group(0)))
    return found


def wording_problems() -> list[str]:
    problems = []
    seen: set[Path] = set()
    for pattern in WORDING_FILES:
        for path in sorted(REPO.glob(pattern)):
            if path in seen:
                continue
            seen.add(path)
            lines = path.read_text().splitlines()
            for n, word in text_problems(path.read_text()):
                problems.append(f"{path.relative_to(REPO)}:{n}: {word!r}: {lines[n - 1].strip()}")
    return problems


def main(argv: list[str]) -> int:
    if argv[1:] == ["sync"]:
        for rel in sync():
            print(f"wrote {rel}")
        return 0
    if argv[1:] == ["check"]:
        failed = False
        try:
            stale = sync(check_only=True)
        except ValueError as e:
            print(e)
            stale, failed = [], True
        for rel in stale:
            print(f"{rel}: disclosure out of date; run python3 integrations/docs/docs.py sync")
            failed = True
        missing = missing_phrases(_source())
        if missing:
            print(f"disclosure.md: missing {', '.join(missing)}")
            failed = True
        for problem in guide_problems():
            print(problem)
            failed = True
        for p in wording_problems():
            print(
                f"{p}\n  describes Sentrook changing by itself or promises more than it does: say what the owner sets, and with "
                "which command, or what is really done"
            )
            failed = True
        return 1 if failed else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
