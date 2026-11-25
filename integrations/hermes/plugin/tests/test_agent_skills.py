"""The agent skills and agent rules both plugins ship: rendered from one template, naming only commands the host has,
and registered with Hermes at load.

The template and its renderer are in `integrations/skills/`; the rendered files are committed in each plugin's folder.
The OpenClaw plugin's tests check its own command names (`agentSkills.test.ts`).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

import plugin
from plugin import agent_skills, cli, commands

REPO = Path(__file__).resolve().parents[4]
SKILLS_DIR = REPO / "integrations" / "skills"


def _renderer():
    spec = importlib.util.spec_from_file_location("skills_render", SKILLS_DIR / "render.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


render = _renderer()


def rendered(host: str) -> dict[str, str]:
    """Template name -> the committed file rendered from it for `host`."""
    base = REPO / render.HOSTS[host]["dir"]
    return {t: (base / rel).read_text() for t, rel in render.TEMPLATES.items()}


# ---- drift and packaging -----------------------------------------------------------------------------------------


def test_the_committed_files_are_the_templates_rendered():
    stale = [
        str(path.relative_to(REPO))
        for path, text in render.outputs().items()
        if not path.exists() or path.read_text() != text
    ]
    assert stale == [], "run python3 integrations/skills/render.py"


@pytest.mark.parametrize("template", list(render.TEMPLATES))
def test_the_two_hosts_differ_only_in_the_substitutions(template):
    """Each rendered file is the template with every placeholder replaced and nothing else changed."""
    text = (SKILLS_DIR / template).read_text()
    pieces = render.PLACEHOLDER.split(text)
    # split keeps the three groups of each placeholder; the literal text is every fourth piece
    literal = pieces[::4]
    pattern = "(.*?)".join(re.escape(p) for p in literal)
    assert len(literal) > 1
    for host in render.HOSTS:
        assert re.fullmatch(pattern, rendered(host)[template], re.DOTALL), (host, template)
        assert "{{" not in rendered(host)[template]


def test_the_hosts_fill_the_same_placeholders():
    keys = {host: set(h["values"]) for host, h in render.HOSTS.items()}
    assert keys["hermes"] == keys["openclaw"]


#: A chat command on Hermes: `/sentrook <verb>`; never the dashed OpenClaw spelling.
HERMES_CHAT = re.compile(r"/sentrook(?:\s+([a-z]+)|-([a-z]+))")
HERMES_CLI = re.compile(r"hermes sentrook ([a-z]+)")


@pytest.mark.parametrize("template", list(render.TEMPLATES))
def test_every_command_the_hermes_text_names_exists_in_hermes(template):
    text = rendered("hermes")[template]
    for m in HERMES_CHAT.finditer(text):
        assert m[2] is None, f"OpenClaw spelling /sentrook-{m[2]} in the Hermes {template}"
        assert m[1] in commands.COMMANDS, f"/sentrook {m[1]} in the Hermes {template}"
    for m in HERMES_CLI.finditer(text):
        assert m[1] in (*cli.LOCAL_COMMANDS, *cli.CLI_COMMANDS), (
            f"hermes sentrook {m[1]} in the Hermes {template}"
        )
    assert "openclaw" not in text.lower()


def test_the_command_list_takes_the_arguments_each_hermes_command_takes():
    for verb in render.HOSTS["hermes"]["commands"]:
        assert render.summary_of("hermes", verb)[0] == commands.COMMANDS[verb].args, verb


def test_the_hermes_guide_lists_every_command():
    guide = rendered("hermes")["sentrook-guide.md"]
    for name in commands.COMMANDS:
        assert f"- `/sentrook {name}" in guide, name
    assert "`hermes sentrook verify`" in guide


@pytest.mark.parametrize("host", list(render.HOSTS))
def test_the_rules_name_every_command_that_changes_sentrook(host):
    """The always-loaded rules and both skills forbid every command that changes what Sentrook allows."""
    for template, text in rendered(host).items():
        for entry in render.HOSTS[host]["change"]:
            verb, _, sub = entry.partition(" ")
            assert f"`{render.chat(host, verb)}{' ' + sub if sub else ''}`" in text, (
                host,
                template,
                entry,
            )


def test_every_hermes_owner_command_that_answers_or_changes_is_in_the_never_run_list():
    """Every owner-only command except the ones that only show something is one the agent must never run."""
    shows = {"history", "why", "report", "grants", "passes"}
    change = {e.split(" ")[0] for e in render.HOSTS["hermes"]["change"]}
    owner = {name for name, c in commands.COMMANDS.items() if c.owner_only}
    assert owner - shows <= change and "passes revoke" in render.HOSTS["hermes"]["change"]


#: Host names in the text: only invented ones (example.com and its kind).
HOSTNAME = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|org|net|io|dev|ai|app|co|uk|example)\b"
)


@pytest.mark.parametrize("host", list(render.HOSTS))
def test_the_text_names_only_invented_hosts(host):
    for template, text in rendered(host).items():
        for m in HOSTNAME.finditer(text.lower()):
            assert m[0].endswith(("example.com", ".example")), (host, template, m[0])


# ---- working well with Sentrook ----------------------------------------------------------------------------------

WORKING_WELL = "## Working well with Sentrook"

#: Advice that would help a call past a review rather than make it clear: splitting, disguising, rewording, avoiding.
EVASION = re.compile(
    r"\b(?:split\w*|disguis\w*|obfuscat\w*|encod\w*|reword\w*|rephras\w*|bypass\w*|evad\w*|evasion|dodg\w*|"
    r"sneak\w*|slip\w*|hid(?:e|ing|den)|avoid\w*|circumvent\w*|get(?:ting)? (?:past|around)|"
    r"below the (?:review|threshold|line)|lower the (?:risk|score)|smaller (?:calls|pieces|steps))\b",
    re.IGNORECASE,
)
NEGATION = re.compile(r"\b(?:never|not|don't|do not|no)\b", re.IGNORECASE)


def working_well(text: str) -> str:
    """The guide's "Working well with Sentrook" section: from its heading to the next one."""
    start = text.index(WORKING_WELL)
    end = text.find("\n## ", start + len(WORKING_WELL))
    return text[start : end if end != -1 else len(text)]


def evasive_advice(section: str) -> list[str]:
    """Each sentence of `section` that names an evasive move without forbidding it."""
    body = " ".join(section.split("\n")[1:])
    sentences = re.split(r"(?<=[.:;])\s+|\s-\s+", body)
    return [s for s in sentences if EVASION.search(s) and not NEGATION.search(s)]


def test_the_evasion_check_catches_advice_to_get_past_a_review():
    bad = (
        f"{WORKING_WELL}\n\nSplit a large fetch into smaller calls so each one scores below the review line. "
        "Rename the tool and encode the host so the scan misses it. Avoid commands Sentrook asks about."
    )
    assert len(evasive_advice(bad)) == 3
    good = f"{WORKING_WELL}\n\nThis is never about getting past a check. Do not retry it reworded."
    assert evasive_advice(good) == []


@pytest.mark.parametrize("host", list(render.HOSTS))
def test_the_guide_says_how_to_shape_work_so_it_scans_clearly(host):
    """Fetch with the host's web tools, keep code local, set up in the owner's chat, one work directory, keys by name,
    and a held or blocked call goes to the owner, never back in a new shape."""
    section = working_well(rendered(host)["sentrook-guide.md"])
    host_name = render.HOSTS[host]["values"]["host"]
    for needed in (
        f"{host_name}'s own web or fetch tools",
        "reads local files",
        "reach the network",
        "in a chat with the owner",
        render.HOSTS[host]["values"]["unattended_runs"],
        "one work directory",
        "by its name",
        f"`{render.chat(host, 'why')}",
        "never about getting past a check",
    ):
        assert needed in " ".join(section.split()), (host, needed)


@pytest.mark.parametrize("host", list(render.HOSTS))
def test_the_working_well_section_never_advises_getting_past_a_review(host):
    """No sentence tells the agent to split, disguise, reword or avoid a call to get it past a review; such a word may
    appear only where the sentence forbids it."""
    assert evasive_advice(working_well(rendered(host)["sentrook-guide.md"])) == []


def test_the_rules_fit_a_hermes_prompt_section():
    text = agent_skills.rules()
    # Hermes's limits: at most 4000 characters, an id of lowercase letters, digits, `.`, `_` and `-`.
    assert 0 < len(text) <= 4000
    assert re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", agent_skills.RULES_SECTION)


@pytest.mark.parametrize("name", agent_skills.SKILLS)
def test_each_skill_file_is_shipped_with_its_name_and_a_description(name):
    path = agent_skills.skill_path(name)
    assert path.is_file() and not path.is_symlink()
    head = path.read_text().split("---")[1]
    assert f"\nname: {name}\n" in head
    assert "Sentrook" in agent_skills.description(path)


# ---- registered at load ------------------------------------------------------------------------------------------


class SkillCtx:
    """The two registrations Hermes 0.23 offers, recorded."""

    def __init__(self):
        self.skills = {}
        self.sections = {}

    def get_config(self, key, default=None):
        return default

    def register_hook(self, name, fn):
        pass

    def register_skill(self, name, path, description=""):
        assert ":" not in name
        assert Path(path).exists()
        self.skills[name] = {"path": Path(path), "description": description}

    def register_system_prompt_section(
        self, id, content, *, position="after_memory", max_chars=4000
    ):
        self.sections[id] = content


def test_hermes_registers_both_skills_and_the_rules_at_load(harness):
    ctx = SkillCtx()
    plugin.register(ctx)
    assert set(ctx.skills) == {"sentrook-guide", "sentrook-setup"}
    for name, entry in ctx.skills.items():
        assert entry["path"] == agent_skills.PLUGIN_DIR / "skills" / name / "SKILL.md"
        assert entry["description"] == agent_skills.description(entry["path"])
    assert ctx.sections == {"sentrook-agent-rules": agent_skills.rules()}
    assert "/sentrook grant" in ctx.sections["sentrook-agent-rules"]


def test_a_host_that_refuses_a_skill_still_gets_the_rules_and_the_hooks(harness, caplog):
    class Refusing(SkillCtx):
        def __init__(self):
            super().__init__()
            self.hooks = {}

        def register_hook(self, name, fn):
            self.hooks[name] = fn

        def register_skill(self, name, path, description=""):
            raise ValueError(f"Plugin skill 'sentrook:{name}' is already registered")

    ctx = Refusing()
    plugin.register(ctx)
    assert "pre_tool_call" in ctx.hooks
    assert "sentrook-agent-rules" in ctx.sections
    assert "sentrook skill sentrook-guide not registered" in caplog.text
