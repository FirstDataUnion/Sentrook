"""The agent skills and the always-loaded agent rules the plugin gives Hermes.

Two read-only skills, which Hermes lists as `sentrook:sentrook-guide` (how Sentrook works, for explaining it) and
`sentrook:sentrook-setup` (helping the owner set it up), and a short system prompt section with the rules the agent
must follow whether or not it opens a skill: never run the commands that change Sentrook, never edit its settings or
folder, never retry a blocked call reworded. All three are files in the plugin's folder, rendered for Hermes from the
shared templates in `integrations/skills/`.

Hermes 0.23 has both registrations (`ctx.register_skill`, `ctx.register_system_prompt_section`); a host without one
skips it, and a failure is logged, never raised: the scanning hooks matter more than the skills.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentrook")

PLUGIN_DIR = Path(__file__).resolve().parent
#: The skills, by name; Hermes adds the plugin's name in front (`sentrook:sentrook-setup`).
SKILLS = ("sentrook-guide", "sentrook-setup")
#: The rules section's id in Hermes's system prompt.
RULES_SECTION = "sentrook-agent-rules"
RULES_FILE = PLUGIN_DIR / "agent-rules.txt"


def skill_path(name: str) -> Path:
    return PLUGIN_DIR / "skills" / name / "SKILL.md"


def description(path: Path) -> str:
    """The `description:` line of a SKILL.md's front matter; empty when there is none."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, sep, value = line.partition(":")
        if sep and key.strip() == "description":
            return value.strip()
    return ""


def rules() -> str:
    return RULES_FILE.read_text(encoding="utf-8").strip()


def register(ctx: Any) -> None:
    """Registers both skills and the rules section with Hermes, where it can."""
    add_skill = getattr(ctx, "register_skill", None)
    if callable(add_skill):
        for name in SKILLS:
            try:
                path = skill_path(name)
                add_skill(name, path, description=description(path))
            except Exception as exc:  # noqa: BLE001 - a missing skill must not stop the scans
                logger.warning("sentrook skill %s not registered: %s", name, exc)
    else:
        logger.info("sentrook skills not registered: this Hermes has no plugin skills")
    add_section = getattr(ctx, "register_system_prompt_section", None)
    if callable(add_section):
        try:
            add_section(RULES_SECTION, rules())
        except Exception as exc:  # noqa: BLE001
            logger.warning("sentrook agent rules not registered: %s", exc)
    else:
        logger.info(
            "sentrook agent rules not registered: this Hermes has no plugin prompt sections"
        )
