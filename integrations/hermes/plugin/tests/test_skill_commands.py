"""The setup skill's fallback commands (for when the setup tools are missing) are ones the plugin accepts: each grant
parses with the grant command's own parser, each binding is set by the bind command, each trust reference parses."""

import re
from datetime import UTC, datetime
from pathlib import Path

from plugin import grants
from plugin.commands import CMD
from plugin.config import resolve_config
from plugin.trust import parse_ref

SKILL = (Path(__file__).resolve().parents[1] / "skills" / "sentrook-setup" / "SKILL.md").read_text()


def fallback_commands() -> list[str]:
    section = SKILL.split("### If the setup tools are missing")[1].split("###")[0]
    return re.findall(r"^\| [^|]+ \| `(/sentrook [^`]+)` \|$", section, re.M)


def test_the_fallback_table_names_the_commands_the_plugin_accepts(tmp_path):
    commands = fallback_commands()
    assert len(commands) == 8
    cfg = resolve_config({"state_dir": str(tmp_path)}, {"HOME": str(tmp_path)})
    for line in commands:
        _slash, verb, *words = line.split(" ")
        rest = " ".join(words)
        if verb == "grant":
            parsed = grants.parse_grant(rest, CMD)
            assert isinstance(parsed, dict), f"{line}: {parsed}"
        elif verb == "bind":
            reply, change = grants.bind(
                tmp_path, cfg, rest, {"basis": ["test"]}, datetime.now(UTC), CMD
            )
            assert change, f"{line}: {reply}"
        elif verb in ("trust-chat", "trust-user"):
            assert words[0] == "add" and parse_ref(words[1]) and words[2] == "--confirm", line
        else:
            raise AssertionError(f"unexpected command {line}")
