"""Action fingerprint `afp1` (skeleton 1.2, preparation step 7).

Captures what a call does, not how it is written: the tool kind plus one session-salted hash per
role-tagged key entity. Components are hashed separately so retry detection can match partially (same
source, new destination). The plugin echoes the fingerprint back in `history` without parsing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..planir.models import ToolKind
from ..state.token import entity_hash
from .entities import Entity, EntityKind, Role

PREFIX = "afp1"

ROLE_TAGS: dict[Role, str] = {
    Role.DATA_SOURCE: "src",
    Role.DATA_DESTINATION: "dst",
    Role.CODE_SOURCE: "code",
    Role.EXECUTABLE: "exe",
    Role.RECIPIENT: "rcpt",
    Role.TOOL_PROVIDER: "prov",
}
_TAG_ROLES = {v: k for k, v in ROLE_TAGS.items()}


@dataclass(frozen=True)
class Fingerprint:
    tool_kind: str
    components: dict[str, frozenset[str]] = field(default_factory=dict)  # tag → hashes

    def render(self) -> str:
        parts = [f"{PREFIX}:{self.tool_kind}"]
        for tag in ROLE_TAGS.values():
            for h in sorted(self.components.get(tag, ())):
                parts.append(f"{tag}:{h}")
        return "|".join(parts)

    def hashes(self, role: Role) -> frozenset[str]:
        return self.components.get(ROLE_TAGS[role], frozenset())

    @classmethod
    def parse(cls, text: str | None) -> Fingerprint | None:
        if not text or not text.startswith(PREFIX + ":"):
            return None
        head, *rest = text.split("|")
        kind = head.split(":", 1)[1]
        comps: dict[str, set[str]] = {}
        for part in rest:
            tag, _, h = part.partition(":")
            if tag in _TAG_ROLES and h:
                comps.setdefault(tag, set()).add(h)
        return cls(tool_kind=kind, components={k: frozenset(v) for k, v in comps.items()})


def fingerprint(tool_kind: ToolKind, entities: list[Entity], salt: str) -> Fingerprint:
    comps: dict[str, set[str]] = {}
    for ent in entities:
        if ent.kind is EntityKind.CHANNEL:
            tag_roles = [Role.RECIPIENT]
        else:
            tag_roles = [r for r in ent.roles if r in ROLE_TAGS]
        for role in tag_roles:
            comps.setdefault(ROLE_TAGS[role], set()).add(
                entity_hash(salt, ent.kind.value, ent.value)
            )
    return Fingerprint(
        tool_kind=tool_kind.value, components={k: frozenset(v) for k, v in comps.items()}
    )
