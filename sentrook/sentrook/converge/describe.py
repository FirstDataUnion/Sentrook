"""Tool description templates: built from Jev's action category and the pending
call's entities, never from model text. `{E1}`-style placeholders are resolved by the plugin."""

from __future__ import annotations

from ..prepare import Prepared
from ..prepare.entities import EntityKind, Origin, Role
from ..response.models import ToolDescription

_TEMPLATES: dict[str, str] = {
    "reads_local_data": "Reads {src}",
    "fetches_remote_content": "Fetches content from {dst_or_src}",
    "writes_local_files": "Writes {dst}",
    "deletes_data": "Deletes {dst_or_src}",
    "runs_code_or_installer": "Runs code from {code}",
    "sends_data_off_host": "Sends {src} to {dst}",
    "sends_message_to_person": "Sends a message to {rcpt}",
    "modifies_agent_or_host_config": "Changes the agent's or host's configuration ({dst})",
    "spawns_subagent": "Starts a sub-agent",
    "other": "Runs {tool}",
}


def _first(
    prepared: Prepared, roles: set[Role], kinds: set[EntityKind] | None = None
) -> str | None:
    for ent in prepared.entities.pending():
        if ent.roles & roles and (kinds is None or ent.kind in kinds):
            return "{" + ent.id + "}"
    return None


def describe(prepared: Prepared, category: str | None) -> ToolDescription:
    cat = category if category in _TEMPLATES else ("other" if category else None)
    if cat is None:
        return ToolDescription(category=None, template=None)
    src = _first(prepared, {Role.DATA_SOURCE}) or "data"
    dst = (
        _first(
            prepared,
            {Role.DATA_DESTINATION},
            {EntityKind.HOST, EntityKind.CHANNEL, EntityKind.RECIPIENT},
        )
        or _first(prepared, {Role.DATA_DESTINATION})
        or "a destination"
    )
    rcpt = _first(prepared, {Role.RECIPIENT}) or dst
    code = _first(prepared, {Role.CODE_SOURCE, Role.EXECUTABLE}) or "an unnamed source"
    dst_or_src = _first(prepared, {Role.DATA_DESTINATION, Role.DATA_SOURCE}) or "a resource"
    template = _TEMPLATES[cat].format(
        src=src, dst=dst, rcpt=rcpt, code=code, dst_or_src=dst_or_src, tool=prepared.pending.tool
    )
    return ToolDescription(category=cat, template=template)


def entity_table(prepared: Prepared) -> dict:
    """Display table for the response: the pending call's entities plus anything a reason names."""
    from ..response.models import EntityDisplay

    out = {}
    for ent in prepared.entities:
        if ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
            out[ent.id] = EntityDisplay(kind=ent.kind.value, display=ent.display)
    return out
