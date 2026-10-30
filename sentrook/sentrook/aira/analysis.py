"""The shared per-call analysis every AIRA detector reads.

Computed once per call (pending or sibling): the exec shape, the normalised (deobfuscated) text,
the paths the call touches with their groups and entity IDs, the hosts, recipients, attachments and
packages with their entity IDs, and whether a secret placeholder is present. Detectors are then
small functions over this object; none of them re-parses the command or re-extracts entities.

Entity resolution goes through `prepared.entities` (kind + normalised value), so a contribution can
name the opaque entity ID the response will carry. A path or host that preparation did not extract
(a bare basename after `cd`, a host revealed only by decoding) has no entity and contributes
without a subject.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..planir.canonical import CanonicalCall
from ..planir.models import ToolKind
from ..prepare import Prepared
from ..prepare.entities import (
    Entity,
    EntityKind,
    Found,
    Role,
    display_path,
    extract_call,
    extract_exec,
    extract_mentions,
    normalise_path,
)
from .exec_shape import ExecShape, derive_exec_shape
from .lists import Lists
from .normalize import encodings_in, normalise_text
from .path_classes import classify_path_detail, derive_path_roles, derive_url_hosts


@dataclass
class PathRef:
    value: str  # normalised absolute path
    display: str
    roles: set[Role] = field(default_factory=set)
    groups: list[str] = field(default_factory=list)  # path groups matched, in list order
    locations: list[str] = field(default_factory=list)
    entity_id: str | None = None

    def in_group(self, *names: str) -> bool:
        return any(n in self.groups for n in names)

    @property
    def is_destination(self) -> bool:
        return Role.DATA_DESTINATION in self.roles

    @property
    def is_source(self) -> bool:
        return Role.DATA_SOURCE in self.roles or Role.EXECUTABLE in self.roles


@dataclass
class EntityRef:
    kind: EntityKind
    value: str
    roles: set[Role] = field(default_factory=set)
    entity_id: str | None = None


@dataclass
class CallAnalysis:
    call: CanonicalCall
    source: str  # pending | sibling
    kind: ToolKind
    tool: str
    command: str | None
    #: `analysis_text`: every string leaf, URL queries percent-decoded (canonicalisation).
    text: str
    #: `text` after `normalize`: base64/hex/quote-concat undone where recognisable.
    normalised: str
    #: Which encodings the normaliser undid (`base64`, `hex`, `quote_concat`); empty when none.
    encodings: set[str]
    #: Shape of the command as written, and of the decoded command when decoding changed it.
    shape: ExecShape | None
    decoded_shape: ExecShape | None
    #: True for Hermes `execute_code` and similar: `command` is interpreter source, not shell.
    inline_code: bool
    heads: set[str]
    paths: list[PathRef]
    #: Path groups referenced anywhere in the text (URLs removed), including bare basenames.
    text_groups: list[str]
    hosts: list[EntityRef]
    recipients: list[EntityRef]
    channels: list[EntityRef]
    packages: list[EntityRef]
    providers: list[EntityRef]
    attachments: list[PathRef]
    content: str
    edit_text: str
    placeholder: bool
    cwd: str | None

    # ----------------------------------------------------------------- helpers

    @property
    def scan_text(self) -> str:
        """The text detectors run regexes over: raw and normalised, deduplicated."""
        if self.normalised == self.text:
            return self.text
        return self.text + "\n" + self.normalised

    def path(self, value: str) -> PathRef | None:
        for p in self.paths:
            if p.value == value:
                return p
        return None

    def paths_in(self, *groups: str) -> list[PathRef]:
        return [p for p in self.paths if p.in_group(*groups)]

    def destination_hosts(self) -> list[EntityRef]:
        dest = [h for h in self.hosts if Role.DATA_DESTINATION in h.roles]
        return dest or list(self.hosts)

    def segment_texts(self) -> list[str]:
        """One line per parsed segment (`head arg …`), or the whole normalised command when the
        parse is not trusted. Regexes scoped to one simple command run over these."""
        if self.shape is not None and self.shape.parse_ok and self.shape.segments:
            return [" ".join([s.head, *s.argv]) for s in self.shape.segments]
        if self.command:
            return [self.normalised_command()]
        return [self.scan_text]

    def segment_tokens(self) -> list[list[str]]:
        """`segment_texts` as words. From the parse, a quoted argument stays one word."""
        if self.shape is not None and self.shape.parse_ok and self.shape.segments:
            return [[s.head, *s.argv] for s in self.shape.segments]
        return [line.split() for line in self.segment_texts()]

    def normalised_command(self) -> str:
        cmd = self.command or ""
        norm = normalise_text(cmd)
        return cmd if norm == cmd else cmd + "\n" + norm


# --------------------------------------------------------------------------- construction


def _entity_id(prepared: Prepared, kind: EntityKind, value: str) -> str | None:
    ent: Entity | None = prepared.entities.get(kind, value)
    return ent.id if ent is not None else None


def _placeholder_in(text: str, lists: Lists) -> bool:
    open_ = str(lists.get("egress", "placeholder", "open", default="⟦secret"))
    return open_ in text


def _resolve(path: str, prepared: Prepared, cwd: str | None) -> str:
    return normalise_path(path, home=prepared.home, workspace_root=prepared.workspace_root, cwd=cwd)


def analyse(call: CanonicalCall, prepared: Prepared, lists: Lists) -> CallAnalysis:
    """Build the shared analysis of one canonical call."""
    home, ws = prepared.home, prepared.workspace_root
    groups = lists.path_groups
    cwd_raw = call.get("cwd")
    cwd = _resolve(str(cwd_raw), prepared, None) if isinstance(cwd_raw, str) and cwd_raw else None

    text = call.analysis_text or ""
    normalised = normalise_text(text)
    encodings = encodings_in(text)
    inline_code = call.tool_kind is ToolKind.EXEC and bool(call.get("interpreter"))
    command = call.command if call.tool_kind is ToolKind.EXEC else None

    shape: ExecShape | None = None
    decoded_shape: ExecShape | None = None
    if command and not inline_code:
        shape = derive_exec_shape(command, groups, workspace_root=ws, home=home)
        decoded_cmd = normalise_text(command)
        if decoded_cmd != command:
            decoded_shape = derive_exec_shape(decoded_cmd, groups, workspace_root=ws, home=home)

    heads: set[str] = set()
    for s in (shape, decoded_shape):
        if s is not None:
            heads.update(s.heads)

    # Entities with roles, from the same extractor preparation used (so values match the table).
    found: list[Found] = list(extract_call(call, home=home, workspace_root=ws))
    if command and normalised != text:
        decoded_cmd = normalise_text(command)
        if decoded_cmd != command:
            found.extend(extract_exec(decoded_cmd, home=home, workspace_root=ws, cwd=cwd_raw))
    if inline_code and command:
        found.extend(
            extract_mentions(command, home=home, workspace_root=ws, role=None, inline_program=True)
        )

    paths: dict[str, PathRef] = {}
    hosts: dict[str, EntityRef] = {}
    recipients: dict[str, EntityRef] = {}
    channels: dict[str, EntityRef] = {}
    packages: dict[str, EntityRef] = {}
    providers: dict[str, EntityRef] = {}
    for f in found:
        if f.kind is EntityKind.PATH:
            ref = paths.get(f.value)
            if ref is None:
                _locations, roles = classify_path_detail(
                    f.value, groups, workspace_root=ws, home=home
                )
                ref = PathRef(
                    value=f.value,
                    display=f.display,
                    groups=roles,
                    locations=_locations,
                    entity_id=_entity_id(prepared, EntityKind.PATH, f.value),
                )
                paths[f.value] = ref
            if f.role is not None:
                ref.roles.add(f.role)
            continue
        bucket = {
            EntityKind.HOST: hosts,
            EntityKind.RECIPIENT: recipients,
            EntityKind.CHANNEL: channels,
            EntityKind.PACKAGE: packages,
            EntityKind.PLUGIN: packages,
            EntityKind.MCP_SERVER: providers,
        }.get(f.kind)
        if bucket is None:
            continue
        ref = bucket.get(f.value)
        if ref is None:
            ref = EntityRef(
                kind=f.kind, value=f.value, entity_id=_entity_id(prepared, f.kind, f.value)
            )
            bucket[f.value] = ref
        if f.role is not None:
            ref.roles.add(f.role)

    # Hosts the shape saw that the extractor did not (e.g. a bare label).
    for h in derive_url_hosts(normalised):
        hosts.setdefault(
            h,
            EntityRef(
                kind=EntityKind.HOST, value=h, entity_id=_entity_id(prepared, EntityKind.HOST, h)
            ),
        )

    attachments: list[PathRef] = []
    for a in call.get("attachments") or []:
        value = _resolve(str(a), prepared, cwd)
        ref = paths.get(value)
        if ref is None:
            locations, roles = classify_path_detail(value, groups, workspace_root=ws, home=home)
            ref = PathRef(
                value=value,
                display=display_path(value, home),
                roles={Role.DATA_SOURCE},
                groups=roles,
                locations=locations,
                entity_id=_entity_id(prepared, EntityKind.PATH, value),
            )
            paths[value] = ref
        attachments.append(ref)

    content_parts: list[Any] = [call.get("content"), call.get("body"), call.get("task")]
    content = "\n".join(str(c) for c in content_parts if isinstance(c, str) and c)
    edit_parts: list[str] = []
    for e in call.get("edits") or []:
        if isinstance(e, dict):
            edit_parts.extend(str(e.get(k) or "") for k in ("old", "new"))
    edit_text = "\n".join(p for p in edit_parts if p) or content

    role_text = text if normalised == text else text + "\n" + normalised
    text_groups = derive_path_roles(role_text, groups)

    return CallAnalysis(
        call=call,
        source=call.source,
        kind=call.tool_kind,
        tool=call.tool,
        command=command,
        text=text,
        normalised=normalised,
        encodings=encodings,
        shape=shape,
        decoded_shape=decoded_shape,
        inline_code=inline_code,
        heads=heads,
        paths=list(paths.values()),
        text_groups=text_groups,
        hosts=list(hosts.values()),
        recipients=list(recipients.values()),
        channels=list(channels.values()),
        packages=list(packages.values()),
        providers=list(providers.values()),
        attachments=attachments,
        content=content,
        edit_text=edit_text,
        placeholder=_placeholder_in(text, lists),
        cwd=cwd,
    )
