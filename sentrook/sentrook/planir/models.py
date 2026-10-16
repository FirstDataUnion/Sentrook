"""PlanIR 2.0 models, transcribed from the "Data structure skeleton" page, section 1.1.

Tolerance rules (skeleton, Conventions and 1.2):
- Unknown enum values resolve to each enum's fallback (`TolerantStrEnum`), never fail validation.
- Unknown fields are kept (`extra="allow"`), so an additive plugin change needs no scanner release.
- The plugin reports facts and Sentrook classifies trust: no field here says whether anything is
  trusted. Fields the plugin asserts (sender relation, grants, decisions, origin) are trusted as facts.
- `history` carries arguments, not content; `new_inputs` carries each piece of content exactly once.

Structural invariants that span fields (unique and increasing steps, `call_id` cross-references,
`session.step == max(history.step) + 1`) are checked by `planir.validate`, not here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..enums import TolerantStrEnum

# --------------------------------------------------------------------------- enums


class ScanKind(TolerantStrEnum):
    """`pending_call` now; `inputs` and `agent_input` are post-v1 scan kinds (skeleton section 8).
    An unrecognised kind is treated as `pending_call` because that is the only kind the pipeline
    runs; `planir.validate` reports it."""

    __fallback__ = "pending_call"
    PENDING_CALL = "pending_call"
    INPUTS = "inputs"
    AGENT_INPUT = "agent_input"


class OS(TolerantStrEnum):
    __fallback__ = "unknown"
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ExecMode(TolerantStrEnum):
    __fallback__ = "unknown"
    ALLOWLIST = "allowlist"
    FULL = "full"
    UNKNOWN = "unknown"


class AgentRole(TolerantStrEnum):
    __fallback__ = "unknown"
    MAIN = "main"
    SUBAGENT = "subagent"
    UNKNOWN = "unknown"


class TriggerKind(TolerantStrEnum):
    __fallback__ = "unknown"
    MESSAGE = "message"
    SCHEDULED = "scheduled"
    HEARTBEAT = "heartbeat"
    HOOK = "hook"
    SUBAGENT = "subagent"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class Channel(TolerantStrEnum):
    __fallback__ = "other"
    CHAT = "chat"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"
    OTHER = "other"


class SenderRelation(TolerantStrEnum):
    __fallback__ = "unknown"
    OWNER = "owner"
    TRUSTED = "trusted"
    OTHER = "other"
    UNKNOWN = "unknown"


class SenderBasis(TolerantStrEnum):
    """How the plugin derived `relation` (skeleton 1.3 for OpenClaw, 1.3b for Hermes). A basis the
    scanner does not recognise is no evidence, so it resolves to `unknown`."""

    __fallback__ = "unknown"
    HOST_OWNER_FLAG = "host_owner_flag"
    PLUGIN_ALLOWLIST_SENDER = "plugin_allowlist:sender"
    PLUGIN_ALLOWLIST_ROLE = "plugin_allowlist:role"
    HOST_ALLOWLIST_DM = "host_allowlist_dm"
    GROUP_CHAT = "group_chat"
    HOST_OPEN_ACCESS = "host_open_access"
    NONE = "none"
    UNKNOWN = "unknown"


class InputKind(TolerantStrEnum):
    """An input kind the scanner does not know is content of unknown provenance, so it falls back to
    `other`, which preparation classifies as untrusted."""

    __fallback__ = "other"
    TOOL_RESULT = "tool_result"
    MESSAGE = "message"
    SUBAGENT_REPLY = "subagent_reply"
    OTHER = "other"


class ToolKind(TolerantStrEnum):
    __fallback__ = "other"
    EXEC = "exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_EDIT = "file_edit"
    WEB_FETCH = "web_fetch"
    BROWSER = "browser"
    MESSAGE_SEND = "message_send"
    MEMORY_WRITE = "memory_write"
    MCP = "mcp"
    SUBAGENT_SPAWN = "subagent_spawn"
    OTHER = "other"


class ProviderKind(TolerantStrEnum):
    __fallback__ = "unknown"
    HOST = "host"
    MCP = "mcp"
    PLUGIN = "plugin"
    UNKNOWN = "unknown"


class Transport(TolerantStrEnum):
    __fallback__ = "other"
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    OTHER = "other"


class ResultStatus(TolerantStrEnum):
    __fallback__ = "error"
    OK = "ok"
    ERROR = "error"


class ContentType(TolerantStrEnum):
    __fallback__ = "other"
    TEXT = "text"
    JSON = "json"
    IMAGE = "image"
    BINARY = "binary"
    OTHER = "other"


class HostApproval(TolerantStrEnum):
    __fallback__ = "unknown"
    REQUIRED = "required"
    GRANTED = "granted"
    NONE = "none"
    UNKNOWN = "unknown"


class Decision(TolerantStrEnum):
    """What happened to an earlier step. `review_timed_out`, `denied_by_user` and `blocked` feed
    `retry_after_denial`; the `*_on_error` values mark steps with no usable scan."""

    __fallback__ = "unknown"
    ALLOWED = "allowed"
    APPROVED_BY_USER = "approved_by_user"
    DENIED_BY_USER = "denied_by_user"
    BLOCKED = "blocked"
    ALLOWED_ON_ERROR = "allowed_on_error"
    BLOCKED_ON_ERROR = "blocked_on_error"
    REVIEW_TIMED_OUT = "review_timed_out"
    UNKNOWN = "unknown"


class GrantScope(TolerantStrEnum):
    """An unknown scope is read as the weaker one (`session`), so relief is never widened by a value
    the scanner does not understand."""

    __fallback__ = "session"
    SESSION = "session"
    PERSISTENT = "persistent"


class Redaction(TolerantStrEnum):
    __fallback__ = "standard"
    OFF = "off"
    STANDARD = "standard"
    STRICT = "strict"


# --------------------------------------------------------------------------- models


class _Model(BaseModel):
    """Base for every PlanIR node: unknown fields are kept, enum values are compared by value."""

    model_config = ConfigDict(extra="allow", use_enum_values=False, populate_by_name=True)


class HostPolicy(_Model):
    """The host's own protection model, platform-neutral."""

    exec_mode: ExecMode = ExecMode.UNKNOWN
    approval_gating: bool = False
    result_masking: bool = False


class Host(_Model):
    platform: str = Field(description="openclaw | hermes | …; open string")
    platform_version: str | None = None
    plugin_version: str | None = None
    workspace_root: str = Field(description="Needed to classify reach: scratch → workspace → host")
    home: str
    os: OS = OS.UNKNOWN
    policy: HostPolicy = Field(default_factory=HostPolicy)


class Session(_Model):
    session_ref: str = Field(description="Episode; owns the state token")
    routing_key: str | None = Field(
        default=None, description="Hashed durable key linking runs of one automation"
    )
    agent_ref: str | None = None
    agent_role: AgentRole = AgentRole.MAIN
    parent_session_ref: str | None = Field(
        default=None, description="Reserved for C13 cross-session joins"
    )
    turn: int = Field(ge=0)
    step: int = Field(ge=1, description="Episode-wide tool-call counter; never resets per turn")
    state: str | None = Field(
        default=None, description="Signed token from the last response; null on the first step"
    )


class Sender(_Model):
    relation: SenderRelation = SenderRelation.UNKNOWN
    basis: list[SenderBasis] = Field(default_factory=list)


class Trigger(_Model):
    """Per turn, best effort; different hosts expose different facts (skeleton 1.3, 1.3b)."""

    kind: TriggerKind = TriggerKind.UNKNOWN
    channel: Channel | None = None
    sender: Sender = Field(default_factory=Sender)


class Request(_Model):
    text: str = Field(
        description="The current turn's request, or the scheduled task's prompt; redacted"
    )
    carried_from_turn: int | None = Field(
        default=None,
        description="Set only when the request text is from an earlier turn (heartbeat, system continuation)",
    )


class Provider(_Model):
    """Alias versus identity: `name` is the alias configured in this deployment, `identity` is stable
    across deployments and is what reputation keys on. Built-in host tools are `kind: host` with both
    null and create no entity."""

    kind: ProviderKind = ProviderKind.UNKNOWN
    name: str | None = None
    identity: str | None = None
    transport: Transport | None = None


class NewInput(_Model):
    """Content received since the last successful scan. One model covers the three variants
    discriminated on `kind`: `tool_result` (call_id, tool, provider, status), `message` (channel,
    sender) and `subagent_reply` (subagent_session_ref). Fields of the other variants are null."""

    input_seq: int = Field(ge=0, description="Monotonic per episode; stable across resends")
    kind: InputKind = InputKind.OTHER
    call_id: str | None = None
    tool: str | None = None
    tool_kind: ToolKind | None = None
    provider: Provider | None = None
    status: ResultStatus = ResultStatus.OK
    content_type: ContentType = ContentType.TEXT
    content: str | None = Field(
        default=None, description="Redacted and capped; null when the host dropped it"
    )
    size_bytes: int | None = Field(default=None, ge=0, description="Original size")
    truncated: bool = False
    channel: Channel | None = None
    sender: Sender | None = None
    subagent_session_ref: str | None = None


class ResultSummary(_Model):
    status: ResultStatus = ResultStatus.OK
    size_bytes: int | None = Field(default=None, ge=0)


class Tiers(_Model):
    """The plugin's echo of an earlier response's tier scores; coarse values only are relied on."""

    suspicion: float | None = Field(default=None, ge=0, le=1)
    consequence: float | None = Field(default=None, ge=0, le=1)
    confidence: float | None = Field(default=None, ge=0, le=1)


class HistoryStep(_Model):
    """One earlier step: arguments, not content. `risk`, `tiers` and `action_fingerprint` are null for
    steps with no usable scan."""

    step: int = Field(ge=1)
    turn: int = Field(ge=0)
    call_id: str
    tool: str
    tool_kind: ToolKind = ToolKind.OTHER
    provider: Provider = Field(default_factory=Provider)
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: ResultSummary | None = None
    action_fingerprint: str | None = None
    risk: float | None = Field(default=None, ge=0, le=100)
    tiers: Tiers | None = None
    request_id: str | None = None
    decision: Decision = Decision.UNKNOWN


class Sibling(_Model):
    """A call issued together with the pending one; each sibling is its own step and its own scan."""

    call_id: str
    tool: str
    tool_kind: ToolKind = ToolKind.OTHER
    provider: Provider = Field(default_factory=Provider)
    arguments: dict[str, Any] = Field(default_factory=dict)


class Batch(_Model):
    batch_ref: str | None = None
    siblings: list[Sibling] = Field(default_factory=list)


class PendingCall(_Model):
    call_id: str = Field(description="Unique within the episode (plugin-guaranteed)")
    host_call_id: str | None = Field(
        default=None, description="The host's original ID, for debugging"
    )
    tool: str
    tool_kind: ToolKind = ToolKind.OTHER
    provider: Provider = Field(default_factory=Provider)
    host_approval: HostApproval = HostApproval.UNKNOWN
    agent_narration: str | None = Field(
        default=None, description="Assistant text accompanying the call; untrusted but informative"
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Raw host arguments; canonicalised server-side"
    )
    batch: Batch | None = None


class Grant(_Model):
    """Something the owner explicitly allowed. `kind` and `allows` are open enums; `pattern` is a glob.
    Sentrook refuses over-broad patterns rather than relieve on them."""

    grant_ref: str
    kind: str = Field(description="destination | file | provider | automation | tool | … (open)")
    pattern: str
    allows: list[str] = Field(
        default_factory=list, description="read | write | edit | delete | exec, where relevant"
    )
    granted_at: datetime | None = None
    scope: GrantScope = GrantScope.SESSION


class Options(_Model):
    packs: list[str] = Field(default_factory=lambda: ["tier1"])
    redaction: Redaction = Redaction.STANDARD


class PlanIR(_Model):
    """The scan request. Auth lives in request headers, never in the body."""

    planir_version: Literal["2.0"]
    request_id: str = Field(
        min_length=1, description="Globally unique (UUID); the only globally unique ID"
    )
    run_ref: str = Field(min_length=1, description="The agent run this scan belongs to")
    sent_at: datetime
    scan_kind: ScanKind = ScanKind.PENDING_CALL
    origin: str = Field(
        default="live", description="live | fixture | replay; metrics only, never affects scoring"
    )
    host: Host
    session: Session
    trigger: Trigger = Field(default_factory=Trigger)
    request: Request
    new_inputs: list[NewInput] = Field(default_factory=list)
    history: list[HistoryStep] = Field(default_factory=list)
    pending_call: PendingCall
    grants: list[Grant] = Field(default_factory=list)
    options: Options = Field(default_factory=Options)
