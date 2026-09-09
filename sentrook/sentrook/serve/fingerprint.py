"""Command fingerprints for community corpus near-dup / session caps.

Fingerprint shape::

    {rule_id}:{label}:{argv_prefix}:{path_class}

``argv_prefix`` is up to three non-flag argv tokens (binary + subcommand),
with URLs/paths/ints skeletonized so ``openclaw config get`` does not
collapse into ``openclaw plugins update``. ``path_class`` still buckets
routine ``ls`` of workspace away from ``ls`` of auth-profiles / ``.ssh``.
Sensitive classes never auto-dedup.
"""

from __future__ import annotations

import re
from typing import Any

from sentrook.corpus.models import CorpusExample, CorpusStep

SENSITIVE_PATH_RE = re.compile(
    r"(?i)("
    r"auth-profiles\.json|"
    r"openclaw-agent\.sqlite|"
    r"openclaw\.json|"
    r"exec-approvals\.json|"
    r"sentrook-allowlist\.json|"
    r"(?:^|[\s\"'`=])/?(?:home/[^/\s]+/)?\.ssh/|"
    r"\bid_ed25519\b|\bid_rsa\b|"
    r"(?:^|[\s\"'`=])\.env(?:\b|/)|"
    r"credentials\.json|"
    r"openclaw-auth-intake"
    r")"
)
PIPE_SINK_RE = re.compile(r"(?i)\|\s*(?:curl|wget|nc|ncat|bash|sh|zsh|python3?|node)\b")
ENV_PROBE_RE = re.compile(r"(?i)\benv\s*\|\s*grep\b|\bprintenv\b")
INGEST_TOOLS = frozenset({"web_fetch", "web_search", "read"})

# Soft session cap: non-sensitive allow-once mints per (session, rule).
DEFAULT_MAX_COMMUNITY_PER_SESSION_RULE = 2
# Binary + two subcommand slots. Package names / config keys sit after this.
ARGV_PREFIX_LIMIT = 3

_FLAG_RE = re.compile(r"^-")
_REDIRECT_RE = re.compile(r"^(?:\d*)(?:>>|&>|&<|<&|>&|>|<)\S*$")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_STOP = frozenset({"|", "||", "&&", ";", "&"})
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INT_RE = re.compile(r"^-?\d+$")
# npm/OpenClaw scoped packages — not filesystem paths.
_SCOPED_PKG_RE = re.compile(r"^@[^/]+/[^/]+$")


def pending_step(
    steps: list[CorpusStep] | list[dict[str, Any]],
) -> CorpusStep | dict[str, Any] | None:
    for step in reversed(steps):
        status = step.status if isinstance(step, CorpusStep) else step.get("status")
        if status == "pending":
            return step
    return steps[-1] if steps else None


def _step_tool(step: CorpusStep | dict[str, Any]) -> str:
    if isinstance(step, CorpusStep):
        return step.tool
    return str(step.get("tool") or "unknown")


def _step_args(step: CorpusStep | dict[str, Any]) -> dict[str, Any]:
    if isinstance(step, CorpusStep):
        return dict(step.args or {})
    args = step.get("args") or {}
    return dict(args) if isinstance(args, dict) else {}


def pending_brief(steps: list[CorpusStep] | list[dict[str, Any]], *, max_len: int = 80) -> str:
    pending = pending_step(steps)
    if pending is None:
        return ""
    args = _step_args(pending)
    brief = ""
    for key in ("command", "url", "path", "file_path", "query"):
        if key in args and args[key] is not None:
            brief = str(args[key]).replace("\n", " ").strip()
            break
    if not brief:
        brief = _step_tool(pending)
    if len(brief) > max_len:
        brief = brief[: max_len - 3] + "..."
    return brief


def derive_community_intent(
    *,
    intent_kind: str | None,
    steps: list[CorpusStep] | list[dict[str, Any]],
    include_one_prior_tool: bool = False,
) -> str:
    """Build a short privacy-safe intent from the pending tool (not session chat).

    Default is pending-only so same-session allow-onces do not share a growing
    ``read→exec→exec→…`` prefix. Optional one prior tool for chain-shaped rows.
    """
    kind = intent_kind or "user"
    pending = pending_step(steps)
    if pending is None:
        return f"{kind}: unknown"[:200]
    pending_tool = _step_tool(pending)
    traj = pending_tool
    if include_one_prior_tool:
        prior_tool = None
        for step in steps:
            if step is pending:
                break
            prior_tool = _step_tool(step)
        if prior_tool and prior_tool != pending_tool:
            traj = f"{prior_tool}→{pending_tool}"
    brief = pending_brief(steps)
    text = f"{kind}: {traj} — {brief}".strip(" —")
    return text[:200]


def base_token(command: str | None) -> str:
    if not command or not str(command).strip():
        return "unknown"
    first = str(command).strip().split()[0]
    return _bin_name(first)


def _bin_name(token: str) -> str:
    return token.split("/")[-1].lower() or "unknown"


def _is_path_like(token: str) -> bool:
    if _SCOPED_PKG_RE.match(token):
        return False
    if token.startswith(("/", "./", "../", "~")):
        return True
    if token.startswith("\\\\") or (len(token) >= 3 and token[1] == ":" and "\\" in token):
        return True
    if "/" in token and not token.startswith("@"):
        return True
    return False


def _skeletonize_prefix_token(token: str, *, index: int) -> str:
    if _URL_RE.match(token):
        return "<url>"
    if _UUID_RE.match(token):
        return "<uuid>"
    if _INT_RE.match(token):
        return "<int>"
    if _is_path_like(token):
        return "<path>"
    if index == 0:
        return _bin_name(token)
    return token.lower()


def _keep_prefix_token(token: str) -> bool:
    if token in _SHELL_STOP:
        return False
    if _FLAG_RE.match(token):
        return False
    if _REDIRECT_RE.match(token):
        return False
    if _ENV_ASSIGN_RE.match(token):
        return False
    return True


def argv_prefix(command: str | None, *, limit: int = ARGV_PREFIX_LIMIT) -> str:
    """Stable CLI-family identity: binary + subcommand slots, volatiles stripped."""
    if not command or not str(command).strip():
        return "unknown"
    kept: list[str] = []
    for raw in str(command).strip().split():
        if raw in _SHELL_STOP:
            break
        if not _keep_prefix_token(raw):
            continue
        kept.append(_skeletonize_prefix_token(raw, index=len(kept)))
        if len(kept) >= limit:
            break
    return "+".join(kept) if kept else "unknown"


def path_class(command: str | None) -> str:
    """Bucket path risk so routine ls does not collapse into credential ls."""
    text = command or ""
    if SENSITIVE_PATH_RE.search(text) or PIPE_SINK_RE.search(text) or ENV_PROBE_RE.search(text):
        return "sensitive"
    lower = text.lower()
    if ".openclaw" in lower or "/home/node/.openclaw" in lower:
        return "openclaw"
    if "/tmp/" in lower or " /tmp" in lower:
        return "tmp"
    if "workspace" in lower:
        return "workspace"
    return "other"


def is_sensitive_path_class(path_cls: str) -> bool:
    return path_cls == "sensitive"


def is_sensitive_fingerprint(fingerprint: str) -> bool:
    return fingerprint.endswith(":sensitive") or ":sensitive:" in fingerprint


def command_fingerprint(
    *,
    rule_id: str,
    label: str,
    steps: list[CorpusStep] | list[dict[str, Any]] | None = None,
    example: CorpusExample | None = None,
) -> str:
    if example is not None:
        rule_id = rule_id or ""
        label = example.label
        steps = list(example.steps)
    steps = steps or []
    pending = pending_step(steps)
    args = _step_args(pending) if pending is not None else {}
    command = None
    for key in ("command", "path", "file_path", "url", "query"):
        if key in args and args[key] is not None:
            command = str(args[key])
            break
    tool = _step_tool(pending) if pending is not None else "unknown"
    token = argv_prefix(command) if command else tool
    pclass = path_class(command) if command else path_class(None)
    return f"{rule_id}:{label}:{token}:{pclass}"


def matched_steps_include_ingest(
    plan_steps: list[Any],
    matched_step_ids: list[str],
) -> bool:
    """True when L2 matched step ids include an ingest tool (fetch/search/read)."""
    wanted = {sid for sid in matched_step_ids if sid}
    if not wanted:
        return False
    for step in plan_steps:
        sid = getattr(step, "id", None) or (step.get("id") if isinstance(step, dict) else None)
        tool = getattr(step, "tool", None) or (step.get("tool") if isinstance(step, dict) else None)
        if sid in wanted and tool in INGEST_TOOLS:
            return True
    return False
