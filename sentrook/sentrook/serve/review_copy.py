"""Human-readable copy for enforce-mode review and block prompts.

OpenClaw's ``plugin.approval.request`` hard-caps ``description`` at 256 chars and
fail-closes (blocks the call) when exceeded. The approval UI maps ``title`` to
the Command field (80) and ``description`` to Shell Preview (256).

Operator cards are built from pending argv with a structural ladder (destination,
sensitive path, packed excerpt) — never rule ids. Long quoted JSON/message
payloads are collapsed so destinations stay visible. Generic "run a shell
command" intent is omitted; an honest miss is used when neither argv nor
structured args (for example ``process action=log``) are available.

Head-truncating long commands hid exfil URLs and sqlite paths in live red-team
runs (A3); this module middle-elides and prefers those spans instead.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from sentrook.planir.args import canonicalize_tool_args, stringify_arg_value
from sentrook.result import MatchedRule, ScanResult
from sentrook.sanitize.core import apply_secret_patterns
from sentrook.sanitize.rules import load_rules
from sentrook.sanitize.signal_excerpt import pack_signal_excerpt
from sentrook.serve.log import ScanLogRecord

# OpenClaw plugin.approval.request limits (verified on 2026.6.x): description
# must be <= 256 chars, title <= 80. Keep a small safety margin below 256.
DESCRIPTION_MAX = 256
TITLE_MAX = 80
_MIN_COMMAND_CHARS = 16
_MIN_EXCERPT_CHARS = 24
_PAYLOAD_COLLAPSE_MIN = 48
_PAYLOAD_PREVIEW = 40
_EXEC_COMMAND_KEYS = ("command", "cmd", "shell", "script", "line", "data", "code", "source")
_PATH_KEYS = ("path", "file", "file_path", "target", "destination")
_SESSION_KEYS = ("sessionId", "session_id", "session")
_STRUCTURED_LEAD_KEYS = (
    "action",
    "sessionId",
    "session_id",
    "session",
    "limit",
    "timeout",
    "offset",
)
_SECRET_ARG_KEY = re.compile(
    r"(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)",
    re.IGNORECASE,
)
_PROCESS_LIFECYCLE_INTENTS = {
    "log": "read output from a background session",
    "poll": "poll a background session",
    "wait": "wait on a background session",
    "list": "list background sessions",
    "kill": "stop a background session",
    "close": "close a background session",
    "clear": "clear a background session",
}
_BODY_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "-F",
        "--form",
        "-m",
        "--message",
        "--content",
        "--body",
        "--json",
        "--payload",
    }
)
_GENERIC_INTENTS = frozenset(
    {
        "run a shell command",
        "use the exec tool",
        "use the tool tool",
    }
)

# Prefer specific credential/exfil rules over broad fetch→exec / bare exec when
# choosing operator-facing copy (scan decision merge is unchanged).
_RULE_SPECIFICITY: dict[str, int] = {
    "AIRA-060": 100,
    "AIRA-062": 100,
    "AIRA-070": 98,
    "AIRA-071": 92,
    "AIRA-020": 95,
    "AIRA-054": 95,
    "AIRA-055": 95,
    "AIRA-031": 95,
    "AIRA-067": 90,
    "AIRA-068": 90,
    "AIRA-052": 90,
    "AIRA-053": 90,
    "AIRA-069": 88,
    "AIRA-063": 85,
    "AIRA-059": 85,
    "AIRA-066": 80,
    "AIRA-050": 75,
    "AIRA-051": 75,
    "AIRA-056": 75,
    "AIRA-057": 75,
    "AIRA-001": 70,
    "AIRA-064": 65,
    "AIRA-058": 40,
    "AIRA-002": 35,
    "AIRA-040": 35,
    "AIRA-010": 10,
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
_UPLOAD_RE = re.compile(
    r"(?:-F|--form|--upload-file|--data-binary?|-d)\s+[^\s]*@([^\s\"']+)"
    r"|(?:-F|--form)\s+[\"']?[^=\s]+=@([^\s\"']+)",
    re.IGNORECASE,
)
_SECRET_PATH_RE = re.compile(
    r"(?:"
    r"[~/\w.-]*openclaw-agent\.sqlite"
    r"|[~/\w.-]*auth-profiles\.json"
    r"|[~/\w.-]*database\.sqlite"
    r"|[~/\w.-]*openclaw-auth-intake/[^\s\"';]+"
    r"|[~/\w.-]*\.ssh(?:/[^\s\"']+)?"
    r"|[~/\w.-]*/\.env(?:\.[^\s\"']*)?"
    r"|[~/\w.-]*credentials(?:/[^\s\"']*)?"
    r")",
    re.IGNORECASE,
)
_MULTIPART_TYPE_RE = re.compile(r";type=[^;\"'\s]+", re.IGNORECASE)
_QUOTED_RE = re.compile(r"""(['"])(?P<body>(?:\\.|[^\\])*?)(\1)""")
# Allow ``/bin/bash -c`` / ``/usr/bin/python3 -c`` (common in live OpenClaw logs).
_INLINE_SCRIPT_RE = re.compile(
    r"^(?:/(?:[\w.-]+/)*)?(?P<interp>python3?|node|nodejs|bash|sh|zsh|ruby|perl)"
    r"(?:\s+[^\s]+)*\s+(?P<flag>-c|-e)\s+",
    re.IGNORECASE,
)
_SECRET_TOKEN_RE = re.compile(
    r"(?i)\b(?:"
    r"sk-[a-z0-9_-]{8,}"
    r"|bearer\s+[a-z0-9._~+/=-]{8,}"
    r"|ghp_[a-z0-9]{8,}"
    r"|fidu_[a-z0-9_-]{8,}"
    r")\b"
)
# Chat / gateway webhook path tokens — keep host, drop secret segment
# (Discord ``/api/webhooks/<id>/<token>`` and similar shapes).
_WEBHOOK_SECRET_RE = re.compile(r"(?i)(/api/webhooks/(?:\d+|\[REDACTED\])/)([A-Za-z0-9_-]{20,})")
_CHAT_WEBHOOK_RE = re.compile(
    r"(?i)(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/"
    r"|(?:outlook\.office(?:365)?\.com|webhook\.office\.com)/webhookb2"
    r"|/api/webhooks/)"
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?i)(?:curl|wget|fetch)\s+[^\n]*\|\s*(?:ba)?sh\b"
    r"|base64\s+[^\n]*\|\s*(?:ba)?sh\b"
)
_GREP_SECRET_HARVEST_RE = re.compile(
    r"(?i)\bgrep\b[^\n]*(?:token|api[_-]?key|secret|pass(?:word|wd)?|credential)"
)
# Google Workspace CLI (``gog …``) is a common benign exec-review shape.
_GOG_SERVICE_RE = re.compile(
    r"(?i)\bgog\s+(?P<svc>gmail|docs?|sheets?|calendar|drive|slides|tasks)"
    r"(?:\s+(?P<sub>[A-Za-z][\w-]*))?"
)
# OpenClaw host CLI is the other large benign/admin review cluster.
_OPENCLAW_CLI_RE = re.compile(
    r"(?i)\bopenclaw\s+(?P<area>message|config|gateway|doctor|agents|models|status|backup|skills)"
    r"(?:\s+(?P<sub>[\w.-]+))?"
)
# Local wiki skill scripts under agent skill dirs.
_WIKI_SCRIPT_RE = re.compile(r"(?i)(?:mediawiki|wiki)\.py\b")
_NTN_RE = re.compile(r"(?i)(?:^|[\s;|&])ntn\b")
_NOTION_SCRIPT_RE = re.compile(r"(?i)notion\.js\b")
_WHICH_CLI_RE = re.compile(r"(?i)(?:^|[\s;|&])which\b")
_MKDIR_OPENCLAW_RE = re.compile(r"(?i)\bmkdir\b[^\n]*\.openclaw")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
_ECHO_ENV_SECRET_RE = re.compile(
    r"(?i)\becho\b[^\n]*\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)"
)
_API_TOKEN_HEADER_RE = re.compile(
    r"(?i)(?:Authorization:\s*(?:Bearer|Bot)\s*\$|Bearer\s+\$[A-Z0-9_]+)"
)
_PKILL_OPENCLAW_RE = re.compile(
    r"(?i)\b(?:pkill|killall|kill)\b[^\n]*openclaw|\bpkill\b[^\n]*gateway"
)
# Scheme-less curl hosts (``curl wttr.in/...``) common in soak logs.
_CURL_BARE_HOST_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]*?['\"]?(?:https?://)?(?P<host>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})"
)
# Google Drive/Docs ids are long opaque tokens; they blow the 256-char card budget.
_GOOGLE_DOC_ID_RE = re.compile(r"\b[A-Za-z0-9_-]{33,44}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_ENV_PIPE_GREP_RE = re.compile(r"(?i)\benv\b[^\n]*\|\s*grep\b")
_ENV_CRED_NEEDLE_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|credential|auth|bearer)\b"
)
_EMBEDDED_CURL_RE = re.compile(r"(?i)\$\(\s*(?:curl|wget)\b")
_CONNECT_RE = re.compile(
    r"sqlite3\.connect\s*\(\s*(?P<q>['\"])(?P<path>.+?)(?P=q)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class _Span:
    text: str
    priority: int  # lower = more important
    kind: str


@dataclass(frozen=True)
class ApprovalCard:
    """Operator-facing OpenClaw title (Command) and description (Shell Preview)."""

    title: str
    description: str
    command_found: bool = True


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _first_sentence(text: str) -> str:
    text = re.sub(r"\s+", " ", text.strip())
    if not text:
        return ""
    for sep in (". ", " — ", " - "):
        if sep in text:
            return text.split(sep, 1)[0].strip().rstrip(".")
    return text


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _scrub_secrets(text: str) -> str:
    # Keep webhook host/path shape before shared secret patterns, which would
    # otherwise replace the entire Discord/Slack URL with ``[REDACTED]``.
    text = _redact_webhook_urls(text)
    text = apply_secret_patterns(text, load_rules())
    text = _SECRET_TOKEN_RE.sub("[redacted]", text)
    return _WEBHOOK_SECRET_RE.sub(r"\1[redacted]", text)


def _redact_webhook_urls(text: str) -> str:
    """Replace webhook URLs with ``https://{host}/[redacted-webhook]`` (host kept)."""

    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        url = raw.rstrip(").,;]")
        trailing = raw[len(url) :]
        if not _is_webhook_url(url):
            return raw
        host = _host_from_url(url) or "host"
        return f"https://{host}/[redacted-webhook]{trailing}"

    return _URL_RE.sub(repl, text)


def _command_urls(command: str) -> list[str]:
    """URLs from argv and inline-script literals, before secret wiping."""
    found: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        cleaned = url.rstrip(").,;]")
        key = cleaned.lower()
        if not cleaned or key in seen:
            return
        seen.add(key)
        found.append(cleaned)

    for url in _URL_RE.findall(command):
        add(url)
    split = _split_inline_script(command)
    if split:
        _interp, body = split
        for url in _URL_RE.findall(body):
            add(url)
        for lit in _python_string_literals(body):
            for url in _URL_RE.findall(lit):
                add(url)
    return found


def _shorten_google_ids(text: str) -> str:
    return _GOOGLE_DOC_ID_RE.sub(lambda m: "…" + m.group(0)[-6:], text)


def _shorten_emails(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        email = match.group(0)
        local, _, domain = email.partition("@")
        if len(local) <= 2:
            return f"{local}…@{domain}"
        return f"{local[:2]}…@{domain}"

    return _EMAIL_RE.sub(repl, text)


def _compress_operator_noise(text: str) -> str:
    """Shorten Drive ids / emails so titles and excerpts stay readable."""
    return _shorten_emails(_shorten_google_ids(text))


def _gog_service_bits(text: str) -> tuple[str, str] | None:
    """Return (service, subcommand) for Google Workspace CLI argv (``gog …``), or None."""
    m = _GOG_SERVICE_RE.search(text)
    if not m:
        return None
    svc = m.group("svc").lower()
    if svc == "doc":
        svc = "docs"
    elif svc == "sheet":
        svc = "sheets"
    sub = (m.group("sub") or "").lower()
    return svc, sub


def _estimate_gog_intent(text: str) -> str | None:
    if not re.search(r"(?i)\bgog\b", text):
        return None
    if re.search(r"(?i)(?:^|\s)--help(?:\s|$)", text) or re.search(
        r"(?i)\bgog\s+\w+\s+help\b", text
    ):
        return "check Google Workspace CLI help"
    bits = _gog_service_bits(text)
    if not bits:
        return "use Google Workspace CLI"
    svc, sub = bits
    if sub == "help":
        return "check Google Workspace CLI help"
    if svc == "gmail":
        return "read Gmail via Google Workspace CLI"
    if svc == "docs":
        return "read Google Docs via Google Workspace CLI"
    if svc == "sheets":
        return "read Google Sheets via Google Workspace CLI"
    if svc == "calendar":
        return "read Google Calendar via Google Workspace CLI"
    return f"use Google Workspace CLI ({svc})"


def _format_gog_excerpt(command: str, limit: int) -> str:
    """Compact Workspace CLI argv: service + action + short id/account/out, not raw Drive ids."""
    collapsed = _collapse_ws(_scrub_secrets(command))
    # Drop leading ``echo '…' &&`` commentary before the real CLI.
    collapsed = re.sub(r'(?i)^echo\s+(["\'])(?:\\.|[^\\])*?\1\s*&&\s*', "", collapsed)
    collapsed = _compress_operator_noise(collapsed)
    bits = _gog_service_bits(collapsed)
    if not bits:
        return _truncate(collapsed, limit)
    svc, sub = bits
    parts: list[str] = ["gog", svc]
    if sub and sub not in {"help"}:
        parts.append(sub)
    elif re.search(r"(?i)(?:^|\s)--help(?:\s|$)", collapsed):
        parts.append("--help")

    account = re.search(r"(?i)--account\s+(\S+)", collapsed)
    out = re.search(r"(?i)--out\s+(\S+)", collapsed)
    short_id = re.search(r"…[A-Za-z0-9_-]{6}", collapsed)
    sheet_title = re.search(r'"([^"]{3,48})"', collapsed)

    if account:
        parts.append(account.group(1))
    elif short_id and svc in {"docs", "drive", "sheets"}:
        parts.append(short_id.group(0))
    elif sheet_title and svc == "sheets":
        parts.append(f'"{sheet_title.group(1)}"')

    if out:
        parts.append(f"→ {_shorten_path(out.group(1), 28)}")

    assembled = " ".join(parts)
    if len(assembled) < _MIN_EXCERPT_CHARS and len(collapsed) > len(assembled):
        return _truncate(collapsed, limit)
    return _truncate(assembled, limit)


def _estimate_openclaw_cli_intent(text: str) -> str | None:
    m = _OPENCLAW_CLI_RE.search(text)
    if not m:
        return None
    area = m.group("area").lower()
    sub = (m.group("sub") or "").lower()
    if re.search(r"(?i)(?:^|\s)--help(?:\s|$)", text):
        return "check openclaw CLI help"
    if area == "message":
        # Online/openclaw soak: ``openclaw message action=read channel=discord …``
        if re.search(r"(?i)action\s*=\s*read", text) or (
            re.search(r"(?i)\bmessage\s+read\b", text)
            and not re.search(r"(?i)(?:-m|--message|\bsend\b)", text)
        ):
            if re.search(r"(?i)discord", text):
                return "read Discord messages via openclaw"
            return "read messages via openclaw"
        if re.search(r"(?i)discord", text):
            return "send a Discord message via openclaw"
        return "send a message via openclaw"
    if area == "config":
        if sub in {"patch", "set", "unset"} or "patch" in text.lower():
            return "change OpenClaw config"
        return "read OpenClaw config"
    if area == "gateway":
        if sub in {"restart", "install", "stop", "start"}:
            return f"{sub} the OpenClaw gateway"
        if sub == "status" or re.search(r"(?i)\bgateway\s+status\b|\bopenclaw\s+status\b", text):
            return "check OpenClaw gateway status"
        return "manage the OpenClaw gateway"
    if area == "doctor":
        return "run openclaw doctor"
    if area == "agents":
        return "manage OpenClaw agents"
    if area == "models":
        return "manage OpenClaw models/auth"
    if area == "backup":
        return "backup OpenClaw data"
    if area == "status":
        return "check OpenClaw status"
    return f"use openclaw {area}"


def _format_openclaw_excerpt(command: str, limit: int) -> str:
    """Compact openclaw CLI; drop long Discord message bodies."""
    collapsed = _collapse_ws(_scrub_secrets(command))
    # Replace long -m/--message payloads with a stub.
    collapsed = re.sub(
        r'(?i)(-m|--message)\s+(["\'])(?:\\.|[^\\])*?\2',
        r'\1 "…"',
        collapsed,
    )
    collapsed = re.sub(
        r"(?i)(-m|--message)\s+(\S{40,})",
        r"\1 …",
        collapsed,
    )
    m = _OPENCLAW_CLI_RE.search(collapsed)
    if not m:
        return _truncate(collapsed, limit)
    area = m.group("area")
    sub = m.group("sub") or ""
    parts: list[str] = ["openclaw", area]
    if re.search(r"(?i)action\s*=\s*read", collapsed):
        parts.append("action=read")
    elif sub:
        parts.append(sub)
    channel = re.search(r"(?i)--channel\s+(\S+)|(?:^|[\s])channel=(\S+)", collapsed)
    target = re.search(r"(?i)(?:-t|--target|--to)\s+(\S+)|(?:^|[\s])to=(\S+)", collapsed)
    cfg_key = re.search(r"(?i)\bopenclaw\s+config\s+(?:get|set|patch)\s+(\S+)", collapsed)
    if channel:
        parts.append(channel.group(1) or channel.group(2))
    elif target:
        parts.append(_truncate(target.group(1) or target.group(2), 28))
    elif cfg_key:
        parts.append(_truncate(cfg_key.group(1), 36))
    if re.search(r'(?i)(-m|--message)\s+"…"', collapsed):
        parts.append('-m "…"')
    assembled = " ".join(parts)
    if len(assembled) < _MIN_EXCERPT_CHARS:
        return _truncate(collapsed, limit)
    return _truncate(assembled, limit)


def _host_from_url(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host


def _shorten_path(path: str, max_len: int = 48) -> str:
    path = path.strip()
    if len(path) <= max_len:
        return path
    # Keep basename-ish tail (sqlite / auth markers).
    return "…" + path[-(max_len - 1) :]


def _clean_upload_path(path: str) -> str:
    """Strip curl multipart ``;type=…`` suffixes from ``@file`` captures."""
    return _MULTIPART_TYPE_RE.sub("", path.strip())


def _path_signal_score(path: str) -> int:
    """Higher = more useful to show operators (live auth DB over staging copies)."""
    lower = path.lower()
    score = 0
    # Live agent auth store beats intake/staging copies of the same data.
    if "openclaw-agent.sqlite" in lower:
        score += 80
    if "auth-profiles" in lower:
        score += 70
    if "credentials" in lower:
        score += 68
    if lower.rstrip("/").endswith(".env") or "/.env." in lower:
        score += 65
    if ".ssh" in lower:
        score += 60
    if "openclaw-auth-intake" in lower and ".sqlite" in lower:
        score += 40
    elif lower.endswith("database.sqlite") or "/database.sqlite" in lower:
        score += 45
    if lower.endswith(".sqlite"):
        score += 20
    if "manifest.json" in lower:
        score -= 30
    if lower.endswith(".json") and "auth" not in lower:
        score -= 10
    return score


def _order_by_appearance(command: str, spans: list[_Span]) -> list[_Span]:
    """Keep arrow direction as src → dst when both paths appear in the command."""

    def idx(span: _Span) -> int:
        pos = command.find(span.text)
        return pos if pos >= 0 else 10**9

    return sorted(spans, key=idx)


def _pending_args(record: ScanLogRecord, result: ScanResult) -> dict:
    pending = result.debug.pending_step
    if pending is None or not pending.args:
        return {}
    return canonicalize_tool_args(pending.tool, dict(pending.args))


def _usable_command_text(raw: object | None) -> str | None:
    """Return stripped argv, ignoring the PlanIR length placeholder."""
    if raw is None:
        return None
    text = raw.strip() if isinstance(raw, str) else stringify_arg_value(raw).strip()
    if not text or text == "[TRUNCATED]":
        return None
    return text


def _full_pending_command(record: ScanLogRecord, result: ScanResult) -> str | None:
    """Prefer full pending argv from scan debug; fall back to log excerpt."""
    args = _pending_args(record, result)
    for key in _EXEC_COMMAND_KEYS:
        command = _usable_command_text(args.get(key))
        if command is not None:
            return command
    return _usable_command_text(record.pending_command_excerpt)


def _arg_text(args: dict, key: str) -> str | None:
    if key not in args:
        return None
    return _usable_command_text(stringify_arg_value(args.get(key)))


def _pending_path_from_args(args: dict) -> str | None:
    for key in _PATH_KEYS:
        text = _arg_text(args, key)
        if text:
            return text
    return None


def _process_action(args: dict) -> str | None:
    raw = _arg_text(args, "action")
    return raw.lower() if raw else None


def _process_session(args: dict) -> str | None:
    for key in _SESSION_KEYS:
        text = _arg_text(args, key)
        if text:
            return text
    return None


def _display_arg_pair(key: str, value: object) -> str | None:
    raw = stringify_arg_value(value).strip()
    if not raw or raw == "[TRUNCATED]":
        return None
    shown = "[REDACTED]" if _SECRET_ARG_KEY.search(key) else _scrub_secrets(raw)
    return f"{key}={shown}"


def pack_structured_args(args: dict, limit: int) -> str:
    parts: list[str] = []
    seen: set[str] = set()

    def emit(key: str) -> None:
        if key in seen or key not in args:
            return
        seen.add(key)
        pair = _display_arg_pair(key, args[key])
        if pair:
            parts.append(pair)

    for key in _STRUCTURED_LEAD_KEYS:
        emit(key)
    for key in args:
        emit(key)
    return pack_signal_excerpt(" ".join(parts), limit)


def has_structured_preview(args: dict | None) -> bool:
    if not args:
        return False
    for value in args.values():
        text = stringify_arg_value(value).strip()
        if text and text != "[TRUNCATED]":
            return True
    return False


def _build_structured_card(tool: str, args: dict) -> ApprovalCard:
    action = _process_action(args)
    session = _process_session(args)
    if tool == "process" and action:
        intent = _PROCESS_LIFECYCLE_INTENTS.get(action)
        title = (
            _truncate(f"process {action}: {session}", TITLE_MAX)
            if session
            else _truncate(f"process {action}", TITLE_MAX)
        )
        if intent:
            intent_line = f"Likely: {intent}"
            budget = max(_MIN_COMMAND_CHARS, DESCRIPTION_MAX - len(intent_line) - 1)
            excerpt = pack_structured_args(args, budget)
            body = f"{intent_line}\n{excerpt}"
            description = (
                body if len(body) <= DESCRIPTION_MAX else _truncate(intent_line, DESCRIPTION_MAX)
            )
            return ApprovalCard(title=title, description=description, command_found=False)
        return ApprovalCard(
            title=title,
            description=_truncate(pack_structured_args(args, DESCRIPTION_MAX), DESCRIPTION_MAX),
            command_found=False,
        )
    title = _truncate(f"{tool} {action}", TITLE_MAX) if action else _truncate(tool, TITLE_MAX)
    return ApprovalCard(
        title=title,
        description=_truncate(pack_structured_args(args, DESCRIPTION_MAX), DESCRIPTION_MAX),
        command_found=False,
    )


def _pending_tool(record: ScanLogRecord, result: ScanResult) -> str:
    return record.pending_tool or result.plan.pending_tool or "tool"


def winning_rule_for_copy(matched: list[MatchedRule]) -> MatchedRule | None:
    """Pick the rule that should drive operator-facing intent (not scan merge)."""
    actionable = [r for r in matched if r.action in ("review", "block")]
    if not actionable:
        return None

    def sort_key(rule: MatchedRule) -> tuple:
        action_rank = 0 if rule.action == "block" else 1
        severity = -_SEVERITY_RANK.get(rule.severity, 1)
        specificity = -_RULE_SPECIFICITY.get(rule.id, 50)
        return (action_rank, severity, specificity, rule.id)

    return sorted(actionable, key=sort_key)[0]


def _split_inline_script(command: str) -> tuple[str, str] | None:
    """Return (interpreter, script_body) for ``python3 -c '…'`` / ``bash -c`` etc."""
    collapsed = command.strip()
    m = _INLINE_SCRIPT_RE.match(collapsed)
    if not m:
        return None
    interp = m.group("interp").lower()
    if interp.startswith("python"):
        interp = "python3" if "3" in interp or interp == "python" else interp
    rest = collapsed[m.end() :]
    if not rest:
        return None
    # Quoted -c payload
    if rest[0] in "'\"":
        q = rest[0]
        body: list[str] = []
        i = 1
        while i < len(rest):
            ch = rest[i]
            if ch == "\\" and i + 1 < len(rest):
                body.append(rest[i + 1])
                i += 2
                continue
            if ch == q:
                break
            body.append(ch)
            i += 1
        return interp, "".join(body)
    # Unquoted remainder (rare; take all)
    return interp, rest


def _python_string_literals(script: str) -> list[str]:
    try:
        tree = ast.parse(script)
    except SyntaxError:
        return [m.group("body") for m in _QUOTED_RE.finditer(script)]
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
    return out


def _collect_spans_from_text(text: str) -> list[_Span]:
    spans: list[_Span] = []
    scrubbed = _scrub_secrets(text)
    for url in _URL_RE.findall(scrubbed):
        url = url.rstrip(").,;]")
        spans.append(_Span(url, 1, "url"))
    # Scheme-less hosts in curl/wget (wttr.in, …).
    if not any(s.kind == "url" for s in spans):
        bare = _CURL_BARE_HOST_RE.search(scrubbed)
        if bare:
            host = bare.group("host").rstrip(").,;]")
            spans.append(_Span(f"https://{host}", 1, "url"))
    for m in _UPLOAD_RE.finditer(scrubbed):
        path = m.group(1) or m.group(2)
        if not path:
            continue
        cleaned = _clean_upload_path(path)
        # ``curl -F f=@-`` (stdin) is not a useful leaf; skip for excerpt ranking.
        if cleaned in {"-", "/dev/stdin"}:
            continue
        spans.append(_Span(cleaned, 2, "upload"))
    for path in _SECRET_PATH_RE.findall(scrubbed):
        spans.append(_Span(path, 3, "secret_path"))
    for m in _CONNECT_RE.finditer(scrubbed):
        spans.append(_Span(m.group("path"), 3, "sqlite_connect"))
    return spans


def _dedupe_spans(spans: list[_Span]) -> list[_Span]:
    seen: set[str] = set()
    out: list[_Span] = []
    # Prefer higher signal paths, then lower priority number, then longer text.
    ordered = sorted(
        spans,
        key=lambda s: (-_path_signal_score(s.text), s.priority, -len(s.text)),
    )
    for span in ordered:
        key = span.text.lower()
        if key in seen:
            continue
        # Drop substrings of an already-chosen longer path/url.
        if any(key in other.lower() and key != other.lower() for other in seen):
            continue
        seen.add(key)
        out.append(span)
    return out


def extract_salient_spans(command: str) -> list[_Span]:
    """High-signal spans from argv or inline script bodies."""
    spans = _collect_spans_from_text(command)
    split = _split_inline_script(command)
    if split:
        _interp, body = split
        spans.extend(_collect_spans_from_text(body))
        for lit in _python_string_literals(body):
            spans.extend(_collect_spans_from_text(lit))
            if _SECRET_PATH_RE.search(lit) or lit.endswith(".sqlite"):
                spans.append(_Span(lit, 3, "literal_path"))
    return _dedupe_spans(spans)


def _best_paths(spans: list[_Span], *, limit: int = 2) -> list[_Span]:
    paths = [
        s for s in spans if s.kind in ("secret_path", "sqlite_connect", "literal_path", "upload")
    ]
    paths = sorted(paths, key=lambda s: -_path_signal_score(s.text))
    return paths[:limit]


def _is_openclaw_inspect(text: str, *, has_secret_path: bool) -> bool:
    """``cd ~/.openclaw/… && grep/find`` without secret paths counts as inspect."""
    if has_secret_path or ".openclaw" not in text.lower():
        return False
    if re.search(r"(?i)\b(?:curl|wget)\b", text):
        return False
    return bool(re.search(r"(?i)\b(?:ls|find|grep|cat|head)\b", text))


def _primary_exec_verb(collapsed: str) -> str:
    """Prefer curl/python/openclaw over a leading ``cd`` in compound commands.

    Do not treat path segments like ``/.openclaw/`` as the ``openclaw`` CLI.
    """
    for candidate in (
        "curl",
        "wget",
        "python3",
        "python",
        "openclaw",
        "gog",
        "ntn",
        "npx",
        "bash",
        "sh",
    ):
        if re.search(rf"(?i)(?:^|[\s;|&]|\$\(){re.escape(candidate)}\b", collapsed):
            return candidate
    raw = collapsed.split(" ", 1)[0] if collapsed else "cmd"
    return raw.rsplit("/", 1)[-1] if "/" in raw else raw


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    lower = host.lower().split("%", 1)[0]
    return lower in _LOOPBACK_HOSTS or lower.endswith(".localhost")


def _is_webhook_url(url: str) -> bool:
    """True for webhook-shaped URLs (path or hooks.* host), any provider."""
    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        host = (parsed.hostname or "").lower()
    except ValueError:
        lower = url.lower()
        return "/webhook" in lower or "/hooks/" in lower
    if host.startswith("hooks."):
        return True
    return "/webhook" in path or "/hooks/" in path


def _looks_like_url_or_path(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith(("@", "/", "~")):
        return True
    if re.match(r"(?i)^https?://", stripped):
        return True
    return bool(_URL_RE.search(stripped))


def _payload_stub(body: str, quote: str) -> str:
    """Short stand-in for a long quoted payload; keep a content/text preview when JSON."""
    stripped = body.strip()
    preview = "…"
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        preview = "{…}"
        for key in ("content", "text", "body", "message", "caption"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                shown = _collapse_ws(value).replace(quote, "")
                if len(shown) > _PAYLOAD_PREVIEW:
                    shown = shown[: _PAYLOAD_PREVIEW - 1] + "…"
                preview = f"{{{key}: {shown}}}"
                break
    elif isinstance(data, list):
        preview = "[…]"
    return f"{quote}{preview}{quote}"


def _should_collapse_payload(previous_token: str, body: str) -> bool:
    if len(body) < _PAYLOAD_COLLAPSE_MIN:
        return False
    if _looks_like_url_or_path(body):
        return False
    flag = previous_token.split("=", 1)[0].lower()
    if flag in _BODY_FLAGS:
        return True
    stripped = body.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def collapse_long_payloads(command: str) -> str:
    """Replace long quoted JSON/message bodies; keep URLs, paths, and destinations.

    Linear scan (no nested quote regex) so long payloads cannot trip ReDoS.
    """
    out: list[str] = []
    i = 0
    n = len(command)
    prev_token = ""
    token: list[str] = []

    def flush_token() -> None:
        nonlocal prev_token
        if token:
            prev_token = "".join(token)
            token.clear()

    while i < n:
        ch = command[i]
        if ch in "'\"":
            quote = ch
            i += 1
            body_chars: list[str] = []
            while i < n:
                cur = command[i]
                if cur == "\\" and i + 1 < n:
                    body_chars.append(cur)
                    body_chars.append(command[i + 1])
                    i += 2
                    continue
                if cur == quote:
                    i += 1
                    break
                body_chars.append(cur)
                i += 1
            body = "".join(body_chars)
            if _should_collapse_payload(prev_token, body):
                out.append(_payload_stub(body, quote))
            else:
                out.append(f"{quote}{body}{quote}")
            prev_token = ""
            token.clear()
            continue
        if ch.isspace() or ch in ";|&":
            flush_token()
            out.append(ch)
            i += 1
            continue
        token.append(ch)
        out.append(ch)
        i += 1
    return "".join(out)


def honest_miss_title(tool: str) -> str:
    if tool == "exec":
        return "exec: no command preview"
    return _truncate(f"{tool}: no preview", TITLE_MAX)


def is_policy_headline(title: str) -> bool:
    """Sidecar titles that name a rule/tool instead of the pending action."""
    return title.strip().lower().startswith("sentrook review:")


def structural_intent(command: str, *, tool: str = "exec") -> str | None:
    """Short why-it-matters line from argv shape, or None when we would only say 'exec'."""
    urls = _command_urls(command)
    spans = extract_salient_spans(command)
    uploads = [s for s in spans if s.kind == "upload"]
    secrets = [s for s in spans if s.kind in ("secret_path", "sqlite_connect", "literal_path")]
    if urls:
        url = urls[0]
        host = _host_from_url(url)
        if _is_webhook_url(url):
            return "post a webhook message"
        if _is_loopback_host(host):
            return "call a local service"
        if uploads:
            return f"upload a file to {host}" if host else "upload a file"
        if re.search(r"(?i)\b(?:curl|wget|urllib|requests)\b", command):
            return (
                f"send an outbound HTTP request to {host}"
                if host
                else "send an outbound HTTP request"
            )
        return f"contact {host}" if host else None
    if uploads:
        return "upload a file"
    if secrets:
        return "access a sensitive path"
    if tool == "exec":
        return None
    return None


def build_command_title(command: str, *, tool: str = "exec") -> str:
    """Command-field copy (≤80 chars) from local argv."""
    urls = _command_urls(command)
    spans = extract_salient_spans(command)
    secrets = [
        s for s in spans if s.kind in ("secret_path", "sqlite_connect", "literal_path", "upload")
    ]
    collapsed = collapse_long_payloads(_collapse_ws(_scrub_secrets(command)))
    verb = _primary_exec_verb(collapsed)

    if urls and secrets:
        host = _host_from_url(urls[0]) or urls[0]
        leaf = secrets[0].text.rstrip("/").split("/")[-1]
        if _is_loopback_host(host):
            return _truncate(f"local: {leaf}", TITLE_MAX)
        return _truncate(f"{leaf} → {host}", TITLE_MAX)
    if urls:
        url = urls[0]
        host = _host_from_url(url) or url
        if _is_webhook_url(url):
            return _truncate(f"webhook → {host}", TITLE_MAX)
        if _is_loopback_host(host):
            return _truncate(f"local → {host}", TITLE_MAX)
        return _truncate(f"{verb} → {host}", TITLE_MAX)
    if secrets:
        return _truncate(f"{verb} {_shorten_path(secrets[0].text, 40)}", TITLE_MAX)
    return _truncate(build_smart_excerpt(command, limit=TITLE_MAX), TITLE_MAX)


def build_command_description(command: str, *, tool: str = "exec") -> str:
    """Shell-preview copy (≤256 chars) from local argv."""
    intent = structural_intent(command, tool=tool)
    if intent in _GENERIC_INTENTS:
        intent = None
    collapsed = collapse_long_payloads(_collapse_ws(_scrub_secrets(command)))
    if intent:
        intent_line = f"Likely: {intent}"
        budget = DESCRIPTION_MAX - len(intent_line) - 1
        if budget >= _MIN_COMMAND_CHARS:
            excerpt = pack_signal_excerpt(collapsed, budget)
            body = f"{intent_line}\n{excerpt}"
            if len(body) <= DESCRIPTION_MAX:
                return body
        return _truncate(intent_line, DESCRIPTION_MAX)
    return pack_signal_excerpt(collapsed, DESCRIPTION_MAX)


def build_approval_card(
    *,
    command: str | None,
    tool: str = "exec",
    path: str | None = None,
    args: dict | None = None,
) -> ApprovalCard:
    """Build OpenClaw Command / Shell Preview copy from pending argv or structured args."""
    usable = _usable_command_text(command)
    if usable is None and args:
        for key in _EXEC_COMMAND_KEYS:
            usable = _usable_command_text(args.get(key))
            if usable is not None:
                break
    if usable:
        return ApprovalCard(
            title=build_command_title(usable, tool=tool),
            description=build_command_description(usable, tool=tool),
            command_found=True,
        )
    resolved_path = (str(path).strip() if path else "") or (
        _pending_path_from_args(args) if args else None
    )
    if resolved_path:
        leaf = _shorten_path(str(resolved_path).strip(), 48)
        return ApprovalCard(
            title=_truncate(f"{tool}: {leaf}", TITLE_MAX),
            description=_truncate(f"`{tool}` `{leaf}`", DESCRIPTION_MAX),
            command_found=False,
        )
    if args and has_structured_preview(args):
        return _build_structured_card(tool, args)
    miss = honest_miss_title(tool)
    return ApprovalCard(
        title=miss,
        description=_truncate(f"{tool}: command was not available to summarise", DESCRIPTION_MAX),
        command_found=False,
    )


def _pending_path(record: ScanLogRecord, result: ScanResult) -> str | None:
    return _pending_path_from_args(_pending_args(record, result))


def _format_script_excerpt(
    interp: str, spans: list[_Span], limit: int, *, command: str = ""
) -> str:
    if not spans:
        return _truncate(f"{interp} -c: long script, no clear URL/path", limit)

    urls = [s for s in spans if s.kind == "url"]
    paths = _best_paths(spans, limit=2)
    if command and len(paths) == 2:
        paths = _order_by_appearance(command, paths)
    bits: list[str] = [f"{interp} -c:"]
    if paths:
        shown = [_shorten_path(p.text, 44) for p in paths]
        if len(shown) == 2 and shown[0] != shown[1]:
            bits.append(f"{shown[0]} → {shown[1]}")
        else:
            bits.append(shown[0])
    if urls:
        host = _host_from_url(urls[0].text) or urls[0].text
        bits.append(f"→ {host}")
    return _truncate(" ".join(bits), limit)


def _format_argv_excerpt(command: str, spans: list[_Span], limit: int) -> str:
    collapsed = _compress_operator_noise(_collapse_ws(_scrub_secrets(command)))
    if re.search(r"(?i)\bgog\b", collapsed):
        return _format_gog_excerpt(command, limit)
    if _OPENCLAW_CLI_RE.search(collapsed):
        return _format_openclaw_excerpt(command, limit)

    if len(collapsed) <= limit and not spans:
        return collapsed

    urls = [s for s in spans if s.kind == "url"]
    paths = _best_paths(spans, limit=2)
    uploads = [s for s in paths if s.kind == "upload"]
    secrets = [s for s in paths if s.kind != "upload"]
    pipe_shell = bool(_PIPE_TO_SHELL_RE.search(collapsed))
    embedded_curl = bool(_EMBEDDED_CURL_RE.search(collapsed))

    verb = _primary_exec_verb(collapsed)
    if embedded_curl and urls:
        host = _host_from_url(urls[0].text) or urls[0].text
        return _truncate(f"$(curl → {host})", limit)

    parts: list[str] = [verb]

    if uploads:
        leaf = uploads[0].text.rstrip("/").split("/")[-1]
        parts.append(f"@…/{leaf}")
    elif secrets:
        parts.append(_shorten_path(secrets[0].text, 36))

    if urls:
        host = _host_from_url(urls[0].text) or urls[0].text
        parts.append(f"→ {host}")
    elif len(paths) > 1:
        parts.append(f"→ {_shorten_path(paths[1].text, 28)}")

    if pipe_shell:
        parts.append("| bash")

    assembled = " ".join(parts)
    if len(assembled) >= _MIN_EXCERPT_CHARS or urls or paths or pipe_shell:
        return _truncate(assembled, limit)

    # Fallback: keep head + tail so URLs at the end survive.
    if len(collapsed) <= limit:
        return collapsed
    head = max(24, limit // 3)
    tail = max(24, limit - head - 3)
    return collapsed[:head] + "…" + collapsed[-tail:]


def build_smart_excerpt(command: str, *, limit: int) -> str:
    """Operator-facing command excerpt within ``limit`` chars."""
    if limit < _MIN_COMMAND_CHARS:
        return _truncate(_collapse_ws(command), max(limit, 0))
    spans = extract_salient_spans(command)
    split = _split_inline_script(command)
    if split and (len(command) > limit or len(split[1]) > 80):
        return _format_script_excerpt(split[0], spans, limit, command=command)
    return _format_argv_excerpt(command, spans, limit)


def estimate_likely_intent(
    command: str | None,
    winning: MatchedRule | None,
    *,
    tool: str = "exec",
) -> str:
    """Closed-catalog intent line; under-claim rather than invent theft.

    Arg/script signals outrank broad chain rules (010/058/064) so Discord posts
    and auth-store reads are not described as bare "shell after reading a file".
    """
    text = command or ""
    spans = extract_salient_spans(text) if text else []
    urls = [s.text for s in spans if s.kind == "url"]
    host = _host_from_url(urls[0]) if urls else None
    has_sqlite = any("sqlite" in s.text.lower() or "auth-intake" in s.text.lower() for s in spans)
    has_auth_json = any("auth-profiles" in s.text.lower() for s in spans)
    has_env = any(s.text.rstrip("/").endswith(".env") or "/.env" in s.text.lower() for s in spans)
    has_ssh = any(".ssh" in s.text.lower() for s in spans)
    has_credentials_dir = any("credentials" in s.text.lower() for s in spans)
    has_secret_path = has_sqlite or has_auth_json or has_env or has_ssh or has_credentials_dir
    has_file_upload = any(s.kind == "upload" for s in spans) or bool(
        re.search(
            r"(?i)(?:-F|--form|--upload-file|-d\s+@|--data-binary?\s+@)",
            text,
        )
    )
    # Piped stdin uploads (``tar … | curl -F f=@-``) still count as upload.
    has_stdin_upload = bool(
        re.search(r"(?i)(?:-F|--form|--upload-file)\s+[^\s]*@-", text)
        or re.search(r"(?i)\|\s*curl\b", text)
    )
    rid = winning.id if winning else ""
    exporting_secret = has_secret_path and (has_file_upload or has_stdin_upload) and not has_ssh

    # --- Strong signals (override soft chain rules) ---
    if rid in ("AIRA-020", "AIRA-054") or _PIPE_TO_SHELL_RE.search(text):
        return "download and run remote/untrusted code"

    if rid == "AIRA-055":
        # Embedded ``$(curl …)`` fetch is not the same as pipe-to-shell.
        if _EMBEDDED_CURL_RE.search(text) and not _PIPE_TO_SHELL_RE.search(text):
            if host:
                return f"fetch from {host} via $(curl…)"
            return "run embedded curl fetch ($(curl…))"
        return "download and run remote/untrusted code"

    if rid == "AIRA-060" or (has_ssh and (has_file_upload or has_stdin_upload)):
        return f"upload SSH keys to {host}" if host else "upload SSH key material"

    # True credential exfil: secret path + upload, or dedicated 067/069.
    # AIRA-052 alone on ``curl … Bearer $TOKEN`` is often a SaaS API call, not exfil.
    if rid in ("AIRA-067", "AIRA-069") or exporting_secret:
        if host:
            return f"export credentials/auth data to {host}"
        return "export credentials/auth data off this machine"

    if rid == "AIRA-052":
        if exporting_secret:
            if host:
                return f"export credentials/auth data to {host}"
            return "export credentials/auth data off this machine"
        if host and _API_TOKEN_HEADER_RE.search(text):
            return f"call {host} with an API token"
        if host:
            return f"call {host} (possible credential use)"
        return "use credentials in an outbound request"

    if rid == "AIRA-031":
        return "change SSH access on this machine"

    if rid == "AIRA-050":
        return "change agent security or standing config"

    if rid == "AIRA-070":
        return "install or change an executable OpenClaw hook"

    if rid == "AIRA-062":
        return "install a hook that uploads data off this machine"

    if rid == "AIRA-071":
        return "store exfil or secret-shaped standing orders in memory"

    if rid in ("AIRA-051", "AIRA-056", "AIRA-057"):
        return "write lasting instructions into agent memory"

    if rid in ("AIRA-063", "AIRA-068"):
        return "send data out via messaging (possible leak)"

    if rid == "AIRA-065":
        return "act on content that may include injection markers"

    # pkill/kill openclaw must not be labeled as credential probe (059).
    if _PKILL_OPENCLAW_RE.search(text) or (
        rid == "AIRA-059" and re.search(r"(?i)\b(?:pkill|killall)\b", text)
    ):
        return "stop or restart OpenClaw processes"

    if rid == "AIRA-059" or (has_secret_path and not has_file_upload and not has_stdin_upload):
        if has_sqlite:
            return "read or copy the auth database"
        if has_auth_json or has_env or has_ssh or has_credentials_dir:
            return "read or probe credentials on this machine"
        # ``env | grep`` without credential-shaped needles is not a secret probe.
        if _ENV_PIPE_GREP_RE.search(text) and not _ENV_CRED_NEEDLE_RE.search(text):
            return "inspect environment variables"
        return "probe credentials on this machine"

    if _ECHO_ENV_SECRET_RE.search(text):
        return "print secret environment variables"

    if _GREP_SECRET_HARVEST_RE.search(text) and "openclaw" in text.lower():
        return "search agent files for secrets"

    if has_file_upload and host:
        if _is_loopback_host(host):
            return "call the local OpenClaw gateway"
        return f"upload a file to {host}"
    if urls and host and re.search(r"(?i)\b(?:curl|wget|urllib|requests)\b", text):
        if _CHAT_WEBHOOK_RE.search(text):
            return "post a chat webhook message"
        if _is_loopback_host(host):
            return "call the local OpenClaw gateway"
        if _API_TOKEN_HEADER_RE.search(text):
            return f"call {host} with an API token"
        return f"send an outbound HTTP request to {host}"

    gog_intent = _estimate_gog_intent(text)
    if gog_intent:
        return gog_intent

    oc_intent = _estimate_openclaw_cli_intent(text)
    if oc_intent:
        return oc_intent

    if _NTN_RE.search(text):
        if re.search(r"(?i)(?:^|\s)--help(?:\s|$)", text):
            return "check Notion CLI (ntn) help"
        return "use Notion via ntn"

    if _NOTION_SCRIPT_RE.search(text):
        return "use Notion skill script"

    if _WIKI_SCRIPT_RE.search(text):
        return "use wiki skill script"

    if _WHICH_CLI_RE.search(text):
        return "check whether a CLI tool is installed"

    if _MKDIR_OPENCLAW_RE.search(text):
        return "create directories under OpenClaw"

    if _is_openclaw_inspect(text, has_secret_path=has_secret_path):
        return "inspect OpenClaw files or config"

    # --- Broad chain / fallback (only when argv has no stronger story) ---
    if rid == "AIRA-064":
        return "run a shell command after reading a local file"

    if rid == "AIRA-058" or rid == "AIRA-001":
        return "run a shell command after reading a web page"

    if has_sqlite and _split_inline_script(text):
        return "copy or inspect the auth database"
    if tool == "exec":
        return "run a shell command"
    if tool in {"write", "edit"}:
        return "write or edit an agent file"
    if tool == "read":
        return "read a file"
    return f"use the {tool} tool"


def describe_pending_action(record: ScanLogRecord, result: ScanResult) -> str:
    """Plain-language description of what the agent is trying to do (single line)."""
    tool = _pending_tool(record, result)
    command = _full_pending_command(record, result)
    if tool == "exec" and command:
        return f"run: `{build_smart_excerpt(command, limit=100)}`"
    if command:
        return f"use `{tool}` with: `{build_smart_excerpt(command, limit=80)}`"
    args = _pending_args(record, result)
    if tool == "process":
        action = _process_action(args)
        session = _process_session(args)
        intent = _PROCESS_LIFECYCLE_INTENTS.get(action or "")
        if intent and session:
            return f"{intent} ({session})"
        if intent:
            return intent
        if action:
            return f"use the `process` tool ({action})"
    return f"use the `{tool}` tool"


def _rule_consequence(rule: MatchedRule) -> str:
    """Short plain-language consequence for a matched rule (no rule id)."""
    name = rule.name.lower()
    if rule.id == "AIRA-010" or "shell exec" in name:
        return "could run arbitrary commands on your machine"
    if rule.id == "AIRA-064" or "read then exec" in name:
        return "may be running instructions from a file it just read"
    if "fetch" in name and "exec" in name:
        return "may be running instructions from fetched web content"
    if "ssh" in name or "credential" in name or "secret" in name or "exfil" in name:
        return "could expose credentials or secrets"
    if "supply chain" in name or "install" in name:
        return "could install untrusted remote code"
    if "curl" in name or "obfuscated" in name or "remote shell" in name:
        return "could download and run remote code"
    if "write" in name and ("etc" in name or "ssh" in name or "path" in name):
        return "could modify sensitive system files"
    if rule.description:
        hint = _first_sentence(rule.description)
        if hint and not hint.lower().startswith("review when"):
            return hint[0].lower() + hint[1:] if len(hint) > 1 else hint
    return f"matched security policy {rule.id}"


def _rule_risk_line(rule: MatchedRule) -> str:
    """Longer risk line (rule name + consequence) for non-length-limited surfaces."""
    return f"{rule.name} — {_rule_consequence(rule)}"


def build_review_title(record: ScanLogRecord, result: ScanResult) -> str:
    return build_approval_card(
        command=_full_pending_command(record, result),
        tool=_pending_tool(record, result),
        path=_pending_path(record, result),
        args=_pending_args(record, result),
    ).title


def build_review_description(
    record: ScanLogRecord,
    result: ScanResult,
    *,
    max_len: int = DESCRIPTION_MAX,
) -> str:
    """Approval body, guaranteed to fit within ``max_len`` (OpenClaw caps at 256)."""
    card = build_approval_card(
        command=_full_pending_command(record, result),
        tool=_pending_tool(record, result),
        path=_pending_path(record, result),
        args=_pending_args(record, result),
    )
    return _truncate(card.description, max_len)


def build_block_reason(
    record: ScanLogRecord,
    result: ScanResult,
    *,
    max_len: int = DESCRIPTION_MAX,
) -> str:
    """User-facing block message (shown to the agent). Kept within ``max_len``."""
    tool = _pending_tool(record, result)
    command = _full_pending_command(record, result)
    matched = [r for r in result.matched_rules if r.action == "block"]
    winning = winning_rule_for_copy(matched)

    intent = estimate_likely_intent(command, winning, tool=tool)
    ids = ", ".join(r.id for r in matched[:2])
    reason = f"Sentrook blocked this: {intent}"
    reason += f" ({ids})." if ids else "."

    if command:
        prefix = "Blocked:\n" if tool == "exec" else f"Blocked `{tool}`:\n"
        fixed = len(prefix) + 2 + 1 + len(reason)
        budget_for_cmd = max_len - fixed
        if budget_for_cmd >= _MIN_COMMAND_CHARS:
            cmd = build_smart_excerpt(command, limit=budget_for_cmd)
            return _truncate(f"{prefix}`{cmd}`\n{reason}", max_len)
    return _truncate(reason, max_len)
