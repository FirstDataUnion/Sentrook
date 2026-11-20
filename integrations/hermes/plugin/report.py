"""A wrong-scan report: one scan from the traffic log, in a block the owner can copy and send to Sentrook.

The summary is what `/sentrook why` shows (without grant suggestions) plus the versions needed to look into
the scan: host, plugin, scanner and scan-wide versions, all read from the scan's own record. It holds no
PlanIR body, call arguments or conversation text, so the owner can post it in a public GitHub issue once
they have read it. The full record adds the scan's traffic-log lines exactly as written, so the scan can be
replayed; it can hold conversation text, paths and addresses, so it is only ever sent privately (to a
colleague, or by email to `SUPPORT_EMAIL`), never put in an issue or a link.

The OpenClaw plugin builds the same summary, full record, issue link and email link for the same log
(fixtures/traffic-log/report).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .config import SUPPORT_EMAIL, WRONG_SCAN_ISSUE_URL
from .history import READ_BUDGET_BYTES, _lines_backward, _response, _text, format_why

BEGIN = "----- BEGIN SENTROOK REPORT v1 -----"
END = "----- END SENTROOK REPORT v1 -----"
FULL_BEGIN = "----- BEGIN SENTROOK FULL RECORD v1 -----"
FULL_END = "----- END SENTROOK FULL RECORD v1 -----"
#: Longest issue link built; past this the entity lines are cut, then the report is left out.
URL_MAX = 6000
#: Shown above every full record.
FULL_WARNING = (
    "Full record: the exact request Sentrook saw. It can hold conversation text, file paths, names and "
    "addresses. Read it and remove anything private before sharing. Send it privately (to a colleague, or "
    f"by email to {SUPPORT_EMAIL}), never in a public issue. Email is not end-to-end encrypted; Sentrook "
    "keeps emailed records for up to 30 days, then deletes them."
)
EMAIL_BODY = (
    "Paste the Sentrook report below (the summary and the full record).\n\n"
    "GitHub issue, if you opened one:\n"
)
_FLAGS = ("--full", "--github", "--save")
_ENTITY = re.compile(r"^  \S")
_FILE_ID = re.compile(r"[^0-9A-Za-z-]")
_GRANTS = "grants that would allow it next time"


@dataclass(frozen=True)
class Found:
    scan: dict[str, Any]
    resolution: dict[str, Any] | None
    #: The traffic-log lines as written, without their newline.
    scan_line: str
    resolution_line: str | None


def find(path: Path, match: Any, budget: int = READ_BUDGET_BYTES) -> Found | None:
    """The newest scan whose request id `match` accepts, with its resolution and both raw lines."""
    left = [budget]
    resolutions: dict[str, tuple[dict[str, Any], str]] = {}
    for p in (path, path.with_name(path.name + ".1")):
        for raw in _lines_backward(p, left):
            line = raw.decode("utf-8", errors="replace")
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            rid = rec.get("request_id") if isinstance(rec, dict) else None
            if not isinstance(rid, str):
                continue
            if rec.get("kind") == "resolution":
                resolutions.setdefault(rid, (rec, line))
            elif rec.get("kind") == "scan" and match(rid):
                res = resolutions.get(rid)
                return Found(rec, res[0] if res else None, line, res[1] if res else None)
    return None


def _well(s: str) -> str:
    """`s` with any lone surrogate (a `\\ud800` escape in the log) as U+FFFD, so it encodes, as on OpenClaw."""
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _scalar(v: Any) -> str | None:
    """A version value as text: strings, whole numbers and booleans; anything else is left out."""
    if isinstance(v, bool):
        return "true" if v else "false"
    # Whole numbers JavaScript holds exactly, so both plugins print the same.
    if isinstance(v, int) and abs(v) < 2**53:
        return str(v)
    if isinstance(v, float) and v.is_integer() and abs(v) < 2**53:
        return str(int(v))
    if isinstance(v, str) and v:
        return _text(v, 60)
    return None


def _pairs(d: dict[str, Any]) -> str:
    out = []
    for k in sorted(d):
        s = _scalar(d[k])
        if s is not None:
            out.append(f"{_text(k, 40)} {s}")
    return ", ".join(out)


def host_of(scan: dict[str, Any]) -> dict[str, str]:
    host = _obj(_obj(scan.get("planir")).get("host"))

    def field(key: str) -> str:
        v = host.get(key)
        return _text(v, 40) if isinstance(v, str) and v.strip() else "?"

    return {
        "platform": field("platform"),
        "platform_version": field("platform_version"),
        "plugin_version": field("plugin_version"),
        "os": field("os"),
    }


def _why_lines(scan: dict[str, Any], resolution: dict[str, Any] | None) -> list[str]:
    lines = format_why(scan, resolution).split("\n")
    for i, line in enumerate(lines):
        if line.startswith(_GRANTS):
            return lines[:i]
    return lines


def _version_lines(scan: dict[str, Any]) -> list[str]:
    h = host_of(scan)
    meta = _obj(_obj(_response(scan)).get("metadata"))
    scanner = meta.get("scanner_version")
    lines = [
        f"host: {h['platform']} {h['platform_version']}, plugin {h['plugin_version']}, {h['os']}",
        f"mode: {_text(scan['mode'], 20) if isinstance(scan.get('mode'), str) and scan['mode'] else '?'}",
        f"scanner: {_text(scanner, 60) if isinstance(scanner, str) and scanner else '?'}",
    ]
    versions = _pairs(_obj(meta.get("versions")))
    if versions:
        lines.append(f"scan versions: {versions}")
    for probe in meta.get("probes") or []:
        if not isinstance(probe, dict) or not isinstance(probe.get("step"), str):
            continue
        pv = _pairs(_obj(probe.get("versions")))
        if pv:
            lines.append(f"probe {_text(probe['step'], 30)}: {pv}")
    return lines


def summary_lines(scan: dict[str, Any], resolution: dict[str, Any] | None) -> list[str]:
    lines = [*_why_lines(scan, resolution), *_version_lines(scan)]
    return [
        *(_well(line) for line in lines),
        "expected: (allow, review or block)",
        "what you were doing: (in your own words)",
    ]


def summary(scan: dict[str, Any], resolution: dict[str, Any] | None) -> str:
    return "\n".join((BEGIN, *summary_lines(scan, resolution), END))


def full_record(found: Found) -> str:
    lines = [FULL_BEGIN, found.scan_line]
    if found.resolution_line is not None:
        lines.append(found.resolution_line)
    lines.append(FULL_END)
    return "\n".join(lines)


def short_id(scan: dict[str, Any]) -> str:
    return str(scan.get("request_id") or "")[:8]


def _enc(s: str) -> str:
    """Percent-encoding as JavaScript's encodeURIComponent does it, so both plugins build the same links."""
    return quote(s, safe="!*'()")


def issue_title(scan: dict[str, Any]) -> str:
    return _well(f"Wrong scan: {_text(scan.get('tool') or '?', 60)} ({short_id(scan)})")


def _issue_url(scan: dict[str, Any], body: str | None) -> str:
    h = host_of(scan)
    url = f"{WRONG_SCAN_ISSUE_URL}&title={_enc(issue_title(scan))}"
    if body is not None:
        url += f"&report={_enc(body)}"
    host = f"{h['platform']} {h['platform_version']}"
    return url + f"&host={_enc(host)}&version={_enc(h['plugin_version'])}"


def github_link(scan: dict[str, Any], resolution: dict[str, Any] | None) -> tuple[str, str]:
    """The issue form link with the summary filled in, and how it was fitted: "" (whole), "trimmed" (entity
    lines cut from the end) or "blank" (no report: the owner pastes the summary)."""
    lines = [BEGIN, *summary_lines(scan, resolution), END]
    url = _issue_url(scan, "\n".join(lines))
    if len(url) <= URL_MAX:
        return url, ""
    entity_at = [i for i, line in enumerate(lines) if _ENTITY.match(line)]
    for cut in range(1, len(entity_at) + 1):
        dropped = set(entity_at[-cut:])
        kept = [line for i, line in enumerate(lines) if i not in dropped]
        kept.insert(entity_at[-cut], f"  (trimmed, {cut} more)")
        url = _issue_url(scan, "\n".join(kept))
        if len(url) <= URL_MAX:
            return url, "trimmed"
    return _issue_url(scan, None), "blank"


def email_subject(scan: dict[str, Any]) -> str:
    return _well(f"Sentrook wrong scan {short_id(scan)}")


def file_id(scan: dict[str, Any]) -> str:
    """The short id as a file name part: letters, digits and dashes only, whatever the log holds."""
    return _FILE_ID.sub("_", short_id(scan)) or "scan"


def mailto(scan: dict[str, Any]) -> str:
    """A mail link with a subject and a short note only: the record itself is pasted or attached, never put in
    the link."""
    return f"mailto:{SUPPORT_EMAIL}?subject={_enc(email_subject(scan))}&body={_enc(EMAIL_BODY)}"


def parse_args(rest: str) -> tuple[str, str] | None:
    """`report [request_id|last] [--full|--github|--save]`: (ref, flag); None when malformed."""
    words = rest.split()
    flags = [w.lower() for w in words if w.startswith("-")]
    refs = [w for w in words if not w.startswith("-")]
    if len(flags) > 1 or len(refs) > 1 or any(f not in _FLAGS for f in flags):
        return None
    return (refs[0] if refs else "", flags[0] if flags else "")


def save(state_dir: Path, found: Found, now: datetime | None = None) -> Path:
    """Writes the summary and full record to `<state_dir>/reports/`, readable by the owner only."""
    now = now or datetime.now(UTC)
    folder = state_dir / "reports"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / f"sentrook-report-{file_id(found.scan)}-{now.strftime('%Y%m%dT%H%M%SZ')}.txt"
    text = (
        "\n\n".join((summary(found.scan, found.resolution), FULL_WARNING, full_record(found)))
        + "\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)  # an existing file keeps its mode on open
    return path


def model(found: Found, cmd: Any) -> dict[str, Any]:
    """The dashboard's report panel for one scan. It never holds the full record: the dashboard is not limited to
    the owner on every host, so the panel gives the owner's commands that print or save it instead."""
    url, fitted = github_link(found.scan, found.resolution)
    sid = short_id(found.scan)
    return {
        "id": found.scan.get("request_id"),
        "summary": summary(found.scan, found.resolution),
        "full_warning": FULL_WARNING,
        "full_commands": [f"{cmd('report')} {sid} --save", f"{cmd('report')} {sid} --full"],
        "github": url,
        "github_fit": fitted,
        "email": SUPPORT_EMAIL,
        "subject": email_subject(found.scan),
        "mailto": mailto(found.scan),
    }


def reply(found: Found, flag: str, cmd: Any, state_dir: Path) -> str:
    """The command's reply; `cmd(verb)` is how the owner types a subcommand on this host."""
    sid = short_id(found.scan)
    text = summary(found.scan, found.resolution)
    if flag == "--full":
        return "\n\n".join((text, FULL_WARNING, full_record(found)))
    if flag == "--save":
        path = save(state_dir, found)
        return "\n".join(
            (
                f"Wrote the report with its full record to {path} (readable by you only).",
                f"Read it, remove anything private, then email it to {SUPPORT_EMAIL} with the subject "
                f'"{email_subject(found.scan)}".',
                "Email is not end-to-end encrypted; Sentrook keeps emailed records for up to 30 days, then "
                "deletes them.",
            )
        )
    if flag == "--github":
        url, fitted = github_link(found.scan, found.resolution)
        note = {
            "": "The issue form opens with this summary filled in.",
            "trimmed": "The issue form opens with this summary filled in, some entity lines cut to fit the link.",
            "blank": "The summary is too long for a link: paste it into the issue form yourself.",
        }[fitted]
        return "\n".join(
            (
                text,
                "",
                f"{note} The issue is public: read the summary first and remove anything private.",
                url,
                "The full record is not in the issue. To send it privately: "
                f"{cmd('report')} {sid} --save, then email the file to {SUPPORT_EMAIL}.",
            )
        )
    return "\n".join(
        (
            text,
            "",
            "Fill in the last two lines, then send it to us:",
            "  colleagues: copy it into Discord or chat, with the full record if asked "
            f"({cmd('report')} {sid} --full)",
            f"  public GitHub issue (summary only): {cmd('report')} {sid} --github",
            f"  full record, privately by email: {cmd('report')} {sid} --save, then email the file to "
            f"{SUPPORT_EMAIL}",
        )
    )
