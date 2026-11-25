"""A credential used only with its own service: the credential-home check.

An agent that reads an API key from its env file and sends it, as the call's authorisation, only to the API host of
the service that issued it is using the key the way it is meant to be used. The same key sent anywhere else is the
attack. The entity library lists, on a provider's API host, the environment names of the credentials that service
issues (`credential_names` on a `known_good` host, which then vouches for nothing else; see `probes.oracle`). The check
holds, and the call's credential does not count as sensitive data sent, only when all of this is true:

- the pending call runs code or a command (an exec), not a message, upload or file tool;
- the call (with the file it runs and the pending command as a sibling's write resolves it) names at least one
  credential-shaped environment name (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, ...), and every one it names is listed by
  every off-machine party the call touches;
- every off-machine party the call or its batch touches, in any role, is a host the library lists with credential
  names (an exact library answer, never a near miss), so a URL to any other host in the code fails the check, and
  none of them reached the agent through content it read (a host only untrusted content named, or one it was
  steered to). A host that only the agent's own installed skills named (a read of an installed skill, on this step
  or an earlier one, and no other content) does not count as content here: the skill is the agent's standing
  instructions for the service, and the library already ties the key to that host. Memory reads do count, and
  everything else still scores such a host as untrusted;
- the call sends by no route whose destination need not be written as a host (`scp`, `nc`, `git push`, ...), in a
  shell command or named in code (`subprocess.run(['nc', ...])`, a raw socket), and builds no address at run time
  (`'https://' + h`, `f"https://{h}"`, `https://$HOST`): a host the code does not write out is not an entity;
- every sensitive file the call touches is a dotenv file (`.env`, `.env.local`, ...) that holds credentials, and
  none is sent whole (`curl -T ~/.env`, `-d @~/.env`, an attachment); no secret value is written in the call;
- the session's sensitive data that the call takes content from is only those env files; for a call with nothing
  to match (it sources the env file), everything the session judged sensitive is one of them (a sensitive read the
  scanner could not tie to a file fails the check);
- the credential is not also put somewhere else: no file write in a shell command (a redirect, `tee`, `cp`), no
  `echo`/`printf`/`printenv` of a credential name, and in code no write or print of the key, the env file or a
  variable assigned from either (`open(..., "w")`, `.write(`, `json.dump(`, `print(`, `shutil.copy(`, ...).

The owner can tie a key to a service the library does not list with a `credential` grant: `NAME@host`, the name
exact or a `PREFIX*` (three or more characters before the `*`), the host exact or `*.example.com` (that domain and
every name under it; at least two labels after the wildcard, and not a shared suffix such as `co.uk`, a common
shared-hosting suffix such as `github.io`, or an address written in numbers). A live grant whose host pattern covers a host adds its
name to the names that host lists, exactly as a library entry would; every other condition above still holds. A
grant never covers a host the oracle marks known-bad. A malformed or over-broad pattern covers nothing. Where a grant
supplied a name the call uses, the check records the grant on that host (`CredentialHome.grants`).

What it relieves is the convergence parameters' business (`credential_home`): with the check holding, the env
file's credential sensitivity and the sensitive-data-sent floor on it are not charged, the send scores as a plain
send, and the model's own sensitivity judgement is held to the level below credentials. Everything else about the
call (who asked, where its arguments came from, the model's doubt) is scored as before.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Any

from ..enums import SessionFlag
from ..planir.models import ToolKind
from .entities import EntityKind, Origin

#: An environment name shaped like a credential: words joined by `_` ending in a key, token, secret or password word.
CREDENTIAL_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_])("
    r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_?KEY|KEY|KEY_ID|TOKEN|SECRET|SECRET_KEY|PASSWORD|PASSWD|PASS|PAT"
    r"|AUTH|AUTH_TOKEN|CREDENTIALS?|ACCESS_KEY|ACCESS_KEY_ID|PRIVATE_KEY)"
    r")(?![A-Za-z0-9_])"
)

#: A dotenv file: `.env` or a per-environment sibling (`.env.local`, `.env.production`).
_DOTENV_RE = re.compile(r"\.env(?:\.[A-Za-z0-9_-]+)*")
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

#: Shell heads that print their arguments where the agent reads them.
_DISPLAY_HEADS = frozenset({"echo", "printf", "printenv"})
#: Redirect targets that keep nothing.
_NULL_TARGETS = ("/dev/null", "/dev/stdout", "/dev/stderr")

#: Code that writes or prints its arguments: a line naming the key there puts it somewhere else.
_CODE_SINK_RE = re.compile(
    r"\b(?:print|pprint|console\.(?:log|error|info|warn)|sys\.std(?:out|err)\.write"
    r"|json\.dump|pickle\.dump|yaml\.(?:safe_)?dump|shutil\.(?:copy\w*|move)|os\.(?:rename|replace|symlink)"
    r"|(?:write|append)File(?:Sync)?|createWriteStream)\s*\("
    r"|\.write(?:_text|_bytes|lines)?\s*\("
    r"|\bopen\s*\([^)]*,\s*(?:mode\s*=\s*)?[rf]?['\"][^'\"]*[wax+]"
)
#: A name assigned on a line (`k = ...`, `env['k'] = ...`, `key: str = ...`), not a comparison or keyword argument.
_ASSIGNED_RE = re.compile(
    r"(?<![\w.'\"\])])([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\]\s*)?(?::\s*[\w\[\], .]+)?=(?!=)"
)


@dataclass(frozen=True)
class CredentialHome:
    """The check held: the credential names the call uses, the hosts they go to and the env files they come from."""

    names: tuple[str, ...]
    #: Entity ids of the provider hosts.
    hosts: tuple[str, ...]
    #: Entity ids of the env files the call reads them from (empty when the key comes from the environment).
    env_files: tuple[str, ...]
    #: Normalised paths of those files.
    env_paths: tuple[str, ...]
    #: `(host entity id, grant_ref)`: the owner's `credential` grant that supplied a name the call uses for that host.
    grants: tuple[tuple[str, str], ...] = ()

    def evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "names": list(self.names),
            "hosts": list(self.hosts),
            "env_files": list(self.env_files),
        }
        if self.grants:
            out["grants"] = [list(g) for g in self.grants]
        return out


#: The grant kind that ties a credential name to its host(s).
GRANT_KIND = "credential"
_GRANT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\*?")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_GRANT_HOST_RE = re.compile(rf"(?:\*\.)?{_LABEL}(?:\.{_LABEL})+")
#: Characters a name prefix needs before its `*`.
_MIN_PREFIX = 3


#: Second-level labels under which a two-letter country domain is shared by many owners (`co.uk`, `com.au`, `ne.jp`):
#: a wildcard there covers strangers.
_SHARED_SECOND_LEVEL = frozenset(
    {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or", "go", "ed", "lg", "gr"}
)
#: Common shared-hosting and shared-registration suffixes, where anyone can get a name of their own
#: (`someone.github.io`): a wildcard on one of these, or on a domain above one (`*.amazonaws.com`), covers strangers.
#: Not every such suffix: the most common ones. The plugins keep the same list less the tunnel services, which they
#: leave to the scanner.
SHARED_HOSTING = frozenset(
    {
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "workers.dev",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "azurewebsites.net",
        "cloudfront.net",
        "s3.amazonaws.com",
        "blob.core.windows.net",
        "onrender.com",
        "fly.dev",
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "glitch.me",
        "replit.dev",
        "repl.co",
        "blogspot.com",
        "wordpress.com",
        "myshopify.com",
        "trycloudflare.com",
        "supabase.co",
        "deno.dev",
        "uk.com",
        "us.com",
        "eu.com",
    }
)


def _wildcard_too_broad(base: str) -> bool:
    labels = base.split(".")
    if all(label.isdigit() for label in labels):
        return True  # part of a numeric address: `*.113.9`
    if len(labels) == 2 and labels[0] in _SHARED_SECOND_LEVEL and len(labels[1]) == 2:
        return True
    if any(s == base or s.endswith("." + base) for s in SHARED_HOSTING):
        return True
    # an S3 endpoint in a region or another form (`s3.eu-west-1.amazonaws.com`, `s3-website-us-east-1.amazonaws.com`)
    return base.startswith(("s3.", "s3-")) and base.endswith(".amazonaws.com")


def host_pattern_ok(host: str) -> bool:
    """A host as a grant may name it (lower-cased, no scheme, port or path): exact, or `*.` and one registrable domain,
    with at least two labels after the wildcard and not a shared suffix such as `co.uk`, a common shared-hosting suffix
    such as `github.io` (`SHARED_HOSTING`) or an address written in numbers. Destination grants read a wildcard host
    the same way."""
    if not _GRANT_HOST_RE.fullmatch(host):
        return False
    return not (host.startswith("*.") and _wildcard_too_broad(host[2:]))


def parse_credential_pattern(pattern: str) -> tuple[str, str] | None:
    """A `credential` grant's pattern as `(name pattern, host pattern)`, or None when it is malformed or over-broad.
    `NAME@host`: the name exact or `PREFIX*` with at least three characters before the `*`; the host lower-cased,
    exact or `*.example.com`, with no scheme, port or path and at least two labels after a wildcard."""
    name, sep, host = str(pattern).strip().partition("@")
    host = host.strip().lower().rstrip(".")
    name = name.strip()
    if not sep or not _GRANT_NAME_RE.fullmatch(name) or not host_pattern_ok(host):
        return None
    if name.endswith("*") and len(name) - 1 < _MIN_PREFIX:
        return None
    return name, host


def host_covered(host_pattern: str, host: str) -> bool:
    """An exact host, or `*.example.com` for `example.com` and every name under it."""
    host = host.lower().rstrip(".")
    if host_pattern.startswith("*."):
        return host == host_pattern[2:] or host.endswith(host_pattern[1:])
    return host == host_pattern


def live_credential_grants(prepared: Any) -> list[tuple[str, str, str]]:
    """`(grant_ref, name pattern, host pattern)` for each `credential` grant live in this request (scope, expiry)
    whose pattern parses."""
    from .grants import lapse

    planir = prepared.planir
    out: list[tuple[str, str, str]] = []
    for g in planir.grants:
        if g.kind.lower() != GRANT_KIND or lapse(g, planir) is not None:
            continue
        parsed = parse_credential_pattern(g.pattern)
        if parsed is not None:
            out.append((g.grant_ref, *parsed))
    return out


def is_dotenv(path: str) -> bool:
    base = posixpath.basename(path.rstrip("/"))
    if not _DOTENV_RE.fullmatch(base) and not base.endswith(".env"):
        return False
    return not base.lower().endswith(_TEMPLATE_SUFFIXES)


def accepts(listed: list[str] | tuple[str, ...], name: str) -> bool:
    """`name` is one of the listed credential names, or starts with a listed `PREFIX*` pattern's prefix."""
    for pattern in listed:
        p = str(pattern)
        if p.endswith("*"):
            if name.startswith(p[:-1]):
                return True
        elif name == p:
            return True
    return False


def credential_names_in(text: str, listed: list[str] | tuple[str, ...] = ()) -> set[str]:
    """The credential-shaped environment names in `text`, plus any listed name it spells as a whole word."""
    found = set(CREDENTIAL_NAME_RE.findall(text))
    for name in listed:
        n = str(name)
        if n.endswith("*"):
            found.update(
                re.findall(
                    r"(?<![A-Za-z0-9_])(" + re.escape(n[:-1]) + r"[A-Z0-9_]*)(?![A-Za-z0-9_])", text
                )
            )
        elif re.search(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", text):
            found.add(n)
    return found


#: A string literal in code (Python, JavaScript), with an optional prefix (`f`, `r`, `b`).
_CODE_STRING_RE = re.compile(r"""(?<![\w])[rRbBuUfF]{0,2}(['"`])((?:\\.|(?!\1)[^\\\n])*)\1""")
#: Code that opens a connection itself: its destination need not be written as a host.
_RAW_SOCKET_RE = re.compile(
    r"\bsocket\s*\.\s*(?:socket|create_connection)\s*\(|\bnet\s*\.\s*(?:connect|createConnection|Socket)\b"
    r"|\btls\s*\.\s*connect\s*\(|\bdgram\b"
)
#: An address whose host is filled in at run time: a scheme followed by a quote, a placeholder or a variable.
_BUILT_ADDRESS_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://(?:['\"`]|\{|%[sr(]|\$)", re.IGNORECASE)


#: Send heads that are also scheme names, so a one-word literal of them is read as a word.
_SCHEME_WORDS = frozenset({"http", "https", "ftp", "sftp", "ssh", "telnet"})


def _code_sends_by_unwritten_route(code: str) -> bool:
    """Code that runs a send tool whose destination need not be written as a host (`subprocess.run(['nc', ...])`,
    `os.system('scp ...')`), or opens a socket itself."""
    from .grants import _SEND_HEADS, sends_by_unwritten_route

    if _RAW_SOCKET_RE.search(code):
        return True
    words: set[str] = set()
    for m in _CODE_STRING_RE.finditer(code):
        text = m.group(2).strip()
        if not text:
            continue
        tokens = text.split()
        head = posixpath.basename(tokens[0]).lower()
        if len(tokens) == 1 and head in _SCHEME_WORDS:
            words.add(head)
            continue  # `scheme == 'https'`: a word, not HTTPie run with no arguments
        if head in _SEND_HEADS or sends_by_unwritten_route(text):
            return True
        words.add(head)
    return ("git" in words and "push" in words) or ("aws" in words and "s3" in words)


def _code_puts_key_elsewhere(code: str, anchors: set[str]) -> bool:
    """In code, a line that writes or prints and names the key's environment name, the env file, or a variable a
    line naming either assigned."""
    lines = code.splitlines()
    # whole names only: the env file `.env` is not the `.env` in `os.environ`
    marks = [re.compile(r"(?<![\w])" + re.escape(a) + r"(?![\w])") for a in sorted(anchors)]
    anchored = [ln for ln in lines if any(m.search(ln) for m in marks)]
    tainted = {m for ln in anchored for m in _ASSIGNED_RE.findall(ln)} - anchors
    words = [re.compile(r"(?<![\w.])" + re.escape(v) + r"(?!\w)") for v in sorted(tainted)]
    for ln in lines:
        if not _CODE_SINK_RE.search(ln):
            continue
        if any(m.search(ln) for m in marks) or any(w.search(ln) for w in words):
            return True
    return False


def _shell_puts_key_elsewhere(a: Any, ctx: Any, names: set[str]) -> bool:
    """In a shell command, any file the command writes (a redirect, `tee`, `cp`, ...), or a display of a credential
    name."""
    from ..aira.detectors import _written_paths

    for ref, _mechanism in _written_paths(a, ctx):
        if not ref.value.startswith(_NULL_TARGETS):
            return True
    shape = a.shape
    if shape is None:
        return False
    for seg in shape.segments:
        if seg.head in _DISPLAY_HEADS and names & credential_names_in(
            " ".join(seg.argv), tuple(names)
        ):
            return True
    return False


def check(
    prepared: Any, extra_grants: tuple[tuple[str, str, str], ...] = ()
) -> tuple[CredentialHome | None, str]:
    """`(home, "ok")` when the check holds, else `(None, why)`. Reads the oracle's answers on `prepared`, so it runs
    after the oracle probe. `extra_grants`: `(grant_ref, name pattern, host pattern)` read as if they were live
    `credential` grants (unparsed: the grant hint passes `*` to learn which names a host would need). Never raises
    for a malformed call: anything it cannot read fails the check."""
    try:
        return _check(prepared, extra_grants)
    except Exception as e:  # noqa: BLE001 (a failed check relieves nothing)
        return None, f"error:{type(e).__name__}"


def _check(
    prepared: Any, extra_grants: tuple[tuple[str, str, str], ...] = ()
) -> tuple[CredentialHome | None, str]:
    from ..aira.analysis import analyse
    from ..aira.detectors import (
        PACK_TIER1,
        Context,
        _secret_in_call,
        _top_sensitive_group,
    )
    from ..aira.lists import load_lists
    from ..oracle.client import is_local_host
    from ..probes.aira import written_file_call
    from .grants import sends_by_unwritten_route

    pending = prepared.pending
    if pending.tool_kind is not ToolKind.EXEC or not pending.command:
        return None, "not_exec"
    lists = load_lists()
    ctx = Context(prepared=prepared, lists=lists, packs=frozenset({PACK_TIER1}))

    # Every off-machine party the call or its batch touches is a host the library lists with credential names, or one
    # the owner's credential grants tie names to.
    owner_grants = [*live_credential_grants(prepared), *extra_grants]
    hosts: dict[str, list[str]] = {}
    host_grants: dict[str, list[tuple[str, str]]] = {}
    for ent in prepared.entities:
        if ent.kind not in (EntityKind.HOST, EntityKind.RECIPIENT, EntityKind.CHANNEL):
            continue
        if not (
            ent.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE, Origin.SIBLING)
            or ent.in_resolved_command
        ):
            continue
        if ent.kind is EntityKind.HOST and is_local_host(ent.value):
            continue
        if ent.kind is not EntityKind.HOST:
            return None, "other_party"
        info = prepared.oracle_entities.get(ent.id) or {}
        listed = [str(n) for n in info.get("credential_names") or []]
        if info.get("verdict") != "known_bad":
            granted = [(ref, n) for ref, n, h in owner_grants if host_covered(h, ent.value)]
            if granted:
                host_grants[ent.id] = granted
                listed += [n for _, n in granted]
        if not listed:
            return None, "unlisted_host"
        if ent.steered or (
            (ent.in_session_untrusted or Origin.UNTRUSTED_INPUT in ent.origins)
            and not ent.skill_named
        ):
            return None, "host_from_content"
        hosts[ent.id] = listed
    if not hosts:
        return None, "no_host"

    calls = [pending, *prepared.resolved]
    written = written_file_call(prepared)
    if written is not None:
        calls.append(written)
    analyses = [analyse(c, prepared, lists) for c in calls]

    # a bare `*` (the grant hint's probe for which names a host would need) finds names by their shape only
    every_listed = tuple(n for listed in hosts.values() for n in listed if n != "*")
    names: set[str] = set()
    for a in analyses:
        names |= credential_names_in(a.call.command or a.text or "", every_listed)
    if not names:
        return None, "no_credential_name"
    for name in names:
        if not all(accepts(listed, name) for listed in hosts.values()):
            return None, "name_not_listed"

    env_ids: dict[str, str] = {}
    sent_whole = lists.patterns("egress", "file_arg_patterns")
    for a in analyses:
        if a.kind is ToolKind.EXEC and not a.inline_code:
            if sends_by_unwritten_route(a.call.command or ""):
                return None, "unwritten_route"
        if (a.inline_code or a.call.code_cell) and _code_sends_by_unwritten_route(
            a.call.command or ""
        ):
            return None, "unwritten_route"
        if _BUILT_ADDRESS_RE.search(a.call.command or a.text or ""):
            return None, "address_built_at_run_time"
        attached = {p.value for p in a.attachments}
        for p in a.paths:
            if _top_sensitive_group(p.groups) is None:
                continue
            if "credential_store" not in p.groups or not is_dotenv(p.value):
                return None, "other_sensitive_file"
            if p.value in attached:
                return None, "env_file_sent_whole"
            if p.entity_id:
                env_ids[p.entity_id] = p.value
        for g in a.text_groups:
            if _top_sensitive_group([g]) is not None and not any(g in p.groups for p in a.paths):
                return None, "unplaced_sensitive_mention"
        for rx in sent_whole:
            for m in rx.finditer(a.scan_text):
                target = m.group(m.lastindex or 0)
                if is_dotenv(target):
                    return None, "env_file_sent_whole"
        if _secret_in_call(a, ctx) is not None:
            return None, "secret_in_call"
        anchors = set(names) | {posixpath.basename(v) for v in env_ids.values()}
        if a.inline_code or a.call.code_cell:
            # A Code Mode cell is JavaScript too: its writes and prints are code, and the shell reading of it names
            # no written file. Its nested calls' command strings are still read as shell.
            if _code_puts_key_elsewhere(a.call.command or "", anchors) or (
                a.call.code_cell and _shell_puts_key_elsewhere(a, ctx, names)
            ):
                return None, "key_put_elsewhere"
        elif _shell_puts_key_elsewhere(a, ctx, names):
            return None, "key_put_elsewhere"

    # The session's sensitive data this call takes content from is only those env files.
    binding = prepared.session_binding.sensitive
    if binding.bound:
        if any(art.kind != "path" or not is_dotenv(art.value) for art in binding.matched):
            return None, "other_session_sensitive"
        for art in binding.matched:
            if art.entity_id:
                env_ids.setdefault(art.entity_id, art.value)
    elif SessionFlag.HOLDS_SENSITIVE in prepared.state.flags and (
        not binding.identifiable or prepared.state.sensitive_unbound
    ):
        # A call with nothing to match (it sources the env file, pipes a body) is fine when everything the session
        # judged sensitive is one of the env files it uses; a sensitive read never tied to a file fails.
        env_hashes = {
            ent.hash
            for eid in env_ids
            if (ent := prepared.entities.by_id(eid)) is not None and ent.hash
        }
        if prepared.state.sensitive_unbound or not set(prepared.state.sensitive) <= env_hashes:
            return None, "session_sensitive_unplaced"

    used: list[tuple[str, str]] = []
    for host_id, granted in sorted(host_grants.items()):
        ref = next((r for r, n in granted if any(accepts((n,), name) for name in names)), None)
        if ref is not None:
            used.append((host_id, ref))
    return (
        CredentialHome(
            names=tuple(sorted(names)),
            hosts=tuple(sorted(hosts)),
            env_files=tuple(sorted(env_ids)),
            env_paths=tuple(sorted(set(env_ids.values()))),
            grants=tuple(used),
        ),
        "ok",
    )
