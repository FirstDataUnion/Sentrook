"""The signed state token.

Sentrook stays stateless: it returns a signed token holding the session flags, a bounded set of hashed
untrusted entities, a smaller bounded set of hashed steered hosts (named in content that tried to steer the
agent, `prepare.steering`), the hashing salt and the highest `input_seq` scanned so far. Four more bounded
sets bind the session judgements to what they are about:

- `sensitive`: files (and database tables) whose content a check judged sensitive, plus what the agent wrote
  from them. `sensitive_unbound` records that a sensitive read could not be tied to any of them (a bare
  basename, a secret typed into a command), so the session flag keeps its weight on every later send.
- `tainted`: what an injected result produced or came from (the file or table its call names), plus what
  the agent wrote from them.
- `trusted`: entities the owner's own configuration supplied (a scanned read of the agent's config files).
- `skill_named`: hosts in the untrusted set that only the agent's own installed skills named (a read of an installed
  skill, `prepare.own_store`), and no other content. A host other content names leaves it for good. Only the
  credential-home check reads it (`prepare.credential_home`); everything else still scores these hosts as untrusted.

- `kernel`: what earlier code-tool calls left in the conversation's interpreter that a later program could reach
  without binding it itself (a code tool may keep one interpreter per conversation): builtins rebound to
  something that reaches a network sink, and modules whose attributes were patched. `kernel_unknown` records
  that a call changed the interpreter in a way that cannot be listed (`exec`, `setattr`, `sys.modules`), or
  that the set overflowed: from then on no program is read as local (`prepare.code_reach`).

What the scanned call itself would add (`holds_sensitive` and the sensitive set from a sensitive read it makes, and
the files it writes from a sensitive or tainted file) is not applied when it is scanned: the plugin has not yet
decided whether the call runs. It is kept in `pending`, keyed to the call, and the next scan settles it from the
call's decision in its history (`settle_pending`): applied once the call ran, dropped when it never did.

A token without one of these sets (issued before it existed) reads as an empty one. The token is an HS256
JWT bound to its `session_ref` and the step it was issued at; it is accepted only when presented with
the same `session_ref` at `session.step − 1`, so an older token cannot be replayed to shed a flag.

An invalid, stale or missing token never rejects the request: it starts a fresh session with reduced
coverage, and the outcome is recorded in `SessionState.status` for the response's coverage signal.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

import jwt

from ..enums import SessionFlag
from ..oracle.client import fold_pypi_name

TOKEN_VERSION = 1
ALGORITHM = "HS256"
UNTRUSTED_CAP = 64
STEERED_CAP = 32
SENSITIVE_CAP = 32
TAINTED_CAP = 32
TRUSTED_CAP = 64
SKILL_NAMED_CAP = 32
KERNEL_CAP = 64
#: Calls whose own marks wait for their outcome; past it the oldest are dropped (they never showed as run).
PENDING_CAP = 8
HASH_HEX = 12
#: Seed prefix for a database table (`table:job_records`); everything else is guessed from its shape.
TABLE_PREFIX = "table:"


class TokenStatus(StrEnum):
    VALID = "valid"  # verified, bound to this session and step
    FIRST_STEP = "first_step"  # step 1, no token expected
    MISSING = "missing"  # null after step 1
    INVALID = "invalid"  # signature or format failure
    STALE = "stale"  # issued at a different step
    MISMATCH = "mismatch"  # a different session_ref
    SEEDED = "seeded"  # minted from a test-mode state_seed


#: History decisions after which the call ran, and after which it never did. A review nobody has answered yet
#: (`review_timed_out`, which is also how a held call is sent) is neither: it may still be approved.
RAN = frozenset({"allowed", "approved_by_user", "allowed_on_error"})
NOT_RUN = frozenset({"blocked", "denied_by_user", "blocked_on_error"})
WAITING = frozenset({"review_timed_out"})


@dataclass
class PendingMarks:
    """What one scanned call adds to the session once it has run."""

    #: The call, as `call_hash` keys it.
    call: str
    flags: set[SessionFlag] = field(default_factory=set)
    sensitive: list[str] = field(default_factory=list)
    sensitive_unbound: bool = False
    tainted: list[str] = field(default_factory=list)
    #: What the call leaves in a code tool's interpreter (`SessionState.kernel`).
    kernel: list[str] = field(default_factory=list)
    kernel_unknown: bool = False
    #: A later scan saw the call waiting for the owner: once it leaves the history it is dropped, not applied.
    waiting: bool = False

    def empty(self) -> bool:
        return not (
            self.flags
            or self.sensitive
            or self.sensitive_unbound
            or self.tainted
            or self.kernel
            or self.kernel_unknown
        )


@dataclass
class SessionState:
    salt: str
    flags: set[SessionFlag] = field(default_factory=set)
    untrusted: list[str] = field(default_factory=list)  # ordered hashes, oldest first
    #: Hosts named in steering content, ordered hashes, oldest first.
    steered: list[str] = field(default_factory=list)
    #: Files and tables judged sensitive, and what was written from them; ordered hashes, oldest first.
    sensitive: list[str] = field(default_factory=list)
    #: A sensitive read that could not be tied to a file or table.
    sensitive_unbound: bool = False
    #: Files and tables an injected result produced or came from, and what was written from them.
    tainted: list[str] = field(default_factory=list)
    #: Entities the owner's own configuration supplied.
    trusted: list[str] = field(default_factory=list)
    #: Untrusted hosts only the agent's installed skills named.
    skill_named: list[str] = field(default_factory=list)
    #: Names earlier code-tool calls left in the interpreter bound to a network sink, and patched modules.
    kernel: list[str] = field(default_factory=list)
    #: The interpreter was changed in a way that cannot be listed, or `kernel` overflowed its cap.
    kernel_unknown: bool = False
    #: Scanned calls whose own marks wait for their outcome, oldest first.
    pending: list[PendingMarks] = field(default_factory=list)
    max_input_seq: int | None = None
    deployment: str | None = None
    issued_step: int | None = None
    issued_at: datetime | None = None
    status: TokenStatus = TokenStatus.FIRST_STEP

    @property
    def fresh(self) -> bool:
        return self.status in (
            TokenStatus.MISSING,
            TokenStatus.INVALID,
            TokenStatus.STALE,
            TokenStatus.MISMATCH,
        )

    def has_untrusted(self, h: str) -> bool:
        return h in self.untrusted

    def add_untrusted(self, hashes: list[str]) -> None:
        for h in hashes:
            if h in self.untrusted:
                continue
            self.untrusted.append(h)
        if len(self.untrusted) > UNTRUSTED_CAP:
            del self.untrusted[: len(self.untrusted) - UNTRUSTED_CAP]

    def add_steered(self, hashes: list[str]) -> None:
        _add_capped(self.steered, hashes, STEERED_CAP)

    def add_sensitive(self, hashes: list[str]) -> None:
        _add_capped(self.sensitive, hashes, SENSITIVE_CAP)

    def add_tainted(self, hashes: list[str]) -> None:
        _add_capped(self.tainted, hashes, TAINTED_CAP)

    def add_trusted(self, hashes: list[str]) -> None:
        _add_capped(self.trusted, hashes, TRUSTED_CAP)

    def drop_trusted(self, hashes: list[str]) -> None:
        self.trusted[:] = [h for h in self.trusted if h not in set(hashes)]

    def add_skill_named(self, hashes: list[str]) -> None:
        _add_capped(self.skill_named, hashes, SKILL_NAMED_CAP)

    def drop_skill_named(self, hashes: list[str]) -> None:
        drop = set(hashes)
        self.skill_named[:] = [h for h in self.skill_named if h not in drop]

    def add_kernel(self, hashes: list[str]) -> None:
        """Track more interpreter names; past the cap nothing is dropped: the set is unknown from then on."""
        for h in hashes:
            if h not in self.kernel:
                self.kernel.append(h)
        if len(self.kernel) > KERNEL_CAP:
            self.kernel_unknown = True
            del self.kernel[KERNEL_CAP:]

    def kernel_marks(self) -> tuple[set[str], bool]:
        """The interpreter names tracked, counting calls still waiting for the owner (they may yet run)."""
        names = set(self.kernel)
        unknown = self.kernel_unknown
        for p in self.pending:
            names.update(p.kernel)
            unknown = unknown or p.kernel_unknown
        return names, unknown

    def add_pending(self, marks: PendingMarks) -> None:
        if marks.empty():
            return
        self.pending = [p for p in self.pending if p.call != marks.call] + [marks]
        if len(self.pending) > PENDING_CAP:
            # A dropped call may have run: what it left in the interpreter is no longer known.
            for p in self.pending[: len(self.pending) - PENDING_CAP]:
                if p.kernel or p.kernel_unknown:
                    self.kernel_unknown = True
            del self.pending[: len(self.pending) - PENDING_CAP]

    def apply(self, marks: PendingMarks) -> None:
        """The call ran: what it read and wrote joins the session."""
        self.flags |= marks.flags
        self.add_sensitive(marks.sensitive)
        self.sensitive_unbound = self.sensitive_unbound or marks.sensitive_unbound
        self.add_tainted(marks.tainted)
        self.add_kernel(marks.kernel)
        self.kernel_unknown = self.kernel_unknown or marks.kernel_unknown


def call_hash(salt: str, call_id: str) -> str:
    return entity_hash(salt, "call", call_id)


def settle_pending(
    state: SessionState,
    decisions: list[tuple[str, str]],
    ran: set[str] | frozenset[str] = frozenset(),
) -> None:
    """Settle the pending marks from the history this request sends (`(call_id, decision)`, oldest first) and the
    calls it shows ran whatever their decision (`ran`: an `ok` result, or a tool result in the request; a host can
    run a call a remembered answer approved without telling the plugin, so its decision stays a review): a call that
    ran is applied, one that never ran is dropped, one waiting for the owner stays pending. A call the history does
    not name, or with a decision the scanner does not know, is applied: nothing says it was stopped. A call that was
    seen waiting and has since left the history is dropped."""
    latest = {call_hash(state.salt, cid): d for cid, d in decisions}
    shown_run = {call_hash(state.salt, cid) for cid in ran}
    keep: list[PendingMarks] = []
    for marks in state.pending:
        decision = latest.get(marks.call)
        if marks.call in shown_run:
            state.apply(marks)
        elif decision in NOT_RUN or (decision is None and marks.waiting):
            continue
        elif decision in WAITING:
            marks.waiting = True
            keep.append(marks)
        else:
            state.apply(marks)
    state.pending = keep


def _add_capped(into: list[str], hashes: list[str], cap: int) -> None:
    """Append new hashes in order; past the cap the oldest go first."""
    for h in hashes:
        if h not in into:
            into.append(h)
    if len(into) > cap:
        del into[: len(into) - cap]


def new_salt(deterministic: str | None = None) -> str:
    return deterministic if deterministic else secrets.token_hex(8)


def entity_hash(salt: str, kind: str, value: str) -> str:
    return "h_" + hashlib.sha256(f"{salt}|{kind}|{value}".encode()).hexdigest()[:HASH_HEX]


def fresh_state(salt: str, status: TokenStatus, deployment: str | None = None) -> SessionState:
    """A new session state. Past the first step (a lost, stale or foreign token), what earlier code-tool calls
    left in the interpreter is not known, and it stays unknown for the rest of the session."""
    return SessionState(
        salt=salt,
        deployment=deployment,
        status=status,
        kernel_unknown=status is not TokenStatus.FIRST_STEP,
    )


def decode_state(
    token: str | None,
    *,
    key: str | bytes,
    session_ref: str,
    expected_step: int,
    deployment: str | None,
    deterministic_salt: str | None = None,
) -> SessionState:
    """Verify `token` for this request. Never raises; failures start a fresh session."""
    salt = new_salt(deterministic_salt)
    if token is None:
        status = TokenStatus.FIRST_STEP if expected_step == 0 else TokenStatus.MISSING
        return fresh_state(salt, status, deployment)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            options={"verify_exp": False, "require": ["sid", "step"]},
        )
    except jwt.PyJWTError:
        return fresh_state(salt, TokenStatus.INVALID, deployment)
    if claims.get("v") != TOKEN_VERSION or not isinstance(claims.get("step"), int):
        return fresh_state(salt, TokenStatus.INVALID, deployment)
    if claims.get("sid") != session_ref:
        return fresh_state(salt, TokenStatus.MISMATCH, deployment)
    if claims["step"] != expected_step:
        return fresh_state(salt, TokenStatus.STALE, deployment)
    flags = {
        SessionFlag(f)
        for f in claims.get("flags", [])
        if f in SessionFlag.__members__.values() or f in {m.value for m in SessionFlag}
    }
    issued = claims.get("iat")
    return SessionState(
        salt=str(claims.get("salt") or salt),
        flags=flags,
        untrusted=[str(h) for h in claims.get("unt", [])][-UNTRUSTED_CAP:],
        steered=[str(h) for h in claims.get("str", [])][-STEERED_CAP:],
        sensitive=[str(h) for h in claims.get("sen", [])][-SENSITIVE_CAP:],
        sensitive_unbound=claims.get("snu") is True,
        tainted=[str(h) for h in claims.get("tnt", [])][-TAINTED_CAP:],
        trusted=[str(h) for h in claims.get("tru", [])][-TRUSTED_CAP:],
        skill_named=[str(h) for h in claims.get("skn", [])][-SKILL_NAMED_CAP:],
        kernel=[str(h) for h in claims.get("krn", [])][:KERNEL_CAP],
        kernel_unknown=claims.get("kru") is True,
        pending=_decode_pending(claims.get("pnd")),
        max_input_seq=claims.get("seq"),
        deployment=claims.get("dep") or deployment,
        issued_step=claims["step"],
        issued_at=datetime.fromtimestamp(issued, tz=UTC)
        if isinstance(issued, int | float)
        else None,
        status=TokenStatus.VALID,
    )


def encode_state(
    state: SessionState, *, key: str | bytes, session_ref: str, step: int, clock: datetime
) -> str:
    claims = {
        "v": TOKEN_VERSION,
        "sid": session_ref,
        "step": step,
        "iat": int(clock.timestamp()),
        "dep": state.deployment,
        "flags": sorted(f.value for f in state.flags),
        "seq": state.max_input_seq,
        "salt": state.salt,
        "unt": list(state.untrusted[-UNTRUSTED_CAP:]),
        "str": list(state.steered[-STEERED_CAP:]),
        "sen": list(state.sensitive[-SENSITIVE_CAP:]),
        "snu": state.sensitive_unbound,
        "tnt": list(state.tainted[-TAINTED_CAP:]),
        "tru": list(state.trusted[-TRUSTED_CAP:]),
        "skn": list(state.skill_named[-SKILL_NAMED_CAP:]),
        "krn": list(state.kernel[:KERNEL_CAP]),
        "kru": state.kernel_unknown,
        "pnd": [_encode_pending(p) for p in state.pending[-PENDING_CAP:]],
    }
    return jwt.encode(claims, key, algorithm=ALGORITHM)


def _encode_pending(marks: PendingMarks) -> dict:
    out: dict = {"c": marks.call}
    if marks.flags:
        out["f"] = sorted(f.value for f in marks.flags)
    if marks.sensitive:
        out["sen"] = list(marks.sensitive[-SENSITIVE_CAP:])
    if marks.sensitive_unbound:
        out["snu"] = True
    if marks.tainted:
        out["tnt"] = list(marks.tainted[-TAINTED_CAP:])
    if marks.kernel:
        out["krn"] = list(marks.kernel[:KERNEL_CAP])
    if marks.kernel_unknown:
        out["kru"] = True
    if marks.waiting:
        out["w"] = True
    return out


def _decode_pending(raw: object) -> list[PendingMarks]:
    """The token's pending marks; an entry that does not parse is skipped."""
    if not isinstance(raw, list):
        return []
    known = {m.value for m in SessionFlag}
    out: list[PendingMarks] = []
    for entry in raw[-PENDING_CAP:]:
        if not isinstance(entry, dict) or not isinstance(entry.get("c"), str):
            continue
        out.append(
            PendingMarks(
                call=entry["c"],
                flags={SessionFlag(f) for f in _strings(entry.get("f")) if f in known},
                sensitive=_strings(entry.get("sen"))[-SENSITIVE_CAP:],
                sensitive_unbound=entry.get("snu") is True,
                tainted=_strings(entry.get("tnt"))[-TAINTED_CAP:],
                kernel=_strings(entry.get("krn"))[:KERNEL_CAP],
                kernel_unknown=entry.get("kru") is True,
                waiting=entry.get("w") is True,
            )
        )
    return out


def _strings(raw: object) -> list[str]:
    return [str(v) for v in raw] if isinstance(raw, list) else []


def seed_state(seed: dict, *, salt: str, deployment: str | None = None) -> SessionState:
    """Test mode: the plain-meaning `state_seed` from a TestNest case becomes a session state."""
    flags = {f for f in SessionFlag if seed.get(f.value)}
    state = SessionState(
        salt=salt,
        flags=flags,
        max_input_seq=seed.get("max_input_seq"),
        deployment=deployment,
        status=TokenStatus.SEEDED,
    )
    state.add_untrusted(_seed_hashes(seed.get("untrusted_entities"), salt))
    state.add_steered(_seed_hashes(seed.get("steered_entities"), salt))
    # Absent means empty: a seed that sets holds_sensitive without naming what it is about binds it to nothing.
    state.add_sensitive(_seed_hashes(seed.get("sensitive_entities"), salt))
    state.sensitive_unbound = seed.get("sensitive_unbound") is True
    state.add_tainted(_seed_hashes(seed.get("tainted_entities"), salt))
    state.add_trusted(_seed_hashes(seed.get("trusted_entities"), salt))
    state.add_skill_named(_seed_hashes(seed.get("skill_named_entities"), salt))
    return state


def _seed_hashes(values: list | None, salt: str) -> list[str]:
    hashes: list[str] = []
    for value in values or []:
        if str(value).startswith(TABLE_PREFIX):
            hashes.append(entity_hash(salt, "table", table_key(str(value)[len(TABLE_PREFIX) :])))
            continue
        kind = _guess_kind(str(value))
        hashes.append(entity_hash(salt, kind, _normalise_seed_value(kind, str(value))))
    return hashes


def table_key(name: str) -> str:
    """A database table as the token keys it: quotes dropped, lower case, the last dotted part
    (`public."Job_Records"` -> `job_records`)."""
    bare = (
        name.strip().strip(";").replace('"', "").replace("`", "").replace("[", "").replace("]", "")
    )
    return bare.rsplit(".", 1)[-1].lower()


def _guess_kind(value: str) -> str:
    if "@" in value and not value.startswith("@"):
        return "recipient"
    if value.startswith("/") or value.startswith("~"):
        return "path"
    if (
        ":" in value
        and value.split(":", 1)[0]
        in ("npm", "pypi", "docker", "crates", "gem", "go", "git+github.com")
        or value.startswith("git+")
    ):
        return "package"
    if "." in value and " " not in value and not value[0].isdigit():
        return "host"
    if value.replace(".", "").replace(":", "").isdigit():
        return "host"
    return "recipient"


def _normalise_seed_value(kind: str, value: str) -> str:
    if kind in ("host", "recipient") and "@" in value or kind == "host":
        return value.strip().lower()
    if kind == "package" and value.strip().startswith("pypi:"):
        return "pypi:" + fold_pypi_name(value.strip()[5:])  # as extraction folds it
    return value.strip()
