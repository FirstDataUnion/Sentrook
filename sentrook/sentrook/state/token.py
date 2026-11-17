"""The signed state token.

Sentrook stays stateless: it returns a signed token holding the session flags, a bounded set of hashed
untrusted entities, a smaller bounded set of hashed steered hosts (named in content that tried to steer the
agent, `prepare.steering`), the hashing salt and the highest `input_seq` scanned so far. Three more bounded
sets bind the session judgements to what they are about:

- `sensitive`: files (and database tables) whose content a check judged sensitive, plus what the agent wrote
  from them. `sensitive_unbound` records that a sensitive read could not be tied to any of them (a bare
  basename, a secret typed into a command), so the session flag keeps its weight on every later send.
- `tainted`: what an injected result produced or came from (the file or table its call names), plus what
  the agent wrote from them.
- `trusted`: entities the owner's own configuration supplied (a scanned read of the agent's config files).

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
    return SessionState(salt=salt, deployment=deployment, status=status)


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
    }
    return jwt.encode(claims, key, algorithm=ALGORITHM)


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
