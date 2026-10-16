"""The signed state token (skeleton 1.2, "State token"; build plan 6.8).

Sentrook stays stateless: it returns a signed token holding the session flags, a bounded set of hashed
untrusted entities, the hashing salt and the highest `input_seq` scanned so far. The token is an HS256
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

TOKEN_VERSION = 1
ALGORITHM = "HS256"
UNTRUSTED_CAP = 64
HASH_HEX = 12


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
    hashes: list[str] = []
    for value in seed.get("untrusted_entities") or []:
        kind = _guess_kind(str(value))
        hashes.append(entity_hash(salt, kind, _normalise_seed_value(kind, str(value))))
    state.add_untrusted(hashes)
    return state


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
    return value.strip()
