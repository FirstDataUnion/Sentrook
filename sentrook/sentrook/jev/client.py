"""Decisions API client (OpenRouter `POST /api/alpha/decisions`), the one way Sentrook talks to Jev.

One configurable base URL (`SENTROOK_JEV_BASE_URL`): in the TestNest loop the runner's caching proxy sits
there and replays or records every answer; Sentrook has no other cache awareness. Requests carry
`provider: {zdr: true, allow_fallbacks: false}` (zero data retention, no provider fallback) and retry with backoff on 429 and
5xx. Over the 32k context limit the API returns a hard `400 max_tokens_exceeded`, surfaced as
`ApiError.context_limit` so the probe records a coverage event instead of crashing.

`classify_failure` sorts a failed call (after its retries) into the outcome classes `/metrics` reports per route:
`provider_rejected` (a 4xx other than 429 and the context limit: the key, the credit or the account refused, which
does not heal on its own), `rate_limited` (429), `outage` (5xx, timeouts, connection errors), `context_limit` (the
request was too large, which says nothing about the provider) and `invalid` (an answer that is not the typed answer
the questions asked for). A second, OpenAI-compatible route lives in `secondary.py`; `routing.py` picks between them.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

DEFAULT_BASE_URL = "https://openrouter.ai"
DECISIONS_PATH = "/api/alpha/decisions"
DEFAULT_MODEL = "typesafe/jev-1.13"
CONTEXT_TOKENS = 32_000
PROVIDER_PREFS: dict[str, Any] = {"zdr": True, "allow_fallbacks": False}
REPEAT_HEADER = "X-TestNest-Repeat"
RETRY_STATUSES = frozenset({429, 499, 500, 502, 503, 524, 529})


class ApiError(Exception):
    def __init__(self, status: int | None, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body

    @property
    def context_limit(self) -> bool:
        return self.status == 400 and "max_tokens_exceeded" in self.body

    @property
    def timeout(self) -> bool:
        return self.status is None and "timeout" in self.body.lower()


class InvalidAnswer(ApiError):
    """A route answered, but not with the typed answer the questions asked for."""

    def __init__(self, body: str):
        super().__init__(None, body)

    @property
    def timeout(self) -> bool:
        return False


OK = "ok"
PROVIDER_REJECTED = "provider_rejected"
RATE_LIMITED = "rate_limited"
OUTAGE = "outage"
CONTEXT_LIMIT = "context_limit"
INVALID = "invalid"
#: Every outcome of one routed call, for metric label initialisation.
OUTCOMES = (OK, PROVIDER_REJECTED, RATE_LIMITED, OUTAGE, CONTEXT_LIMIT, INVALID)


def classify_failure(exc: Exception) -> str:
    """The outcome class of a failed call: see the module docstring. Anything that is not an `ApiError` (a 2xx
    whose body is not JSON, say) is `invalid`."""
    if isinstance(exc, InvalidAnswer) or not isinstance(exc, ApiError):
        return INVALID
    if exc.status is None or exc.status >= 500 or exc.status == 499:
        return OUTAGE
    if exc.status == 429:
        return RATE_LIMITED
    if exc.context_limit:
        return CONTEXT_LIMIT
    if 400 <= exc.status < 500:
        return PROVIDER_REJECTED
    return OUTAGE


@dataclass
class DecisionResult:
    response: dict[str, Any]
    latency_ms: float
    cache_hit: bool | None = None  # from the proxy's X-TestNest-Cache header when present

    @property
    def answers(self) -> dict[str, Any]:
        return self.response.get("answers") or {}

    @property
    def usage(self) -> dict[str, Any]:
        return self.response.get("usage") or {}

    @property
    def model(self) -> str | None:
        return self.response.get("model")

    #: Which route answered, set by `RoutedDecider` only when a second route is configured.
    route: str | None = None


class Decider(Protocol):
    """Anything that answers a Decisions API body. `repeat` (1-based) selects the cached sample under
    the TestNest proxy's fill/replay modes; live clients ignore it."""

    def decide(self, body: dict[str, Any], *, repeat: int | None = None) -> DecisionResult: ...


@dataclass
class JevConfig:
    base_url: str = DEFAULT_BASE_URL
    api_key: str | None = None
    model: str = DEFAULT_MODEL
    timeout_s: float = 20.0
    retries: int = 3
    provider: dict[str, Any] = field(default_factory=lambda: dict(PROVIDER_PREFS))
    exposure_question_set: str = "exposure-v1"
    call_question_set: str = "call-v1"
    #: The call question set for declared self-edits; None sends them to `call_question_set`.
    selfedit_question_set: str | None = None
    #: Exposure above this sets the `tainted` session flag.
    taint_threshold: float = 0.5


def post_with_retries(
    http: httpx.Client, path: str, data: bytes, headers: dict[str, str], retries: int
) -> tuple[httpx.Response, float]:
    """POST with retry and backoff on `RETRY_STATUSES`, timeouts and connection errors; returns the 2xx response
    and its latency in ms, or raises the last `ApiError`."""
    last: ApiError | None = None
    for attempt in range(max(1, retries)):
        t0 = time.perf_counter()
        try:
            r = http.post(path, content=data, headers=headers)
        except httpx.TimeoutException as e:
            last = ApiError(None, f"timeout: {e!r}")
        except httpx.HTTPError as e:
            last = ApiError(None, repr(e))
        else:
            latency = (time.perf_counter() - t0) * 1000
            if r.status_code < 300:
                return r, latency
            last = ApiError(r.status_code, r.text)
            if r.status_code not in RETRY_STATUSES:
                raise last
        if attempt < retries - 1:
            time.sleep(min(10.0, 0.5 * 2**attempt + random.random() * 0.25))
    assert last is not None
    raise last


class DecisionsClient:
    """Live HTTP client with retry and backoff."""

    def __init__(self, config: JevConfig):
        self.config = config
        headers = {"Content-Type": "application/json", "X-Title": "Sentrook"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        self._http = httpx.Client(
            base_url=config.base_url.rstrip("/"), headers=headers, timeout=config.timeout_s
        )

    def decide(self, body: dict[str, Any], *, repeat: int | None = None) -> DecisionResult:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {REPEAT_HEADER: str(repeat)} if repeat else {}
        r, latency = post_with_retries(
            self._http, DECISIONS_PATH, data, headers, self.config.retries
        )
        cache = r.headers.get("X-TestNest-Cache")
        return DecisionResult(
            r.json(), latency, cache_hit=None if cache is None else cache == "hit"
        )

    def close(self) -> None:
        self._http.close()
