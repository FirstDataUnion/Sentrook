"""Decisions API client (OpenRouter `POST /api/alpha/decisions`), the one way Sentrook talks to Jev.

One configurable base URL (`SENTROOK_JEV_BASE_URL`): in the TestNest loop the runner's caching proxy sits
there and replays or records every answer; Sentrook has no other cache awareness. Requests carry
`provider: {zdr: true, allow_fallbacks: false}` (zero data retention, no provider fallback) and retry with backoff on 429 and
5xx. Over the 32k context limit the API returns a hard `400 max_tokens_exceeded`, surfaced as
`ApiError.context_limit` so the probe records a coverage event instead of crashing.
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
    #: Exposure above this sets the `tainted` session flag.
    taint_threshold: float = 0.5


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
        last: ApiError | None = None
        for attempt in range(max(1, self.config.retries)):
            t0 = time.perf_counter()
            try:
                r = self._http.post(DECISIONS_PATH, content=data, headers=headers)
            except httpx.TimeoutException as e:
                last = ApiError(None, f"timeout: {e!r}")
            except httpx.HTTPError as e:
                last = ApiError(None, repr(e))
            else:
                latency = (time.perf_counter() - t0) * 1000
                if r.status_code < 300:
                    cache = r.headers.get("X-TestNest-Cache")
                    return DecisionResult(
                        r.json(), latency, cache_hit=None if cache is None else cache == "hit"
                    )
                last = ApiError(r.status_code, r.text)
                if r.status_code not in RETRY_STATUSES:
                    raise last
            if attempt < self.config.retries - 1:
                time.sleep(min(10.0, 0.5 * 2**attempt + random.random() * 0.25))
        assert last is not None
        raise last

    def close(self) -> None:
        self._http.close()
