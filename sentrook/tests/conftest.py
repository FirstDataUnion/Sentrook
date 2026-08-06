"""Shared pytest fixtures for Sentrook tests."""

from __future__ import annotations

import pytest

from sentrook.config import L3Policy
from sentrook.library import oidc_client as oc

_REAL_FETCH_OIDC_DISCOVERY = oc.fetch_oidc_discovery


@pytest.fixture(autouse=True)
def stub_oidc_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(issuer: str) -> oc.OIDCDiscovery:
        base = issuer.rstrip("/")
        return oc.OIDCDiscovery(
            issuer=base,
            token_endpoint=f"{base}/oauth/token",
            device_authorization_endpoint=f"{base}/oauth/device/code",
        )

    monkeypatch.setattr(oc, "fetch_oidc_discovery", fake)


@pytest.fixture(autouse=True)
def offline_l3_unless_embed(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Use the deterministic KeywordScorer unless a test opts into real fastembed."""
    if request.node.get_closest_marker("l3_embed"):
        return

    from tests.helpers.l3_keyword_scorer import KeywordScorer

    scorer = KeywordScorer()

    def _make_scorer(config):
        if config.l3_policy == L3Policy.OFF:
            return None
        return scorer

    monkeypatch.setattr("sentrook.layers.l3_embed.make_scorer", _make_scorer)


@pytest.fixture
def real_oidc_discovery(monkeypatch: pytest.MonkeyPatch):
    """Restore the real OIDC discovery fetcher for one test."""
    monkeypatch.setattr(oc, "fetch_oidc_discovery", _REAL_FETCH_OIDC_DISCOVERY)
    oc._discovery_cache.clear()
    yield
    oc._discovery_cache.clear()
