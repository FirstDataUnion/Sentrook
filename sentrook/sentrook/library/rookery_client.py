from __future__ import annotations

from sentrook.library.oidc_client import get_access_token

ROOKERY_API_KEY_HEADER = "X-Rookery-API-Key"


def rookery_auth_headers(api_key: str | None = None) -> dict[str, str]:
    """Build auth headers for a Rookery request.

    An explicit ``api_key`` always wins (unchanged legacy behavior). When none
    is given, transparently falls back to a cached/refreshed FIDU ID OIDC
    access token from ``sentrook library login`` (or a client-credentials token
    when ``SENTROOK_ROOKERY_CI_CLIENT_SECRET`` is set), and finally to no auth at
    all — matching Rookery's hybrid API-key/OIDC model. All Rookery client
    call sites (library sync, library push, shadow feedback) route through
    this function, so they all gain OIDC support for free.
    """
    # Strip surrounding whitespace/newlines: a stray newline (e.g. from a pasted
    # key in an env var) yields an illegal "Bearer \n<key>" HTTP header value.
    key = api_key.strip() if api_key else ""
    if key:
        return {
            "Authorization": f"Bearer {key}",
            ROOKERY_API_KEY_HEADER: key,
        }

    token = get_access_token()
    if token:
        return {"Authorization": f"Bearer {token}"}

    return {}
