"""
Authenticated scanning (FRS Section 29).

Applies a scan's auth profile to the httpx client used for crawling and
active testing, so scans can reach content behind a login. Supports the
three methods the FRS lists as in-scope for Release 1: bearer tokens,
pre-obtained session cookies, and form-based login performed once at
scan start.
"""

from __future__ import annotations

import httpx

from app.platform import get_logger
from app.platform.errors.exceptions import ValidationException

logger = get_logger(__name__)

_LOGIN_TIMEOUT = 15.0


async def apply_authentication(client: httpx.AsyncClient, auth_config: dict | None) -> None:
    """
    Mutates `client` in place (headers/cookies) so subsequent requests
    on this client carry the authenticated session.
    """

    if not auth_config or auth_config.get("type") in (None, "none"):
        return

    auth_type = auth_config["type"]

    if auth_type == "bearer":
        token = auth_config.get("bearer_token")
        if not token:
            raise ValidationException("bearer_token is required for bearer authentication.")
        client.headers["Authorization"] = f"Bearer {token}"
        return

    if auth_type == "cookie":
        cookies = auth_config.get("cookies") or {}
        if not cookies:
            raise ValidationException("cookies is required for cookie authentication.")
        for name, value in cookies.items():
            client.cookies.set(name, value)
        return

    if auth_type == "form":
        login_url = auth_config.get("login_url")
        username_field = auth_config.get("username_field")
        password_field = auth_config.get("password_field")

        if not (login_url and username_field and password_field):
            raise ValidationException(
                "login_url, username_field, and password_field are required "
                "for form authentication."
            )

        payload = {
            username_field: auth_config.get("username", ""),
            password_field: auth_config.get("password", ""),
            **(auth_config.get("extra_fields") or {}),
        }

        try:
            response = await client.post(
                login_url, data=payload, timeout=_LOGIN_TIMEOUT, follow_redirects=True
            )
        except httpx.HTTPError as exc:
            raise ValidationException(f"Login request to {login_url} failed: {exc}") from exc

        if response.status_code >= 400:
            raise ValidationException(
                f"Login request to {login_url} returned HTTP {response.status_code}."
            )

        # Session cookies set by the login response are already captured
        # in client.cookies (httpx persists Set-Cookie automatically for
        # requests made on the same client instance), so subsequent
        # crawl/active-test requests on this client are authenticated.
        logger.info("Form login to %s completed with status %s", login_url, response.status_code)
        return

    raise ValidationException(f"Unsupported authentication type: {auth_type}")
