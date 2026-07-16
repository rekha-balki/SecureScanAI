"""
Parses a pasted curl command into a structured HTTP request.

Supports the flags people actually paste from browser DevTools /
Postman "copy as curl" exports: -X/--request, -H/--header, -d/--data
(+ --data-raw/--data-binary/--data-urlencode), -u/--user, -b/--cookie,
-A/--user-agent, -e/--referer, -G/--get, and a bare positional URL
(with or without --url). Anything unrecognized is ignored rather than
raising, since curl exports often include flags (--compressed,
-k/--insecure, --location) that don't affect how we build the request.
"""

from __future__ import annotations

import base64
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlencode

from app.platform.errors.exceptions import ValidationException

_IGNORED_NO_ARG_FLAGS = {
    "--compressed",
    "-k",
    "--insecure",
    "-L",
    "--location",
    "-s",
    "--silent",
    "-v",
    "--verbose",
    "-i",
    "--include",
}


@dataclass(slots=True)
class ParsedCurlRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None


def parse_curl(command: str) -> ParsedCurlRequest:
    command = command.strip()

    if not command:
        raise ValidationException("curl command is empty.")

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValidationException(f"Could not parse curl command: {exc}") from exc

    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    if not tokens:
        raise ValidationException("curl command has no arguments.")

    method: str | None = None
    headers: dict[str, str] = {}
    data_parts: list[str] = []
    cookie_parts: list[str] = []
    basic_auth: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    url: str | None = None
    is_get_with_data = False

    i = 0
    while i < len(tokens):
        token = tokens[i]

        def _next_value(flag: str) -> str:
            nonlocal i
            if i + 1 >= len(tokens):
                raise ValidationException(f"curl flag '{flag}' is missing its value.")
            i += 1
            return tokens[i]

        if token in ("-X", "--request"):
            method = _next_value(token).upper()
        elif token in ("-H", "--header"):
            header = _next_value(token)
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()
        elif token in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            data_parts.append(_next_value(token))
        elif token == "--data-urlencode":
            raw = _next_value(token)
            if "=" in raw:
                k, v = raw.split("=", 1)
                data_parts.append(urlencode({k: v}))
            else:
                data_parts.append(urlencode({raw: ""}))
        elif token in ("-u", "--user"):
            basic_auth = _next_value(token)
        elif token in ("-b", "--cookie"):
            cookie_parts.append(_next_value(token))
        elif token in ("-A", "--user-agent"):
            user_agent = _next_value(token)
        elif token in ("-e", "--referer"):
            referer = _next_value(token)
        elif token in ("-G", "--get"):
            is_get_with_data = True
        elif token == "--url":
            url = _next_value(token)
        elif token in _IGNORED_NO_ARG_FLAGS:
            pass
        elif token.startswith("-"):
            # Unrecognized flag - if it plausibly takes a value (not
            # itself another flag next), skip that value too so we
            # don't misinterpret it as the URL.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                i += 1
        else:
            if url is None:
                url = token

        i += 1

    if not url:
        raise ValidationException(
            "Could not find a URL in the curl command. Include the target "
            "URL directly or via --url."
        )

    body = "&".join(data_parts) if data_parts else None

    if is_get_with_data and body:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{body}"
        body = None
        if method is None:
            method = "GET"

    if method is None:
        method = "POST" if body else "GET"

    if basic_auth:
        encoded = base64.b64encode(basic_auth.encode("utf-8")).decode("ascii")
        headers.setdefault("Authorization", f"Basic {encoded}")

    if cookie_parts:
        headers.setdefault("Cookie", "; ".join(cookie_parts))

    if user_agent:
        headers.setdefault("User-Agent", user_agent)

    if referer:
        headers.setdefault("Referer", referer)

    return ParsedCurlRequest(method=method, url=url, headers=headers, body=body)
