"""
Lightweight Discovery / Crawl Engine (FRS Part 2, Sections 24-28).

Performs a bounded, read-only breadth-first crawl of the target,
restricted to the same registrable host, honoring max depth, max page,
and (FRS Section 23) request-delay limits. Also catalogs forms
encountered along the way (FRS Section 26: "Extract forms") so the
attack surface can be inspected even for fields that weren't actively
tested.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

_HREF_PATTERN = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
_UNSUPPORTED_SCHEMES = ("mailto:", "javascript:", "tel:", "ftp:", "file:")

_FORM_BLOCK = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_ATTR = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
_METHOD_ATTR = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
_FIELD_NAME = re.compile(
    r'<(?:input|select|textarea)\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE
)


@dataclass(slots=True)
class DiscoveredForm:
    """
    A form found during crawl (FRS Section 26).
    """

    page_url: str
    action_url: str
    method: str
    fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CrawlResult:
    pages: list[tuple[str, httpx.Response, float]]
    forms: list[DiscoveredForm]


def _canonicalize(url: str) -> str:
    """
    Basic URL canonicalization (FRS Section 25): strip fragments and
    trailing slashes so equivalent URLs are not processed twice.
    """

    url, _ = urldefrag(url)
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return parsed._replace(path=path).geturl()


def _same_host(base: str, candidate: str) -> bool:
    return urlparse(base).netloc == urlparse(candidate).netloc


def _extract_links(base_url: str, html: str) -> set[str]:
    links: set[str] = set()

    for match in _HREF_PATTERN.finditer(html):
        raw = match.group(1).strip()

        if raw.lower().startswith(_UNSUPPORTED_SCHEMES):
            continue

        absolute = urljoin(base_url, raw)

        if absolute.startswith(("http://", "https://")):
            links.add(_canonicalize(absolute))

    return links


def _extract_forms(page_url: str, html: str) -> list[DiscoveredForm]:
    forms: list[DiscoveredForm] = []

    for attrs, body in _FORM_BLOCK.findall(html):
        action_match = _ACTION_ATTR.search(attrs)
        method_match = _METHOD_ATTR.search(attrs)

        action = urljoin(page_url, action_match.group(1)) if action_match else page_url
        method = (method_match.group(1) if method_match else "GET").upper()
        fields = list(dict.fromkeys(_FIELD_NAME.findall(body)))

        forms.append(
            DiscoveredForm(
                page_url=page_url, action_url=action, method=method, fields=fields
            )
        )

    return forms


async def crawl(
    client: httpx.AsyncClient,
    start_url: str,
    max_depth: int,
    max_pages: int,
    request_delay_ms: int = 0,
    enable_js_rendering: bool = False,
) -> CrawlResult:
    """
    Returns discovered pages and forms. `request_delay_ms` (FRS Section
    23: "Request Delay") throttles requests to be respectful of the
    target - applied between every crawl request.

    `enable_js_rendering`, if True, additionally renders the start URL
    in a headless browser (see js_rendering_service.py) to discover
    links a JS-driven single-page app would inject client-side, that a
    plain HTTP GET would never see. This runs once for the start URL
    only, to keep cost bounded, and is a no-op if Playwright isn't
    installed.
    """

    start_url = _canonicalize(start_url)

    queue: list[tuple[str, int]] = [(start_url, 0)]
    visited: set[str] = set()
    pages: list[tuple[str, httpx.Response, float]] = []
    forms: list[DiscoveredForm] = []
    js_rendering_attempted = False

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)

        if url in visited or depth > max_depth:
            continue

        visited.add(url)

        if request_delay_ms > 0 and pages:
            await asyncio.sleep(request_delay_ms / 1000)

        try:
            started = time.perf_counter()
            response = await client.get(url, timeout=10.0, follow_redirects=True)
            elapsed_ms = (time.perf_counter() - started) * 1000
        except httpx.HTTPError:
            continue

        pages.append((url, response, elapsed_ms))

        content_type = response.headers.get("content-type", "")

        if "text/html" in content_type:
            forms.extend(_extract_forms(url, response.text))

            if depth < max_depth:
                discovered_links = _extract_links(url, response.text)

                if enable_js_rendering and url == start_url and not js_rendering_attempted:
                    js_rendering_attempted = True
                    js_links = await _try_js_rendered_links(url)
                    if js_links:
                        discovered_links |= {
                            _canonicalize(link) for link in js_links
                        }

                for link in discovered_links:
                    if _same_host(start_url, link) and link not in visited:
                        queue.append((link, depth + 1))

    return CrawlResult(pages=pages, forms=forms)


async def _try_js_rendered_links(url: str) -> set[str] | None:
    """
    Isolated import so environments without Playwright installed never
    pay an import cost or risk an import error when JS rendering is
    disabled (the default).
    """

    from app.domains.scan.services.js_rendering_service import (
        discover_js_rendered_links,
    )

    return await discover_js_rendered_links(url)
