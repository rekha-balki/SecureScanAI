"""
Optional JS-rendered link discovery via a headless browser.

The plain httpx-based crawler in crawler_service.py sees only the raw
HTML a server returns - it never executes JavaScript, so single-page
apps and JS-injected navigation are invisible to it. This module closes
part of that gap using Playwright, but is intentionally scoped to link
discovery only (not full DOM-based vulnerability scanning, which would
need a much larger investment in JS instrumentation).

This is opt-in (CompanySettings.scanner_defaults.enable_js_rendering)
and degrades gracefully:
- If Playwright/its browser binaries aren't installed, this logs a
  warning once and the crawl proceeds with httpx-only results.
- Any runtime error rendering a specific page is caught and skipped;
  it never fails the scan.

Setup (not installed by default - see requirements.txt):
    pip install playwright
    playwright install chromium

NOTE: this module has not been exercised against a live browser in the
environment this codebase was authored in (no network access to install
browser binaries there). The Playwright API usage follows their
documented async pattern, but treat this as unverified until you've run
it once locally.
"""

from __future__ import annotations

from app.platform import get_logger

logger = get_logger(__name__)

_warned_missing_playwright = False
_RENDER_TIMEOUT_MS = 15000


async def discover_js_rendered_links(url: str) -> set[str] | None:
    """
    Loads `url` in headless Chromium, waits for the network to go
    idle, and returns the set of absolute href values present in the
    rendered DOM. Returns None if Playwright is unavailable or
    rendering failed - callers should treat that as "no additional
    links found" and continue with httpx-only results.
    """

    global _warned_missing_playwright

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        if not _warned_missing_playwright:
            logger.warning(
                "enable_js_rendering is on but Playwright is not installed. "
                "Run `pip install playwright && playwright install chromium` "
                "to enable JS-rendered link discovery. Falling back to "
                "HTTP-only crawling for this scan."
            )
            _warned_missing_playwright = True
        return None

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    user_agent="SecureScanAI/1.0 (+authorized-assessment; js-render)"
                )
                await page.goto(
                    url, wait_until="networkidle", timeout=_RENDER_TIMEOUT_MS
                )

                hrefs = await page.eval_on_selector_all(
                    "a[href]", "elements => elements.map(e => e.href)"
                )

                return {h for h in hrefs if h.startswith(("http://", "https://"))}
            finally:
                await browser.close()
    except Exception:  # noqa: BLE001 - never let a render failure break the scan
        logger.exception("JS rendering failed for %s; continuing without it", url)
        return None
