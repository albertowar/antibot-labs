"""
Launching a browser for the lab agent.

Real agent tools come in two shapes. Developer frameworks (browser-use,
Playwright MCP) launch their own Chromium. Consumer agentic browsers and
Chrome DevTools MCP drive a Chromium the person is already using. Either way
the automation speaks the Chrome DevTools Protocol to a real Chromium: same
rendering engine, same GPU, same TLS stack as a human's browser. That is the
whole point of this chapter — the browser fingerprint is genuine.

For the lab we use Playwright's own launch(), because it is reproducible on
every student's machine and needs no second process. We pass a normal desktop
window size and a stock Chrome User-Agent so nothing in the fingerprint says
"automated"; the tells this chapter teaches are about behaviour and identity,
not the fingerprint. HEADLESS=1 (or no display) runs headless for CI.
"""

import contextlib

from playwright.sync_api import sync_playwright

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common

VIEWPORT = {"width": 1280, "height": 800}


@contextlib.contextmanager
def agent_browser(user_agent=None, headless=None):
    """Yield a Playwright page in a fresh context. One context = one 'agent session'."""
    headless = _common.headless() if headless is None else headless
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--disable-blink-features=AutomationControlled"])
        context = browser.new_context(viewport=VIEWPORT, user_agent=user_agent or _common.CHROME_UA,
                                      locale="en-US")
        page = context.new_page()
        try:
            yield context, page
        finally:
            with contextlib.suppress(Exception):
                context.close()
            with contextlib.suppress(Exception):
                browser.close()
