"""
Shared helpers for the Chapter 5 attack scripts.

Rules of engagement, enforced in code: every script reaches the store through
tools/labclient.py, which asks labnet.py at the lab root for DEMO_URL and refuses
anything that is not this machine. Browsers get the same guard
(labclient.browser_context aborts every non-local request). No script supports proxies:
the "residential" source addresses are rented from data/world.json, never real.

Every bot buys the shoe drop (/drop/lab-runner-9) once per run and reports what the
gate said, from the X-Lab-* headers the lab store adds to every response:

    reserved    the gate let it through (200 order confirmed, or 410 sold out after the gate)
    challenge   403, verdict "challenge" (in production: a CAPTCHA or PoW step-up)
    blocked     403, verdict "block"
    failed      the store sent the form back (invalid size or email): the bot's bug
"""

import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, LabClient, browser_context, world_pool  # noqa: E402,F401

DROP = "/drop/lab-runner-9"
FIELDS = ("name", "email", "size")
SELECTOR = {"name": "#name", "email": "#email", "size": "#size", "reserve": "#drop-buy"}

# Synthetic identities only.
NAMES = ["Ada Quill", "Bo Reyes", "Cy Novak", "Dee Okafor", "Eli Marsh", "Fay Lindqvist"]
SIZES = ["7", "8", "9", "10", "11", "12"]


def identity(rng=random):
    name = rng.choice(NAMES)
    user = name.lower().replace(" ", ".")
    return {"name": name, "email": f"{user}{rng.randint(1, 999)}@example.test", "size": rng.choice(SIZES)}


def bot_ip(rng=random):
    """A rented 'residential' exit (W1 Ch3 taught why the attacker pays for these)."""
    return rng.choice(world_pool("residential_proxy_net"))


def open_drop(playwright, actor, **context_kw):
    """Launch Chromium and open the drop page with the lab headers. Returns (browser, page)."""
    browser = playwright.chromium.launch()
    kw = {"viewport": {"width": 1280, "height": 720}}
    kw.update(context_kw)
    ctx = browser_context(browser, f"bot:{actor}", ip=bot_ip(), **kw)
    page = ctx.new_page()
    page.goto(BASE_URL + DROP)
    return browser, page


def box(page, field):
    return page.locator(SELECTOR[field]).bounding_box()


def outcome(status, verdict, signals="", confirmed=True):
    if verdict == "challenge":
        status_word = "challenge"
    elif verdict == "block" or status == 403:
        status_word = "blocked"
    elif status == 410 or (status == 200 and confirmed):
        status_word = "reserved"
    else:
        status_word = "failed"         # the form came back (a validation error): a bug in the bot, not a defense
    return {"status": status_word, "http": status, "verdict": verdict,
            "signals": [s for s in (signals or "").split(",") if s]}


def submit(page, click):
    """Run `click()` (which submits the form), wait for the page the store answers with."""
    with page.expect_navigation(timeout=20000) as nav:
        click()
    r = nav.value
    return outcome(r.status, r.headers.get("x-lab-verdict"), r.headers.get("x-lab-signals"),
                   confirmed="order-confirmed" in page.content())


def report(name, result):
    mark = {"reserved": "🟢", "challenge": "🟡", "blocked": "🔴"}.get(result["status"], "?")
    print(f"  {mark} {name:<28} {result['status']:<9} {result.get('http')}  {' '.join(result['signals'])}")


def finish(name, results):
    """The last line every attack prints: one JSON object for tools/checkpoint.py."""
    out = {"attack": name, "attempted": len(results),
           "succeeded": sum(r["status"] == "reserved" for r in results),
           "challenged": sum(r["status"] == "challenge" for r in results),
           "blocked": sum(r["status"] == "blocked" for r in results),
           "signals": sorted({s for r in results for s in r["signals"]})}
    print(json.dumps(out))
    return out


def sleep_ms(ms):
    time.sleep(max(0, ms) / 1000)
