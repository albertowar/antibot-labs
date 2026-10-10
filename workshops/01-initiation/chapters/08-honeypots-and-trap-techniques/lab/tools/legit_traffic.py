"""
Chapter 8 — Legitimate Traffic Simulator (Section 8.5)

Measures the other half of every trap: which REAL users it catches.

Five personas, each modelled on people (and one crawler) that real honeypots
hurt in production:

  mouse_shopper         sees the page, clicks each labelled field, types, submits.
                        The user every honeypot tutorial assumes.
  screenreader_shopper  moves with the Tab key and fills every field it lands
                        on, named by its label, the way a screen-reader user
                        hears and answers them. If your honeypot takes focus,
                        this user fills it.
  autofill_shopper      lets "the browser" fill the fields it recognises (email,
                        phone, ...) by name, label or autocomplete, then types a
                        username and password. Modelled on browser autofill and
                        password managers, which fill fields that are off-screen
                        but still focusable. They have also long ignored
                        autocomplete="off". Test your own browser too.
  search_crawler        a well-behaved search engine crawler: reads robots.txt,
                        obeys it, follows links in the raw HTML, never runs JS.
  cgnat_shopper         a normal customer behind a mobile carrier's CGNAT, so
                        it shares 203.0.113.77 with the Round 4 bot.

Every shopper signs up, then logs in. The cgnat_shopper also posts a review.
tools/checkpoint.py compares what each persona experienced with what the
server recorded for it (trap hits, blocks, dropped or quarantined signups,
suppressed reviews). Any of those is a false positive.

Trade-off: personas are models, not people. They catch the false positives we
know about. Your production logs will show you the ones we don't.

Run the demo site first, then:
    python tools/legit_traffic.py                       # all personas
    python tools/legit_traffic.py cgnat_shopper         # just one
"""

import os
import re
import sys
from collections import deque
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))

from _lab import BASE_URL, http_client, lab_headers, require_local, tag  # noqa: E402

PERSONAS = {
    "mouse_shopper": "198.51.100.10",
    "screenreader_shopper": "198.51.100.11",
    "autofill_shopper": "198.51.100.12",
    "search_crawler": "198.51.100.20",
    "cgnat_shopper": "203.0.113.77",
}
BROWSER_PERSONAS = {"mouse_shopper", "screenreader_shopper", "autofill_shopper", "cgnat_shopper"}
AUTOFILL_VOCAB = {"email": "email", "e-mail": "email", "phone": "phone", "tel": "phone",
                  "mobile": "phone", "website": "url", "url": "url", "company": "org"}


def profile(name):
    user = f"{name.split('_')[0]}-{tag(3)}"
    return {"username": user, "email": f"{user}@example.com", "password": f"Pw-{user}-2026",
            "phone": "+1 555 0100", "url": "https://example.com", "org": "Example Ltd"}


def login(page, me):
    page.goto(f"{BASE_URL}/login")
    page.get_by_label("Username").fill(me["username"])
    page.get_by_label("Password").fill(me["password"])
    page.click("form#signin button[type=submit]")
    return page.locator("#result").get_attribute("data-outcome") == "signed-in"


def mouse_shopper(page, me):
    page.goto(f"{BASE_URL}/")
    page.click("text=Create account")
    page.wait_for_timeout(700)                      # read the form
    for label in ("Username", "Email", "Password"):
        field = page.get_by_label(label, exact=True)
        field.click()
        field.press_sequentially(me[label.lower()], delay=35)
    page.click("form#signup button[type=submit]")


def screenreader_shopper(page, me):
    page.goto(f"{BASE_URL}/register")
    page.wait_for_timeout(1000)                     # listen to the page
    for _ in range(30):
        page.keyboard.press("Tab")
        el = page.evaluate("""() => {
            const e = document.activeElement;
            return {tag: e.tagName, type: e.type || "", inForm: !!e.closest("form#signup"),
                    label: e.labels && e.labels[0] ? e.labels[0].innerText : ""};
        }""")
        if not el["inForm"]:
            continue
        if el["tag"] == "BUTTON":
            page.keyboard.press("Enter")
            return
        label = el["label"].lower()
        if any(word in label for word in ("leave", "empty", "blank")):
            continue                                # the label told them not to
        key = next((k for k in ("username", "email", "password", "phone") if k in label), None)
        page.keyboard.type(me[key] if key else "n/a", delay=25)
    raise RuntimeError("never reached the submit button")


def autofill_shopper(page, me):
    page.goto(f"{BASE_URL}/register")
    page.wait_for_timeout(1000)
    # "Autofill": every field the browser recognises that has a layout box
    for field in page.locator("form#signup input").all():
        kind = field.get_attribute("type") or "text"
        if kind in ("hidden", "password", "submit") or not field.is_visible():
            continue
        fid = field.get_attribute("id") or ""
        label = page.locator(f'label[for="{fid}"]').all_inner_texts() if fid else []
        hints = " ".join([field.get_attribute("name") or "", fid,
                          field.get_attribute("autocomplete") or "", *label]).lower()
        key = next((v for k, v in AUTOFILL_VOCAB.items() if k in hints), None)
        if key:
            field.fill(me[key])
    # Then the user types what autofill doesn't know
    page.get_by_label("Username", exact=True).press_sequentially(me["username"], delay=30)
    page.get_by_label("Password", exact=True).press_sequentially(me["password"], delay=30)
    page.wait_for_timeout(300)
    page.click("form#signup button[type=submit]")


def cgnat_shopper(page, me):
    mouse_shopper(page, me)


def run_browser_persona(browser, name):
    me = profile(name)
    context = browser.new_context(extra_http_headers=lab_headers(name, PERSONAS[name]))
    context.set_default_timeout(5000)
    page = context.new_page()
    notes = []
    try:
        globals()[name](page, me)
        result = page.locator("#result").get_attribute("data-outcome")
        if result != "created":
            notes.append(f"signup page said {result!r}")
        if not login(page, me):
            notes.append("could not log in with the new account")
        elif name == "cgnat_shopper":
            page.goto(f"{BASE_URL}/products/3")
            page.get_by_label("Your review").fill("Warm feet all winter. Recommended.")
            page.click("form#review button[type=submit]")
    except Exception as exc:  # a persona that can't finish is a failure, not a crash
        if page.locator('#result[data-outcome="blocked"]').count():
            notes.append("blocked with a 403")
        else:
            notes.append(f"{type(exc).__name__}: {str(exc).splitlines()[0]}")
    finally:
        context.close()
    return {"persona": name, "notes": notes}


def search_crawler():
    """Obeys robots.txt, follows raw-HTML links two levels deep, no JS."""
    notes, pages = [], 0
    with http_client("search_crawler", PERSONAS["search_crawler"],
                     user_agent="WorkshopSearchBot/1.0 (+http://localhost/bot)") as client:
        robots = RobotFileParser()
        robots.parse(client.get("/robots.txt").text.splitlines())
        queue, seen = deque([("/", 0)]), {"/"}
        while queue and pages < 40:
            path, depth = queue.popleft()
            response = client.get(path)
            pages += 1
            if response.status_code == 403:
                notes.append(f"403 on {path}")
            if depth == 2 or "text/html" not in response.headers.get("content-type", ""):
                continue
            for href in re.findall(r'<a [^>]*href="([^"#]+)"', response.text):
                url = urlparse(urljoin(path, href))
                if url.netloc or url.path in seen or url.path.startswith(("/trap-", "/lab/")):
                    continue
                if robots.can_fetch("WorkshopSearchBot", url.path):
                    seen.add(url.path)
                    queue.append((url.path, depth + 1))
    return {"persona": "search_crawler", "notes": notes, "pages": pages}


FP_COUNTERS = ("blocked", "signup_trapped", "signup_quarantined", "review_suppressed",
               "review_dropped")


def problems(result, counters):
    """Everything that went wrong for one persona: its own notes plus the server's records."""
    harms = [f"{k}={counters[k]}" for k in FP_COUNTERS if counters.get(k)]
    traps = [f"trap:{k[5:]}×{v}" for k, v in counters.items() if k.startswith("trap:")]
    return result["notes"] + harms + traps


def run(names=None, skip_browser=False):
    """Run the personas. Returns one result per persona."""
    require_local()
    names = names or list(PERSONAS)
    results = []
    browser_names = [n for n in names if n in BROWSER_PERSONAS and not skip_browser]
    if browser_names:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            results += [run_browser_persona(browser, n) for n in browser_names]
            browser.close()
    if "search_crawler" in names:
        results.append(search_crawler())
    return results


if __name__ == "__main__":
    import json
    import urllib.request

    chosen = [a for a in sys.argv[1:] if a in PERSONAS] or None
    results = run(chosen)
    with urllib.request.urlopen(f"{BASE_URL}/lab/summary", timeout=5) as resp:
        actors = json.loads(resp.read())["actors"]
    print("=== Legitimate users ===")
    for r in results:
        found = problems(r, actors.get(r["persona"], {}))
        print(f"  {'❌' if found else '✅'} {r['persona']:<22} " + ("; ".join(found) or "ok"))
