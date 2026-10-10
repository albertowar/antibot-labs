"""
Chapter 8 — Round 1 Attack, part b: Markup-Aware Spammer (Section 8.5)

Objective: beat the textbook honeypot without a browser. Before filling a
field, read the markup around it and skip anything that LOOKS hidden:

  - an inline style with display:none or visibility:hidden, on the input or
    on any element around it
  - the `hidden` attribute, or aria-hidden="true" on any ancestor
  - a name from the usual honeypot list (website, url, homepage, ...)

All of that is visible in the HTML, so the bot needs about 15 extra lines.
It still submits instantly, and it still can't see what CSS does.

Expected results:
  - level 1: every signup is created (the inline display:none gave it away)
  - level 2+: trapped. The honeypot is hidden by a class in store.css and has
    an opaque name, and the instant submit trips the timing token.
    Ask yourself: what would it take to beat level 2 without a browser?

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/round1b_markup_aware.py
"""

import re

from _lab import TEXT_TYPES, fill_value, http_client, outcome, parse_form, tag

ACTOR, IP = "round1b_markup_aware", "203.0.113.11"
HONEYPOT_NAMES = {"website", "url", "homepage", "hp", "honeypot", "fax", "address2"}
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)


def looks_hidden(field):
    for element in [field, *field["_ancestors"]]:
        if HIDDEN_STYLE.search(element.get("style") or ""):
            return "inline style"
        if "hidden" in element or element.get("aria-hidden") == "true":
            return "hidden / aria-hidden"
    if (field.get("name") or "").lower() in HONEYPOT_NAMES:
        return "honeypot-like name"
    return None


def build_form(fields, i, user, verbose=False):
    data = {}
    for f in fields:
        if not f.get("name") or f.get("type") in ("submit", "button"):
            continue
        if f.get("type") == "hidden":
            data[f["name"]] = f.get("value", "")
            continue
        why = looks_hidden(f)
        if why:
            if verbose:
                print(f"    skipping {f['name']!r}: {why}")
            continue
        if f.get("type", "text") in TEXT_TYPES:
            data[f["name"]] = fill_value(f, i, user)
    return data


def run(attempts=10, verbose=False):
    ok = 0
    for i in range(attempts):
        with http_client(ACTOR, IP) as client:
            fields = parse_form(client.get("/register").text)
            user = f"aware{i}-{tag()}"
            response = client.post("/register",
                                   data=build_form(fields, i, user, verbose and i == 0))
            result = outcome(response.text)
            ok += result == "created"
            if verbose:
                print(f"  signup {user:<17} {response.status_code} data-outcome={result}")
    if verbose:
        print(f"\nBot's view: {ok}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"actor": ACTOR, "attempts": attempts, "reported_ok": ok}


if __name__ == "__main__":
    print("=== Round 1b: markup-aware spammer ===")
    run(verbose=True)
