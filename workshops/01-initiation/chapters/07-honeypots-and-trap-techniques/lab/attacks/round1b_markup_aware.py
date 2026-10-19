"""
Chapter 7, Round 1 attack, part b: the markup-aware spammer.

Objective: beat the textbook honeypot without a browser. Before filling a field, read the markup
around it and skip anything that LOOKS hidden:

  - an inline style with display:none or visibility:hidden, on the input or on any element around it
  - the `hidden` attribute, or aria-hidden="true" on any ancestor
  - a name from the usual honeypot list (website, url, homepage, ...)

All of that is visible in the HTML, so the bot needs about 15 extra lines. It still submits instantly,
and it still cannot see what the stylesheet does.

    python attacks/round1b_markup_aware.py

Expected:   level 1: every signup is created (the inline display:none gave the honeypot away).
            level 2+: trapped. The honeypot is hidden by a class in traps.css and has an opaque name,
            and the instant submit trips the timing token. Ask yourself: what would it take to beat
            level 2 without a browser?
"""

import json
import os
import re
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, LabClient, world_pool  # noqa: E402

ACTOR = "bot:r1b_markup_aware"
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


def build_form(fields, user, verbose=False):
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
        if f.get("type", "text") in trapkit.TEXT_TYPES:
            data[f["name"]] = trapkit.fill_value(f, user)
    return data


def run(attempts=10, verbose=False):
    ip, believed = world_pool("cloud_vm")[2], 0
    for i in range(attempts):
        bot = LabClient(ACTOR, ip=ip)
        page = bot.get("/register", trapkit.headers("link", BASE_URL + "/"))
        user = f"aware{i}-{secrets.token_hex(3)}"
        data = build_form(trapkit.parse_form(page.text), user, verbose and i == 0)
        reply = trapkit.follow(bot, bot.post("/register", data, trapkit.headers("post", BASE_URL + "/register")),
                               trapkit.headers("link", BASE_URL + "/register"))
        ok = trapkit.signed_up(reply)
        believed += ok
        if verbose:
            print(f"  signup {user:<17} -> {reply.status_code} {reply.url.replace(BASE_URL, '')}")
    if verbose:
        print(f"\nBot's view: {believed}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"attempted": attempts, "succeeded": believed}


if __name__ == "__main__":
    print("=== Round 1b: markup-aware spammer ===")
    print(json.dumps(run(verbose=True)))
