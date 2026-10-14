"""
Chapter 8, Round 1 attack: the naive form spammer.

Objective: create accounts in bulk (spam reviews, coupon abuse, resale). Fetch the signup page, fill
EVERY text-like input, submit at once. This is what most form-spam kits still do, because most sites
have no trap: it never renders the page, so it cannot know which fields a human would see.

    python attacks/round1_form_spammer.py

Expected:   level 0: every signup is created.
            level 1+: every signup lands in the hidden field and is silently dropped. The bot still
            lands on a plausible /account page and counts a success. That is the point of a fake
            success: the attacker gets no signal to adapt to. The server's view is in
            `python tools/scoreboard.py` (deceived) and /lab/decisions.
"""

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, LabClient, world_pool  # noqa: E402

ACTOR = "bot:r1_spammer"
ATTEMPTS = 10


def build_form(fields, user):
    data = {}
    for f in fields:
        if not f.get("name") or f.get("type") in ("submit", "button"):
            continue
        if f.get("type") == "hidden":
            data[f["name"]] = f.get("value", "")                    # copy tokens as-is
        elif f.get("type", "text") in trapkit.TEXT_TYPES:
            data[f["name"]] = trapkit.fill_value(f, user)           # fill everything
    return data


def run(attempts=ATTEMPTS, verbose=False):
    ip, believed = world_pool("cloud_vm")[1], 0
    for i in range(attempts):
        bot = LabClient(ACTOR, ip=ip)                               # fresh cookies every time
        page = bot.get("/register", trapkit.headers("link", BASE_URL + "/"))
        user = f"spam{i}-{secrets.token_hex(3)}"
        reply = trapkit.follow(bot, bot.post("/register", build_form(trapkit.parse_form(page.text), user),
                                             trapkit.headers("post", BASE_URL + "/register")),
                               trapkit.headers("link", BASE_URL + "/register"))
        ok = trapkit.signed_up(reply)
        believed += ok
        if verbose:
            print(f"  signup {user:<16} -> {reply.status_code} {reply.url.replace(BASE_URL, '')}")
    if verbose:
        print(f"\nBot's view: {believed}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"attempted": attempts, "succeeded": believed}


if __name__ == "__main__":
    print("=== Round 1: naive form spammer ===")
    print(json.dumps(run(verbose=True)))
