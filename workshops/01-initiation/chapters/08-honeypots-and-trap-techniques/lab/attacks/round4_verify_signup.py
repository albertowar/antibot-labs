"""
Chapter 8, Round 4 attack: check your work.

Objective: a fake success only works while the bot believes it. This bot verifies every signup the way a
careful operator does:

  1. sign up (filling every field, so it trips the honeypot)
  2. log in with the new account
  3. post a review, then reload the product page to look for it

It shares an address with the shopper phones behind one mobile carrier (the first mobile_cgnat address
in data/world.json): one bot and several real customers behind a single IP.

What the bot concludes, by TRAP_RESPONSE_MODE (policy.py, DEFENSE_LEVEL=4):
  block       "blocked": the 403 says exactly which request was caught
  fake        "shadow-banned": the signup looked fine, but the login fails
  quarantine  "success": login works and its review shows up... for itself. Nobody else ever sees it.

    python attacks/round4_verify_signup.py
"""

import json
import os
import secrets
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, LabClient, world_pool  # noqa: E402
from labclient import csrf_of  # noqa: E402

ACTOR = "bot:r4_verify"
SPAM = "Best deal ever!!! Visit cheap-widgets.example for 90% off"
SKU = "p001"


def attempt(i, verbose):
    bot = LabClient(ACTOR, ip=world_pool("mobile_cgnat")[0])
    page = bot.get("/register", trapkit.headers("link", BASE_URL + "/"))
    if page.status_code == 403:
        return "blocked"
    user = f"verify{i}-{secrets.token_hex(3)}"
    data = {f["name"]: f.get("value", "") if f.get("type") == "hidden" else trapkit.fill_value(f, user)
            for f in trapkit.parse_form(page.text) if f.get("name") and f.get("type") not in ("submit", "button")}
    signup = bot.post("/register", data, trapkit.headers("post", BASE_URL + "/register"))
    if signup.status_code == 403:
        return "blocked"
    trapkit.follow(bot, signup, trapkit.headers("link", BASE_URL + "/register"))
    login_page = bot.get("/login", trapkit.headers("link", BASE_URL + "/"))
    login = bot.post("/login", {"csrf": csrf_of(login_page.text), "email": data["email"],
                                "password": data["password"], "next": "/account"},
                     trapkit.headers("post", BASE_URL + "/login"))
    if login.status_code == 403:
        return "blocked"
    if login.status_code != 302:
        return "shadow-banned"                                 # the account the signup promised does not exist
    product = bot.get(f"/product/{SKU}", trapkit.headers("link", BASE_URL + "/"))
    post = bot.post(f"/review/{SKU}", {"csrf": csrf_of(product.text), "rating": "5", "title": f"Great {user}",
                                       "body": SPAM}, trapkit.headers("post", BASE_URL + f"/product/{SKU}"))
    if post.status_code == 403:
        return "blocked"
    visible = SPAM in bot.get(f"/product/{SKU}", trapkit.headers("link", BASE_URL + "/")).text
    if verbose:
        print(f"  {user}: signup ok, login ok, own review visible: {visible}")
    return "success" if visible else "review-missing"


def run(attempts=3, verbose=False):
    conclusions = Counter(attempt(i, verbose) for i in range(attempts))
    if verbose:
        print("\nBot's conclusions:", dict(conclusions))
        print("Server's view (were the reviews actually published?): python tools/scoreboard.py")
    return {"attempted": attempts, "succeeded": conclusions["success"], "conclusions": dict(conclusions)}


if __name__ == "__main__":
    print("=== Round 4: verify every signup ===")
    print(json.dumps(run(verbose=True)))
