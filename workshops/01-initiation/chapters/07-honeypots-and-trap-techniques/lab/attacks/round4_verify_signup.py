"""
Chapter 7 — Round 4 Attack: Check Your Work (Section 7.5)

Objective: a fake success page only works while the bot believes it. This bot
verifies every signup the way a careful operator does:

  1. sign up (filling every field, so it trips the honeypot)
  2. log in with the new account
  3. post a review, then reload the product page to look for it

It shares 203.0.113.77 with `cgnat_shopper` in tools/legit_traffic.py: one
mobile carrier IP, one bot and one real customer behind it.

What the bot concludes, by RESPONSE_MODE (DEFENSE_LEVEL=4):
  block       "blocked": the 403 says exactly which request was caught
  fake        "shadow-banned": signup said OK, but the login fails
  quarantine  "success": login works and its review shows up... for itself.
              Nobody else ever sees it.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=4 RESPONSE_MODE=block SANCTION_KEY=ip python app.py
Then run:
    python attacks/round4_verify_signup.py
"""

from collections import Counter

from _lab import fill_value, http_client, outcome, parse_form, tag

ACTOR, IP = "round4_verify_signup", "203.0.113.77"
SPAM = "Best deal ever!!! Visit cheap-widgets.example for 90% off"


def attempt(i, verbose):
    with http_client(ACTOR, IP) as client:
        signup_page = client.get("/register")
        if signup_page.status_code == 403:
            return "blocked"
        user = f"verify{i}-{tag()}"
        data = {f["name"]: f.get("value", "") if f.get("type") == "hidden"
                else fill_value(f, i, user) for f in parse_form(signup_page.text) if f.get("name")}
        signup = client.post("/register", data=data)
        if signup.status_code == 403:
            return "blocked"
        password = fill_value({"type": "password"}, i, user)
        login = client.post("/login", data={"username": user, "password": password})
        if outcome(login.text) != "signed-in":
            return "shadow-banned"
        client.post("/review", data={"product_id": 1, "text": SPAM})
        visible = SPAM in client.get("/products/1").text
        if verbose:
            print(f"  {user}: signup ok, login ok, own review visible: {visible}")
        return "success" if visible else "review-missing"


def run(attempts=3, verbose=False):
    conclusions = Counter(attempt(i, verbose) for i in range(attempts))
    if verbose:
        print("\nBot's conclusions:", dict(conclusions))
        print("Server's view (were the reviews actually published?): python tools/scoreboard.py")
    return {"actor": ACTOR, "attempts": attempts, "conclusions": dict(conclusions)}


if __name__ == "__main__":
    print("=== Round 4: verify every signup ===")
    run(verbose=True)
