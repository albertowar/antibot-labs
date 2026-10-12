"""
Chapter 7 — Round 1 Attack: Naive Form Spammer (Section 7.5)

Objective: create accounts in bulk (for spam reviews, coupon abuse, fake
followers). Fetch the signup page, fill EVERY text-like input, submit at once.

This is what most form-spam kits still do, because most sites have no trap.
It never renders the page, so it can't know which fields a human would see.

Expected results:
  - level 0: every signup is created
  - level 1+: every signup lands in the hidden field and is silently dropped.
    The bot still sees "Welcome aboard!" and counts a success. That's the
    point of a fake success: the attacker gets no signal to adapt to.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/round1_form_spammer.py
"""

from _lab import TEXT_TYPES, fill_value, http_client, outcome, parse_form, tag

ACTOR, IP = "round1_form_spammer", "203.0.113.10"


def build_form(fields, i, user):
    data = {}
    for f in fields:
        if not f.get("name") or f.get("type") in ("submit", "button"):
            continue
        if f.get("type") == "hidden":
            data[f["name"]] = f.get("value", "")      # copy tokens as-is
        elif f.get("type", "text") in TEXT_TYPES:
            data[f["name"]] = fill_value(f, i, user)  # fill everything
    return data


def run(attempts=10, verbose=False):
    ok = 0
    for i in range(attempts):
        with http_client(ACTOR, IP) as client:   # fresh cookies every time
            fields = parse_form(client.get("/register").text)
            user = f"spam{i}-{tag()}"
            response = client.post("/register", data=build_form(fields, i, user))
            result = outcome(response.text)
            ok += result == "created"
            if verbose:
                print(f"  signup {user:<16} {response.status_code} data-outcome={result}")
    if verbose:
        print(f"\nBot's view: {ok}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"actor": ACTOR, "attempts": attempts, "reported_ok": ok}


if __name__ == "__main__":
    print("=== Round 1: naive form spammer ===")
    run(verbose=True)
