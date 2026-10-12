"""
Chapter 7 — Round 0: Recon (Section 7.5)

Objective: look at the store the way a bot does. What does the signup form
contain? What does robots.txt say? Then create one account, to confirm the
form works for scripts at DEFENSE_LEVEL=0.

Expected results:
  - level 0: three inputs (username, email, password), one account created
  - level 1+: an extra input appears. Run this again each round and compare.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round0_recon.py
"""

from _lab import fill_value, http_client, outcome, parse_form, tag

ACTOR, IP = "round0_recon", "203.0.113.9"


def run(verbose=False):
    with http_client(ACTOR, IP) as client:
        robots = client.get("/robots.txt").text
        html = client.get("/register").text
        fields = parse_form(html)
        user = f"recon-{tag()}"
        data = {f["name"]: f.get("value", "") if f.get("type") == "hidden"
                else fill_value(f, 0, user) for f in fields if f.get("name")}
        response = client.post("/register", data=data)
        result = outcome(response.text)

    if verbose:
        print("=== Round 0: Recon ===\n")
        print("robots.txt:\n  " + robots.strip().replace("\n", "\n  "))
        print("\nSignup form inputs, as the raw HTML shows them:")
        for f in fields:
            wrappers = [a for a in f["_ancestors"] if a.get("style") or a.get("class")]
            hint = ", ".join(f"{k}={v!r}" for a in wrappers for k, v in a.items()
                             if k in ("style", "class", "aria-hidden"))
            print(f"  name={f.get('name')!r:<16} type={f.get('type', 'text'):<9} "
                  f"label={f['_label']!r:<26} {hint}")
        print(f"\nSignup as {user!r}: {response.status_code} data-outcome={result!r}")
    return {"actor": ACTOR, "attempts": 1, "reported_ok": int(result == "created")}


if __name__ == "__main__":
    run(verbose=True)
