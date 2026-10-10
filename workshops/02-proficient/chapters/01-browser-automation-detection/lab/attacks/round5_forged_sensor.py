"""
W2 Ch1 — Round 5 Attack: Skip the Browser, Forge the Sensor (Section 1.6, Round 5)

Objective: notice that every defense in this chapter judges a JSON payload
the CLIENT sends. The attacker visits the store once with a real browser,
saves what the sensor posted (exactly what /capture does), and from then on
replays it with plain HTTP: fetch a fresh nonce from the page, post the
saved signals with it, then call the API and post a human-looking click.

No browser, no JavaScript engine, ~5 requests per purchase. This is
tools/legit_traffic.py with a different intent, which is the point: at the
HTTP level a perfect replay of a real browser IS a real browser.

What would stop it is integrity, not more signals: an obfuscated,
per-session sensor whose output is bound to a server challenge and cannot
be computed without executing it (Workshop 2, Chapter 2), plus behaviour
that cannot be replayed (Workshop 2, Chapter 3).

Expected results:
  - every DEFENSE_LEVEL → 200 on /api/products and /api/cart

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=4 python app.py
Then run:
    python attacks/round5_forged_sensor.py [profile-name]
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

from _common import BASE_URL, CART_PATH, SCRAPE_PATH, report, require_local
from legit_traffic import PROFILES_DIR, replay_profile

DEFAULT_PROFILE = "chrome-153-windows"


def run(profile_name=DEFAULT_PROFILE):
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    require_local()
    with open(os.path.join(PROFILES_DIR, f"{profile_name}.json")) as f:
        stolen = json.load(f)
    trip = replay_profile(stolen, BASE_URL)
    reasons = trip["reasons"]
    return [{"path": SCRAPE_PATH, "status": trip["products"], "reasons": reasons if trip["products"] == 403 else []},
            {"path": CART_PATH, "status": trip["cart"], "reasons": reasons if trip["cart"] == 403 else []}]


if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROFILE
    report(f"Round 5: forged sensor (replaying {name})", run(name))
