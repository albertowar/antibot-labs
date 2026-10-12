"""
W2 Ch1 — Round 5 Attack: Skip the Browser, Forge the Sensor (Section 1.6, Round 5)

Objective: notice that every defense in this chapter judges a JSON payload
the CLIENT sends. The attacker visits the store once with a real browser,
saves what the sensor posted (exactly what /lab/capture does), and from then on
replays it with plain HTTP: fetch a fresh nonce from the page, post the
saved signals with it, then call the API and post a human-looking click.

No browser, no JavaScript engine, ~5 requests per purchase. This is
tools/profile_replay.py, the module the checkpoint's shoppers use, with a
different intent, which is the point: at the HTTP level a perfect replay of
a real browser IS a real browser.

What would stop it is integrity, not more signals: an obfuscated,
per-session sensor whose output is bound to a server challenge and cannot
be computed without executing it (Chapter 2), plus behaviour
that cannot be replayed (Chapter 3).

Expected results:
  - every level → 200 on /api/products and /api/cart/add: the report, the headers and the click
    are a real browser's. Only Chapter 2's integrity checks can tell them apart.

Run the store first (python demo_site/app.py), then:
    python attacks/round5_forged_sensor.py [profile-name]
"""

import sys

from _common import CART_PATH, SCRAPE_PATH, bot_ip, finish, report
from labclient import LabClient
import profile_replay

DEFAULT_PROFILE = "chrome-153-windows"


def run(profile_name=DEFAULT_PROFILE):
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    stolen = profile_replay.profile(profile_name)
    out = profile_replay.trip(LabClient("bot:round5_forged_sensor", ip=bot_ip()), stolen)
    sig = [s for s in out["signals"].split(",") if s]
    return [{"path": SCRAPE_PATH, "status": out["products"] if out["page"] == 200 else out["page"], "signals": sig},
            {"path": CART_PATH, "status": out["cart"], "signals": sig}]


if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROFILE
    results = run(name)
    report(f"Round 5: forged sensor (replaying {name})", results)
    finish("round5_forged_sensor", results)
