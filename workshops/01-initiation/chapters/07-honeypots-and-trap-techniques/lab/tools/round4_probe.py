"""
Round 4 probe: one row of the response-strategy table, for whatever policy.py says right now.

    python tools/round4_probe.py          # DEFENSE_LEVEL=4 store running

Edit TRAP_RESPONSE_MODE / TRAP_SANCTION_KEY in defenses/policy.py, save (the store reloads it on the next
request), run this again. It wipes the store, runs the Round 4 bot (3 signups, each: log in, post a review,
look for it), then one real customer from the SAME carrier address, and prints what each of them lived.

The customer is the mobile_cgnat shopper from the Chapter 7 population (tools/personas_ch7.py): same
address as the bot, a normal signup, a normal review. "Silently trapped" means a trap or sanction signal
touched what they did while the page looked fine, or their review is invisible to everyone else.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "attacks"))

import personas_ch7  # noqa: E402,F401
import population  # noqa: E402
from labclient import admin, reset, world_pool  # noqa: E402

import round4_verify_signup as bot  # noqa: E402

MEANING = {"blocked": "blocked with a 403", "trapped": "silently trapped: signup dropped, or quarantined with the review hidden",
           "logged_in": "unaffected"}


def main():
    cfg = admin("GET", "/lab/traps")
    if cfg["level"] != 4:
        raise SystemExit(f"The probe needs DEFENSE_LEVEL=4 (the store runs level {cfg['level']}): "
                         "python tools/checkpoint.py --round 4 sets it, or POST /lab/level.")
    reset()
    attack = bot.run(attempts=3)
    shared = world_pool("mobile_cgnat")[0]
    customer = next(p for p in population.personas() if p.persona == "mobile_cgnat" and p.ip == shared)
    result = population.run("signup", people=[customer], quiet=True)[0]
    print(f"TRAP_RESPONSE_MODE={cfg['response_mode']}  TRAP_SANCTION_KEY={cfg['sanction_key']}")
    print(f"  the bot concludes   {attack['conclusions']}")
    print(f"  the carrier customer: {MEANING.get(result.get('outcome'), result.get('outcome'))}")
    print(json.dumps({"attempted": attack["attempted"], "succeeded": attack["succeeded"],
                      "conclusions": attack["conclusions"], "customer": result.get("outcome")}))


if __name__ == "__main__":
    main()
