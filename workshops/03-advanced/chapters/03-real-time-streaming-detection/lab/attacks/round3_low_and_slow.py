"""
Round 3 attack: low and slow, distributed across hundreds of IPs.

The attacker gives up on volume per IP entirely. Five target accounts are attacked from a pool of
300 residential-proxy addresses, one try per address (a third of them retry once, three seconds
later), paced like slow humans. Per IP there is nothing to see: one or two failed logins. The
per-IP window is silent, the Round 2 session gate never trips (each session fails once or twice),
and there are too few events per session for timing regularity to mean anything.

What gives it away is the pivot to the *account*: each of the five victims is hit from 60
distinct IPs. No real account fails logins from 60 IPs inside two minutes. That is the
distinct-IP-per-account fan-out the cross-key detector counts with a HyperLogLog.

    python attacks/round3_low_and_slow.py
"""

import random

from _common import execute, finish, login, username, wrong_password, world_pool

VICTIMS = [200 + v for v in range(5)]
IPS_PER_VICTIM = 60
WINDOW_S = 20.0
UA = "okhttp/4.12.0"


def run():
    rng = random.Random(303)
    ips = world_pool("residential_proxy_net")[:len(VICTIMS) * IPS_PER_VICTIM]
    plan, n = [], 0
    for v, victim in enumerate(VICTIMS):
        for j in range(IPS_PER_VICTIM):
            ip, key = ips[v * IPS_PER_VICTIM + j], f"slow-{v}-{j}"
            start = rng.uniform(0, WINDOW_S)
            for k in range(1 if rng.random() < 0.7 else 2):
                plan.append(login(start + k * 3.0, key, ip, username(victim), wrong_password(n)))
                n += 1
    return execute(plan, "bot:low_and_slow", UA)


if __name__ == "__main__":
    finish(run())
