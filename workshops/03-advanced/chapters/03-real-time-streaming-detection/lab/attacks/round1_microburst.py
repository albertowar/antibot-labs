"""
Round 1 attack: a single-IP micro-burst.

The crudest credential stuffer: one client hammering POST /api/login as fast as its loop allows,
300 stolen credentials in ten seconds from one datacenter address, evenly spaced because a tight
loop with a fixed sleep is regular. A fixed-window limiter can split this across its window
boundary; the sliding-window detector on the stream does not. And it finishes long before a
session-level or batch scorer would look: that is Round 0's gap.

    python attacks/round1_microburst.py
"""

from _common import CHROME_UA, execute, finish, login, username, wrong_password, world_pool  # noqa: F401

N_REQUESTS = 300
RATE_HZ = 30.0
UA = "python-requests/2.34.2"


def run():
    ip = world_pool("cloud_vm")[0]
    plan = [login(i / RATE_HZ, "burst", ip, username(100 + i % 190), wrong_password(i)) for i in range(N_REQUESTS)]
    return execute(plan, "bot:microburst", UA)


if __name__ == "__main__":
    finish(run())
