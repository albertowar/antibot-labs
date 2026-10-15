"""
Round 2 attack: the burst, spread across rotating IPs.

Round 1 keyed on the source IP, so the attacker spreads the same campaign over 40 addresses of
a hosting provider, each making four tries two and a half seconds apart. Per IP that is four
requests: far under the per-IP window. But the endpoint is still taking 160 failed logins from
40 distinct IPs, which is what the sketches measure. Each IP is its own session (own cookie).

The tries are interleaved in time (the starts are staggered), so the campaign is visible on the
stream while it happens, not all at the end.

    python attacks/round2_ip_rotation.py
"""

from _common import execute, finish, login, username, wrong_password, world_pool

N_IPS = 40
TRIES_PER_IP = 4
SPACING_S = 2.5
STAGGER_S = 0.15
UA = "curl/8.9.0"


def run():
    ips = world_pool("cloud_vm")[1:1 + N_IPS]
    plan = [login(i * STAGGER_S + k * SPACING_S, f"rot-{i}", ip, username(100 + i * TRIES_PER_IP + k), wrong_password(i * 10 + k))
            for i, ip in enumerate(ips) for k in range(TRIES_PER_IP)]
    return execute(plan, "bot:ip_rotation", UA)


if __name__ == "__main__":
    finish(run())
