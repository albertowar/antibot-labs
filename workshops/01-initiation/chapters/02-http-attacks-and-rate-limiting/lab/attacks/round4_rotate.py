"""
Chapter 2, Round 4 attack: change the key the limiter counts on.

Round 3's limits all key on the source address, so the attacker's answer is to not reuse an
address. Four shapes, each defeating a different per-IP assumption:

    (default)        credential stuffing spread over a fleet (cloud_vm + cloud_gcp): one pair
                     per address, so no per-IP login bucket ever fills. Beats endpoint_limit.
    --brute          one account, many guesses, a fresh address each time. Beats every per-IP
                     limit, because no address repeats; only a per-ACCOUNT cap sees it.
    --xff            one real cloud VM, but a forged X-Forwarded-For naming a random home
                     address on every request. A naive left-most reader scores a clean new
                     user each time, so the per-IP bucket keys on a value the attacker picks.
    --pool cloud_v6  a fresh IPv6 address, from one /64, per request. Free on IPv6.

The metric is "attempts/requests the defense let through". For the login shapes that is a
non-429 response; for the scrape shapes (--xff, --pool) it is a 200 with a price.

Expected (level 4 = endpoint_limit + account_limit):
    default   full       rotating addresses still beats a per-IP login bucket
    --brute   blocked    the per-account cap (5 / 15 min) stops one hammered account
    --xff     full       the forged header still picks the bucket (no trusted-proxy yet)
    cloud_v6  full       a per-address limit never sees the same IPv6 twice
Round 5 turns --xff and cloud_v6 off.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402  (guard runs on import)
from labclient import world_pool  # noqa: E402

FLEET = ["cloud_vm", "cloud_gcp"]


def _fleet_ips():
    return [ip for p in FLEET for ip in world_pool(p)]


def run_stuff():
    import _common
    from demo_site.seed import weak_users
    ips = _fleet_ips()
    return _common.stuff("r4_rotate", weak_users(), lambda i: ips[i % len(ips)])


def run_brute(n=60):
    import _common
    from demo_site.seed import username
    ips = _fleet_ips()
    pairs = [(username(0), f"guess-{i:04d}") for i in range(n)]      # one account, many guesses
    return _common.stuff("r4_brute", pairs, lambda i: ips[i % len(ips)])


def run_xff():
    import ipkit as ik
    r = ik.rng(4)
    ip = world_pool("cloud_vm")[0]
    fakes = world_pool("home_eu") + world_pool("home_broadband")    # nobody shops from here
    return ik.scrape("r4_xff", lambda i: ip, xff=lambda i: r.choice(fakes), extra={"spoof": "home"})


def run_pool(pool):
    ips = world_pool(pool)
    return ipkit.scrape(f"r4_{pool}", lambda i: ips[(i + 1) % len(ips)], keep_cookies=False, extra={"pool": pool})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--brute", action="store_true", help="one account, many guesses, rotating addresses")
    ap.add_argument("--xff", action="store_true", help="one VM, forged X-Forwarded-For per request")
    ap.add_argument("--pool", default=None, help="scrape from a pool, a fresh address per request (e.g. cloud_v6)")
    a = ap.parse_args()
    if a.brute:
        import _common
        _common.finish(run_brute())
    elif a.xff:
        ipkit.finish(run_xff())
    elif a.pool:
        ipkit.finish(run_pool(a.pool))
    else:
        import _common
        _common.finish(run_stuff())
