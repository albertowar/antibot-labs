"""
Calibrate the Round 2 risk model offline: every cohort member's and every attacker's score and
band under the thresholds in defenses/policy.py, and the friction they cost.

A threshold is a business decision with two prices: each point you lower `medium` prompts more
real customers; each point you raise it lets more unfamiliar logins through without a prompt.
This tool puts both on one screen, from the same seeded history the store loads, without starting
the store. It is the defender's labelled view: it reads the attackers' kits too, which no check
in the store may do (that is what makes it calibration, not detection).

    python tools/calibrate.py               # one row per person and per crew, at policy.py's thresholds
    python tools/calibrate.py --sweep       # friction and attacker bands across a grid of thresholds
    python tools/calibrate.py --check       # assert ua_key() matches the store's User-Agent parsing

Needs your defenses/rba_score.py (Round 2). Before you write it, run it with the reference:
`python tools/checkpoint.py --round 2 --catch-up` installs it (`--restore` puts yours back).
"""

import argparse
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
sys.path[:0] = [LAB, HERE]

import browsers  # noqa: E402
from labclient import world_pool  # noqa: E402  (offline: no request is made)
from defenses import netinfo, policy, rba_score  # noqa: E402
from defenses.context import UserAgent  # noqa: E402
from demo_site.ext import rba_world as W  # noqa: E402

LIBRARY_UA = "python-requests/2.34.2"


def address(pool, slot=0):
    ips = world_pool(pool)
    return ips[slot % len(ips)]


def cohort_rows():
    """(persona, index, features, net_type) for each cohort member's login today."""
    out = []
    for idx, a in sorted(W.accounts().items()):
        if a.persona not in dict(W.COHORT):
            continue
        t = W.today(a)
        f = W.features_of(a, t["device"], t["pool"], t["browser"], rd_of=t["rd_of"])
        out.append((a.persona, idx, f, netinfo.lookup(address(t["pool"], a.home_slot))["asn_type"]))
    return out


def geo_matched_pool(home_pool):
    """The residential proxy pool a careful crew rents for a victim: the victim's own ISP if it can."""
    return "residential_proxy" if home_pool == "home_broadband" else "resi_us"


def attack_rows():
    """(crew, index, features, net_type) for each attacker login, as the attack scripts make them."""
    out = []
    lib = UserAgent.parse(LIBRARY_UA)
    for v in W.kit("cheap"):
        asn, cc = W.pool_info("cloud_vm")
        f = {"dev": "none", "asn": str(asn), "cc": cc, "ua": f"{lib.family}/{lib.major}/d"}
        out.append(("cheap", v["index"], f, netinfo.lookup(address("cloud_vm", v["index"]))["asn_type"]))
    for crew in ("premium", "mailbox", "inbox"):
        for v in W.kit(crew):
            pool = geo_matched_pool(v["home_pool"])
            asn, cc = W.pool_info(pool)
            dev = v.get("rd", "none")
            ua = W.ua_key(v.get("browser", W.NEW_LAPTOP))
            out.append((crew, v["index"], {"dev": dev, "asn": str(asn), "cc": cc, "ua": ua},
                        netinfo.lookup(address(pool, v["index"]))["asn_type"]))
    return out


def scored(rows, per, glob):
    out = []
    for who, idx, f, net in rows:
        total, parts = rba_score.score(f, per[idx], glob, net)
        out.append((who, idx, total, rba_score.band(total, per[idx]), parts))
    return out


def summary(people, attackers):
    prompted = sum(1 for _, _, _, b, _ in people if b != "low")
    print(f"\nfriction: {prompted}/{len(people)} cohort logins prompted ({prompted / len(people):.0%}),"
          f" budget {policy.FRICTION_BUDGET:.0%}")
    for crew in ("cheap", "premium", "mailbox", "inbox"):
        bands = Counter(b for who, _, _, b, _ in attackers if who == crew)
        print(f"  {crew:<8} " + "  ".join(f"{b} {bands.get(b, 0)}" for b in ("low", "medium", "high")))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        profiles = W.DESKTOPS + W.PHONES + [W.NEW_LAPTOP]
        for prof in profiles:
            ua = dict(browsers.headers_for(prof, "typed", "http://127.0.0.1"))["User-Agent"]
            u = UserAgent.parse(ua)
            got = f"{u.family}/{u.major}/{'m' if u.mobile else 'd'}"
            assert got == W.ua_key(prof), (prof, got, W.ua_key(prof))
        print(f"ua_key matches UserAgent.parse for {len(profiles)} profiles")
        return
    per, glob = W.seeded_counts()
    people, attackers = scored(cohort_rows(), per, glob), scored(attack_rows(), per, glob)
    if args.sweep:
        saved = dict(policy.RBA_BANDS)
        print(f"{'medium':>7}{'high':>6}{'friction':>10}   attackers low / high (premium, mailbox, cheap)")
        for med in (-4.0, -2.0, 0.0, 2.0, 4.0):
            for high in (8.0, 10.0, 12.0):
                policy.RBA_BANDS.update(medium=med, high=high)
                p = [rba_score.band(t, per[i]) for _, i, t, _, _ in people]
                a = {c: Counter(rba_score.band(t, per[i]) for w, i, t, _, _ in attackers if w == c)
                     for c in ("premium", "mailbox", "cheap")}
                fr = sum(b != "low" for b in p) / len(p)
                print(f"{med:>7}{high:>6}{fr:>10.0%}   " + ", ".join(f"{a[c]['low']}/{a[c]['high']}" for c in a))
        policy.RBA_BANDS.update(saved)
        return
    print(f"{'who':<17}{'acct':>5}{'score':>7}  band    contributions")
    for who, idx, total, b, parts in people + attackers:
        contrib = " ".join(f"{k}{v:+.1f}" for k, v in parts.items())
        print(f"{who:<17}{idx:>5}{total:>7.1f}  {b:<7} {contrib}")
    summary(people, attackers)


if __name__ == "__main__":
    main()
