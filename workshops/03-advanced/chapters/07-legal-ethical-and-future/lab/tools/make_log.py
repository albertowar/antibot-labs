"""
Chapter 7, Round 2: generate the decision log the audit runs over.

The store's detection pipeline (W2 Ch8 and the W3 streaming chapters) writes
one line per request: who the pipeline *thinks* it saw (the signals) and, in
this lab only, who it *actually* was (the actor and persona). Production logs
never carry ground truth; here it is what lets you measure false positives.

The people are the W2 Ch8 population: the same persona names, the same
shares, the same weak signals each one trips.

    persona      share   signals it trips                       who it is
    typical      ~65%    (none, or one weak one)                home broadband
    autofill     ~10%    no_keystrokes                          password managers
    vpn          ~6%     datacenter_asn, tz_geo_mismatch        work VPN, privacy, travel
    cgnat        ~5%     ip_elevated, ip_burst                  mobile carrier NAT
    privacy      ~3%     fp_randomized, fp_inconsistent         Firefox RFP, Brave, extensions
    a11y         ~2%     no_pointer, timing_too_regular         keyboard-only, screen readers
    old_device   ~2%     outdated_browser                       can't upgrade the hardware
    tor          ~1%     tor_exit, fp_randomized, tz mismatch   Tor Browser

Traits combine, so some rows are "vpn+autofill". The bot campaigns are the
Round 2 attackers; each one is built to look like one of the minorities:

    scraper_dc    datacenter scraper, http library, no telemetry      (easy)
    scraper_resi  residential proxies, headless Chrome, replayed fp    (medium)
    cgnat_burst   automation behind the mobile carrier's NAT           (hides in cgnat)
    tor_hidden    automation over Tor exits                            (hides in tor)
    a11y_mimic    keyboard-only automation, no pointer events          (hides in a11y)

Every address comes from the documentation ranges in data/world.json
(RFC 5737 / RFC 3849), so nothing here can ever point at a real network.
The generator is deterministic: the same seed gives the same file, which is
what makes the README's expected-results table reproducible.

Run:
    python tools/make_log.py                  # writes data/decisions.jsonl (seed 2026)
    python tools/make_log.py --seed 7 --out /tmp/other.jsonl
"""

import argparse
import ipaddress
import json
import os
import random
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
WORLD = os.path.join(LAB, "data", "world.json")
OUT = os.path.join(LAB, "data", "decisions.jsonl")

SEED = 2026
HUMANS = 2000
BOTS_PER_CAMPAIGN = 300
CAMPAIGNS = ["scraper_dc", "scraper_resi", "cgnat_burst", "tor_hidden", "a11y_mimic"]

ENDPOINTS = [("/login", 45), ("/api/products", 30), ("/checkout", 15), ("/account", 10)]
HOME_POOLS = [("isp-a", 35), ("isp-b", 25), ("fiber", 20), ("dsl", 20)]
MOBILE_SHARE = 0.35


def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def _ip(world, pool, index):
    net = ipaddress.ip_network(world["pools"][pool]["cidr"])
    if net.num_addresses <= 4:                 # the CGNAT pool is a /31: two shared addresses
        return str(net[index % net.num_addresses])
    return str(net[1 + index % (net.num_addresses - 2)])


def human(rng, i, world):
    """One real customer's request. Traits are drawn independently, as in W2 Ch8."""
    mobile = rng.random() < MOBILE_SHARE
    traits = []
    if not mobile and rng.random() < 0.02:
        traits.append("old_device")
    if rng.random() < 0.01:
        traits.append("tor")
    elif rng.random() < 0.03:
        traits.append("privacy")
    if mobile and rng.random() < 0.15:
        traits.append("cgnat")
    elif not mobile and "tor" not in traits and rng.random() < 0.06:
        traits.append("vpn")
    if not mobile and rng.random() < 0.02:
        traits.append("a11y")
    if rng.random() < 0.10:
        traits.append("autofill")

    home = _weighted(rng, HOME_POOLS)
    pool = "tor" if "tor" in traits else "vpn" if "vpn" in traits else "mobile" if "cgnat" in traits else home
    signals = []
    if "vpn" in traits:
        signals.append("datacenter_asn")
        if rng.random() < 0.6:
            signals.append("tz_geo_mismatch")
        if rng.random() < 0.2:
            signals.append("lang_mismatch")
    if "tor" in traits:
        signals += ["tor_exit", "fp_randomized", "tz_geo_mismatch"]
    if "cgnat" in traits:
        signals.append("ip_elevated" if rng.random() < 0.8 else "ip_burst")
    if "privacy" in traits:
        signals.append("fp_randomized")
        if rng.random() < 0.4:
            signals.append("fp_inconsistent")
    if "a11y" in traits:
        signals.append("no_pointer")
        if rng.random() < 0.5:
            signals.append("timing_too_regular")
    if "autofill" in traits:
        signals.append("no_keystrokes")
    if "old_device" in traits:
        signals.append("outdated_browser")
        if rng.random() < 0.3:
            signals.append("header_order_mismatch")
    if not traits and rng.random() < 0.03:       # nobody is perfectly clean
        signals.append(rng.choice(["ip_elevated", "header_order_mismatch", "fp_inconsistent"]))

    # Shared exits (VPN, Tor, CGNAT) are shared by many people; homes are not.
    index = rng.randrange(8) if pool in ("vpn", "tor", "mobile") else i
    return {
        "id": i,
        "actor": "human",
        "persona": "+".join(traits) or "typical",
        "traits": traits,
        "campaign": None,
        "pool": pool,
        "ip": _ip(world, pool, index),
        "country": world["pools"][pool]["country"],
        "endpoint": _weighted(rng, ENDPOINTS),
        "signals": sorted(set(signals)),
    }


def bot(rng, i, campaign, world):
    """One request from a bot campaign. Each campaign is just strong enough to
    beat the previous policy and to teach one false-positive trade-off."""
    if campaign == "scraper_dc":
        pool, index = "cloud", rng.randrange(64)
        signals = ["datacenter_asn", "http_library_ua", "ja4_non_browser", "no_telemetry"]
        if rng.random() < 0.7:
            signals.append("ip_burst")
    elif campaign == "scraper_resi":
        pool, index = _weighted(rng, HOME_POOLS), 1000 + rng.randrange(400)
        signals = ["headless_gpu", "timing_too_regular", "fp_reuse"]
        if rng.random() < 0.5:
            signals.append("cdp_artifacts")
        if rng.random() < 0.3:
            signals.append("mouse_too_straight")
    elif campaign == "cgnat_burst":
        pool, index = "mobile", rng.randrange(8)
        signals = ["ip_elevated", "fp_reuse"]
        if rng.random() < 0.5:
            signals.append("ip_burst")
        if rng.random() < 0.4:
            signals.append("cdp_artifacts")
    elif campaign == "tor_hidden":
        pool, index = "tor", rng.randrange(8)
        signals = ["tor_exit", "fp_randomized", "tz_geo_mismatch", "timing_too_regular"]
        if rng.random() < 0.5:
            signals.append("no_keystrokes")
        if rng.random() < 0.3:
            signals.append("mouse_too_straight")
    elif campaign == "a11y_mimic":
        pool, index = _weighted(rng, HOME_POOLS), 1500 + rng.randrange(300)
        signals = ["no_pointer", "timing_too_regular", "fp_reuse"]
        if rng.random() < 0.4:
            signals.append("no_keystrokes")
    else:
        raise ValueError(f"unknown campaign {campaign}")
    return {
        "id": i,
        "actor": "bot",
        "persona": f"bot:{campaign}",
        "traits": [],
        "campaign": campaign,
        "pool": pool,
        "ip": _ip(world, pool, index),
        "country": world["pools"][pool]["country"],
        "endpoint": "/api/products" if campaign.startswith("scraper") else "/login",
        "signals": sorted(set(signals)),
    }


def generate(seed=SEED, humans=HUMANS, bots=BOTS_PER_CAMPAIGN):
    with open(WORLD) as f:
        world = json.load(f)
    rng = random.Random(seed)
    rows = [human(rng, i, world) for i in range(humans)]
    n = humans
    for campaign in CAMPAIGNS:
        for _ in range(bots):
            rows.append(bot(rng, n, campaign, world))
            n += 1
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    rows = generate(args.seed)
    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
    personas = Counter(r["persona"] for r in rows if r["actor"] == "human")
    print(f"wrote {len(rows)} rows to {os.path.relpath(args.out)} (seed {args.seed})")
    print(f"  humans {sum(personas.values())}: " + ", ".join(f"{p} {n}" for p, n in personas.most_common()))
    print(f"  bots   {len(rows) - sum(personas.values())}: {BOTS_PER_CAMPAIGN} per campaign ({', '.join(CAMPAIGNS)})")


if __name__ == "__main__":
    main()
