"""
Chapter 8, Round 2: generate the agent-session log the audit runs over.

The store's pipeline (W2 Ch8, and the agent telemetry from W4 Ch4)
writes one line per *session*: the signals it saw, the client type it inferred,
whether the session reached checkout, the account's order velocity, and, in
this lab only, who it actually was. Production logs never carry ground truth;
here it is what lets you measure who your agent policy hurts.

Legitimate cohorts (2,000 sessions), and the signals each one trips:

    cohort            share  client            signals it trips
    shopper           ~72%   browser           (none, or one stray)
    agent_shopper     ~12%   local agent       no_pointer, timing_too_regular, cdp_artifacts;
                                                half declare an agent UA, half look like Chrome
    a11y_agent         ~2%   assistive agent   no_pointer, screen_reader_api; a third declare
    cloud_signed       ~6%   cloud agent       agent_ua, signature_agent (valid), datacenter_asn, no_pointer
    cloud_undeclared   ~3%   cloud agent       datacenter_asn, no_pointer, cdp_artifacts; no declaration
    vpn                ~5%   browser           datacenter_asn, tz_geo_mismatch

Every legitimate session has a person behind it (human_present = true): a
shopper's agent hands a confirmation step back to the shopper, a cloud agent
relays it to the user's chat. Order velocity per account is 0-2 an hour.
Farms are unattended, except for the 10-25% of sessions they route to a human
operator (a click farm), so a human step-up alone is not a verdict either.

Bot campaigns (250 sessions each). The default one is the classic headless
scalper; the three hidden ones are the Round 2 attackers, each built to look
like a cohort the first fix protects:

    scalper_headless          cloud ASN, headless Chrome, reused fingerprints, bursts   (easy)
    local_agent_farm          200 fresh accounts each driving a local agent; per session
                              identical to agent_shopper; nobody home at the step-up   (hides in agent_shopper)
    declared_then_undeclared  signs its requests until blocked, then drops the signature
                              and comes back as Chrome on residential addresses         (hides in cloud_undeclared)
    a11y_mimic                no pointer events, screen-reader API calls, reused fps   (hides in a11y_agent)

Every address comes from the documentation ranges in data/world.json
(RFC 5737 / RFC 3849), so nothing here can ever point at a real network.
Deterministic: the same seed gives the same file.

Run:
    python tools/make_log.py                  # writes data/agent_sessions.jsonl (seed 2026)
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
OUT = os.path.join(LAB, "data", "agent_sessions.jsonl")

SEED = 2026
HUMANS = 2000
BOTS_PER_CAMPAIGN = 250
CAMPAIGNS = ["scalper_headless", "local_agent_farm", "declared_then_undeclared", "a11y_mimic"]
COHORTS = [("shopper", 72), ("agent_shopper", 12), ("cloud_signed", 6), ("vpn", 5),
           ("cloud_undeclared", 3), ("a11y_agent", 2)]
HOME_POOLS = [("isp-a", 35), ("isp-b", 25), ("fiber", 20), ("dsl", 20)]


def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def _ip(world, pool, index):
    net = ipaddress.ip_network(world["pools"][pool]["cidr"])
    if net.num_addresses <= 4:
        return str(net[index % net.num_addresses])
    return str(net[1 + index % (net.num_addresses - 2)])


def _row(i, actor, cohort, campaign, client, declared, signature_valid, pool, ip, signals,
         account_age_days, orders_per_hour, checkout, human_present):
    return {
        "id": i, "actor": actor, "cohort": cohort, "campaign": campaign,
        "client": client, "declared": declared, "signature_valid": signature_valid,
        "pool": pool, "ip": ip, "signals": sorted(set(signals)),
        "account_age_days": account_age_days, "orders_per_hour": orders_per_hour,
        "checkout": checkout, "human_present": human_present,
    }


def human(rng, i, world):
    """One real person's session, with or without an agent in between."""
    cohort = _weighted(rng, COHORTS)
    home = _weighted(rng, HOME_POOLS)
    signals, client, declared, sig = [], "browser", False, None
    pool, index = home, i
    age = rng.choice([3, 30, 200, 800, 1500])
    checkout_p = 0.25
    if cohort == "shopper":
        if rng.random() < 0.03:
            signals.append(rng.choice(["timing_too_regular", "tz_geo_mismatch", "cdp_artifacts"]))
    elif cohort == "agent_shopper":
        client = "local_agent"
        declared = rng.random() < 0.5
        if declared:
            signals.append("agent_ua")
        if rng.random() < 0.9:
            signals.append("no_pointer")
        if rng.random() < 0.6:
            signals.append("timing_too_regular")
        if rng.random() < 0.7:
            signals.append("cdp_artifacts")
        checkout_p = 0.4
    elif cohort == "a11y_agent":
        client = "assistive_agent"
        declared = rng.random() < 0.3
        if declared:
            signals.append("agent_ua")
        signals += ["no_pointer", "screen_reader_api"]
        if rng.random() < 0.5:
            signals.append("timing_too_regular")
        checkout_p = 0.3
    elif cohort == "cloud_signed":
        client, declared, sig = "cloud_agent", True, True
        pool, index = "cloud", rng.randrange(16)
        signals += ["agent_ua", "signature_agent", "datacenter_asn", "no_pointer"]
        checkout_p = 0.35
    elif cohort == "cloud_undeclared":
        client = "cloud_agent"
        pool, index = "cloud", 16 + rng.randrange(16)
        signals += ["datacenter_asn", "no_pointer"]
        if rng.random() < 0.5:
            signals.append("cdp_artifacts")
        checkout_p = 0.3
    elif cohort == "vpn":
        pool, index = "vpn", rng.randrange(8)
        signals.append("datacenter_asn")
        if rng.random() < 0.6:
            signals.append("tz_geo_mismatch")
    if age <= 3:
        signals.append("new_account")
    orders = rng.choices([0, 1, 2], weights=[70, 25, 5])[0]
    return _row(i, "human", cohort, None, client, declared, sig, pool, _ip(world, pool, index), signals,
                age, orders, rng.random() < checkout_p, True)


def bot(rng, i, campaign, world):
    """One session from a bot campaign. Each campaign is just strong enough to
    beat the previous policy and to teach one trade-off. operator_p is the share
    of sessions where the farm routes a confirmation step to a human operator
    (a click farm): a human step-up alone is not a verdict either."""
    declared, sig, client, operator_p = False, None, "browser", 0.0
    if campaign == "scalper_headless":
        pool, index = "cloud", 32 + rng.randrange(64)
        signals = ["headless_gpu", "cdp_artifacts", "fp_reuse", "datacenter_asn"]
        if rng.random() < 0.7:
            signals.append("ip_burst")
        age, orders = rng.randrange(0, 3), rng.randrange(20, 60)
    elif campaign == "local_agent_farm":
        pool, index = _weighted(rng, HOME_POOLS), 1000 + rng.randrange(200)
        client = "local_agent"
        declared = rng.random() < 0.5
        signals = ["no_pointer"] + (["agent_ua"] if declared else [])
        if rng.random() < 0.6:
            signals.append("timing_too_regular")
        if rng.random() < 0.7:
            signals.append("cdp_artifacts")
        if rng.random() < 0.8:
            signals.append("fp_reuse")
        age, orders, operator_p = rng.randrange(0, 4), rng.randrange(6, 16), 0.25
    elif campaign == "declared_then_undeclared":
        if rng.random() < 0.4:                      # phase 1: signed, declared, cloud
            pool, index, client, declared, sig = "cloud", 96 + rng.randrange(16), "cloud_agent", True, True
            signals = ["agent_ua", "signature_agent", "datacenter_asn", "no_pointer"]
        else:                                       # phase 2: signature dropped, Chrome UA, residential proxies
            pool, index, client = _weighted(rng, HOME_POOLS), 1200 + rng.randrange(200), "local_agent"
            signals = ["cdp_artifacts", "fp_reuse", "no_pointer"]
        age, orders, operator_p = rng.randrange(0, 6), rng.randrange(4, 11), 0.15
    elif campaign == "a11y_mimic":
        pool, index, client = _weighted(rng, HOME_POOLS), 1400 + rng.randrange(200), "assistive_agent"
        signals = ["no_pointer", "screen_reader_api", "timing_too_regular"]
        if rng.random() < 0.7:
            signals.append("fp_reuse")
        age, orders, operator_p = rng.randrange(0, 4), rng.randrange(5, 13), 0.10
    else:
        raise ValueError(f"unknown campaign {campaign}")
    if age <= 3:
        signals.append("new_account")
    return _row(i, "bot", f"bot:{campaign}", campaign, client, declared, sig, pool, _ip(world, pool, index),
                signals, age, orders, True, rng.random() < operator_p)


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
    cohorts = Counter(r["cohort"] for r in rows if r["actor"] == "human")
    print(f"wrote {len(rows)} rows to {os.path.relpath(args.out)} (seed {args.seed})")
    print(f"  humans {sum(cohorts.values())}: " + ", ".join(f"{c} {n}" for c, n in cohorts.most_common()))
    print(f"  bots   {len(rows) - sum(cohorts.values())}: {BOTS_PER_CAMPAIGN} per campaign ({', '.join(CAMPAIGNS)})")


if __name__ == "__main__":
    main()
