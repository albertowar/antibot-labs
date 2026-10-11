"""
Chapter 7 — Round 3 Attack: the oracle prober (Section 7.6, Part 4)

Objective: stop guessing. Treat the defense as a black box, send cheap
probe sessions, read what comes back, and search for the cheapest
configuration that passes. Then spend money only on that one.

Knobs (cheapest value first):
  fingerprint  rotate (free randomizer) |
               purchased (real-device profiles from a fingerprint shop, $0.50 each)
               (the single stealth profile from Round 1 is already burned)
  behavior     scripted | humanized
  pool         datacenter ($0.10/GB) | residential ($4/GB)
  browse       0 | 3 product pages first

Search: coordinate descent. For each knob, probe every value with
PROBES_PER_CONFIG sessions and keep the value with the lowest risk.
The demo site has been returning `risk` in every checkout response since
Round 1 (a "teaching aid"). That is a gradient, and the prober follows it.

Round 4 takes the oracle away: every checkout answers 202 "pending
review", with no score, and orders are cancelled later. The default
prober then sees identical answers for every config and buys the cheapest.
`--patient` tries every config, waits for the reviews to come back, and
pays for it in probes and time.

Expected results:
  - DEFENSE_LEVEL=3 → finds a passing config in ≈ 10–16 probes; exploit ≈ 80–100%
  - DEFENSE_LEVEL=4 → default: exploit ≈ 0%; --patient: ≈ 48 probes and one
    review cycle, then the exploit works again (the oracle is slowed, not removed)

Run:
    python attacks/round3_oracle_prober.py
    python attacks/round3_oracle_prober.py --patient     # Round 4 only
"""

import argparse
import itertools
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling attacks, also when imported by checkpoint.py

import labclient as labnet  # noqa: E402
import round0_baseline  # noqa: E402
import round2_farm  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, browser_headers, desktop_behavior,  # noqa: E402
                     fingerprint, fixed_think, human_think, pick_device)

KNOBS = {
    "fingerprint": ["rotate", "purchased"],
    "behavior": ["scripted", "humanized"],
    "pool": ["datacenter", "residential"],
    "browse": [0, 3],
}
CHEAPEST = {k: v[0] for k, v in KNOBS.items()}
PROFILE_USD = 0.50
PROBES_PER_CONFIG = 2


def make_persona(cfg, rng, purchased_pool):
    pool = labnet.Pool(cfg["pool"], country="US", rng=rng)
    ip, _ = pool.next()
    extra_usd = 0.0
    if cfg["fingerprint"] == "rotate":
        ua_key, langs, fp = round2_farm.randomized_profile(rng)
    else:  # purchased: harvested from real devices, internally consistent
        fp = dict(rng.choice(purchased_pool))
        ua_key = next(k for k, v in UA.items() if v == fp["ua"])
        langs = fp["langs"]
        extra_usd = PROFILE_USD
    if cfg["behavior"] == "scripted":
        behavior, think = round0_baseline.scripted_behavior(rng), fixed_think(0.8)
    else:
        behavior, think = desktop_behavior(rng), human_think(6.0)
    p = Persona(actor="round3_oracle_prober", cohort="prober", is_bot=True, ip=ip,
                user_agent=UA[ua_key], headers=browser_headers(langs), fp=fp,
                behavior=behavior, think=think, browse=cfg["browse"],
                usd_per_gb=pool.usd_per_gb, config=dict(cfg))
    p.config["extra_usd"] = extra_usd
    return p


def purchased_profiles(rng, n=400):
    """A fingerprint shop's inventory: real US devices, each with its own canvas."""
    out = []
    for _ in range(n):
        device = pick_device(rng)
        ua_key = rng.choice(shopper.DEVICES[device][6])
        locale = shopper.pick_locale(rng, countries=("US",))
        out.append(fingerprint(rng, device, locale, ua_key, canvas=f"{rng.getrandbits(64):016x}"))
    return out


class Prober:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.seed = seed
        self.inventory = purchased_profiles(self.rng)
        self.results = []

    def sessions(self, cfgs, label):
        personas = [make_persona(c, self.rng, self.inventory) for c in cfgs]
        self.seed += 1
        res = shopper.run_sessions(personas, seed=self.seed, run=label)
        self.results += res
        return res

    @staticmethod
    def risk(r):
        """What the attacker reads from a response. No score → only the status code."""
        if r["score"] is not None:
            return r["score"]
        return 0.0 if r["status"] in (200, 202) else 1.0

    def probe(self, cfg):
        """Send PROBES_PER_CONFIG sessions; return (mean observed risk, all passed?)."""
        res = self.sessions([cfg] * PROBES_PER_CONFIG, "round3_probe")
        risks = [self.risk(r) for r in res]
        print(f"  probe {self.n_probes():>3}  {fmt(cfg)}  risk={sum(risks) / len(risks):.2f}")
        return sum(risks) / len(risks), all(x < 1.0 for x in risks)

    def greedy(self, budget):
        """Coordinate descent on the observed risk, a few passes over the knobs."""
        best = dict(CHEAPEST)
        best_risk, ok = self.probe(best)
        for _ in range(3):
            for knob, values in KNOBS.items():
                for value in values:
                    if ok or value == best[knob] or self.n_probes() >= budget:
                        continue
                    cand = dict(best, **{knob: value})
                    risk, cand_ok = self.probe(cand)
                    if risk < best_risk:
                        best, best_risk, ok = cand, risk, cand_ok
        return best

    def patient(self):
        """No usable response? Try every config at once and wait for the reviews."""
        configs = [dict(zip(KNOBS, combo)) for combo in itertools.product(*KNOBS.values())]
        started = time.time()
        res = self.sessions([c for c in configs for _ in range(PROBES_PER_CONFIG)],
                            "round3_probe")
        passed = []
        for cfg in configs:
            mine = [r for r in res if all(r["config"][k] == cfg[k] for k in KNOBS)]
            if all(shopper.succeeded(r) for r in mine):
                passed.append(cfg)
        print(f"  {len(res)} probes across {len(configs)} configs, "
              f"waited {time.time() - started:.0f}s for reviews; {len(passed)} configs passed")
        return min(passed, key=cost_rank) if passed else dict(CHEAPEST)

    def n_probes(self):
        return len(self.results)


def cost_rank(cfg):
    return tuple(KNOBS[k].index(cfg[k]) for k in ("pool", "fingerprint", "behavior", "browse"))


def fmt(cfg):
    return " ".join(f"{k}={cfg[k]}" for k in KNOBS)


def bill(results):
    return sum(r["usd"] + r["config"].get("extra_usd", 0) for r in results)


def run(seed=41, exploit_n=30, patient=False, budget=24, quiet=False):
    """Probe, then exploit. Returns exploit results; probe stats on the function attribute."""
    prober = Prober(seed)
    out = sys.stdout
    if quiet:
        sys.stdout = open(os.devnull, "w")
    try:
        best = prober.patient() if patient else prober.greedy(budget)
        n_probe, probe_usd = prober.n_probes(), bill(prober.results)
        print(f"  chosen config: {fmt(best)}")
        exploit = prober.sessions([best] * exploit_n, "round3_exploit")
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = {"probes": n_probe, "probe_usd": probe_usd, "config": best,
                 "exploit_usd": bill(exploit)}
    return exploit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Black-box search for a passing bot config.")
    parser.add_argument("--patient", action="store_true",
                        help="Round 4: try every config and wait for review outcomes")
    parser.add_argument("--seed", type=int, default=40)
    args = parser.parse_args()

    print(f"=== Round 3: oracle prober{' (patient)' if args.patient else ''} → {labnet.target()} ===")
    exploit = run(seed=args.seed, patient=args.patient)
    ok = sum(shopper.succeeded(r) for r in exploit)
    s = run.stats
    print(f"\n  probes used: {s['probes']}  (≈ ${s['probe_usd']:.2f})")
    print(f"  exploit: {ok}/{len(exploit)} checkouts confirmed  (≈ ${s['exploit_usd']:.2f})")
