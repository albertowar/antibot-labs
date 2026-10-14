"""
Round 3 attack: the oracle prober

Objective: stop guessing. Treat the defense as a black box, send cheap probe sessions, read what comes
back, and search for the cheapest configuration that passes. Then spend money only on that one.

Knobs (cheapest value first):
  fingerprint  rotate (free randomizer) |
               purchased (real-device profiles from a fingerprint shop, $0.50 each)
               (the single stealth profile from Round 1 is already burned)
  behavior     scripted | humanized
  pool         datacenter ($0.10/GB) | residential ($4/GB)
  browse       0 | 3 product pages first

Search: coordinate descent. For each knob, probe every value with PROBES_PER_CONFIG sessions and keep
the value with the lowest risk. The store has been returning `X-Lab-Score` on every response since
Round 1 (the gate's teaching-aid header; 75 is the blocking line, and the score climbs with the model's
risk on both sides of it). That is a gradient, and the prober follows it.

Round 4 takes the oracle away: every purchase answers 202 "pending review" with a score of 0, and
orders are cancelled later. The default prober then sees identical answers for every config and buys
the cheapest. `--patient` tries every config, waits for the reviews to come back, and pays for it in
probes and time.

Expected results:
  - DEFENSE_LEVEL=3 -> finds a passing config in a handful of probe sessions; the exploit mostly succeeds
  - DEFENSE_LEVEL=4 -> default: exploit ~0%; --patient: 32 probes and one review cycle, then it works again
    (the oracle is slowed, not removed)

Run:
    python attacks/round3_oracle_prober.py
    python attacks/round3_oracle_prober.py --patient     # Round 4 only
"""

import argparse
import itertools
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
sys.path.insert(0, HERE)                                   # sibling attacks, also when imported by checkpoint.py

import labclient  # noqa: E402  (runs the labnet guard)
import round0_baseline  # noqa: E402
import round2_farm  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, accept_language, desktop_behavior, fingerprint,  # noqa: E402
                     fixed_think, human_think, pick_device)

KNOBS = {
    "fingerprint": ["rotate", "purchased"],
    "behavior": ["scripted", "humanized"],
    "pool": ["datacenter", "residential"],
    "browse": [0, 3],
}
POOLS = {"datacenter": ("cloud_vm", 0.10), "residential": ("resi_us", 4.0)}
CHEAPEST = {k: v[0] for k, v in KNOBS.items()}
PROFILE_USD = 0.50
PROBES_PER_CONFIG = 2
BLOCK_SCORE = 75            # X-Lab-Score at which the gate blocks: risk 1.0


def make_persona(cfg, rng, purchased_pool, n):
    pool, usd = POOLS[cfg["pool"]]
    ip = rng.choice(labclient.world_pool(pool))
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
    return Persona(actor=f"bot:prober:{n:03d}", persona="prober", browser=("prober",), ip=ip, ua=UA[ua_key],
                   accept_language=accept_language(langs), fp=fp, behavior=behavior, think=think,
                   browse=cfg["browse"], usd_per_gb=usd, extra_usd=extra_usd, config=dict(cfg))


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

    def sessions(self, cfgs):
        personas = [make_persona(c, self.rng, self.inventory, len(self.results) + i) for i, c in enumerate(cfgs)]
        self.seed += 1
        res = shopper.run_sessions(personas, seed=self.seed)
        self.results += res
        return res

    @staticmethod
    def risk(r):
        """What the attacker reads from a response: the gate's score, as a share of the blocking line."""
        if r["score"] is not None:
            return r["score"] / BLOCK_SCORE
        return 0.0 if r["final"] in ("confirmed", "pending") else 1.0

    def probe(self, cfg):
        """Send PROBES_PER_CONFIG sessions; return (mean observed risk, all passed?)."""
        res = self.sessions([cfg] * PROBES_PER_CONFIG)
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
        res = self.sessions([c for c in configs for _ in range(PROBES_PER_CONFIG)])
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
    return sum(r["usd"] for r in results)


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
        exploit = prober.sessions([best] * exploit_n)
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = {"probes": n_probe, "probe_usd": round(probe_usd, 2), "config": best, "exploit_usd": round(bill(exploit), 2)}
    return exploit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Black-box search for a passing bot config.")
    parser.add_argument("--patient", action="store_true", help="Round 4: try every config and wait for review outcomes")
    parser.add_argument("--seed", type=int, default=40)
    args = parser.parse_args()

    print(f"=== Round 3: oracle prober{' (patient)' if args.patient else ''} -> {labclient.BASE_URL} ===")
    exploit = run(seed=args.seed, patient=args.patient)
    s = run.stats
    ok = sum(shopper.succeeded(r) for r in exploit)
    print(f"\n  probes used: {s['probes']}  (~ ${s['probe_usd']:.2f})")
    print(f"  exploit: {ok}/{len(exploit)} purchases confirmed  (~ ${s['exploit_usd']:.2f})")
    print(json.dumps(shopper.summarize_attack(exploit, probes=s["probes"], probe_usd=s["probe_usd"],
                                              config=fmt(s["config"]))))
