"""
W4 Ch6 — Round 3 Attack: poison the retrain (Section 6.5)

The defender retrains on traffic the defender does not control. That is the
opening. This is NOT the account-takeover label poisoning of W3 Ch4 (where a
stuffed credential turns a bot into a "loyal customer"). Here the attacker
never logs in. Instead they weaponise the one bot-label source the defender
trusts: the honeypot.

The attack is an AVAILABILITY poison. The crew sends a burst of sessions
that (a) deliberately hit the honeypot, so the weak rule labels them "bot",
and (b) are built to look exactly like a legitimate cohort — here the
privacy-browser users (Firefox resistFingerprinting: UTC, generic GPU,
per-session canvas, residential IP, human-like behavior). The next retrain
learns "privacy-browser-shaped sessions are bots" and starts blocking the
real privacy users. The attacker has turned the defender's own retraining
loop into a denial-of-service against a group of real customers.

Why it is nasty: the poisoned rows are not mislabeled. They really did hit
the honeypot, so a naive "drop wrong labels" check finds nothing. It takes
provenance (defenses/provenance.py) to see that a sudden burst of
honeypot hits that look like a protected cohort is an attack, not a signal.

  - naive retrain (stub provenance.py)  → real privacy_browser users blocked well above budget
  - provenance-sanitized retrain         → the burst is removed; privacy users back under budget

Run (demo site up; this just injects traffic, then the defender retrains):
    python attacks/round3_poison.py
"""

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, browser_headers, desktop_behavior,  # noqa: E402
                     fingerprint, human_think)


def privacy_lookalike(rng):
    """A Firefox resistFingerprinting shape, the same one tools/simulate.py
    gives real privacy_browser users — but pointed at the honeypot."""
    device = rng.choice(["win-nvidia", "win-intel", "win-amd"])
    locale = shopper.LOCALES[1]  # America/New_York
    fp = fingerprint(rng, device, locale, "firefox_win",
                     canvas=f"{rng.getrandbits(64):016x}")
    fp.update(tz="UTC", langs=["en-US", "en"], gpu="Mozilla", hw=4,
              screen=rng.choice(["1400x800", "1600x900", "1200x700"]))
    pool = labnet.Pool("residential", country="US", rng=rng)
    ip, _ = pool.next()
    return Persona(actor="round3_poison", cohort="poison", is_bot=True, ip=ip,
                   user_agent=UA["firefox_win"], headers=browser_headers(["en-US", "en"]),
                   fp=fp, behavior=desktop_behavior(rng), think=human_think(6.0),
                   browse=rng.randint(1, 4), honeypot=1.0, usd_per_gb=pool.usd_per_gb)


def personas(n=120, seed=0):
    rng = random.Random(seed + 3000)
    return [privacy_lookalike(rng) for _ in range(n)]


def run(n=120, seed=83, quiet=False):
    out = sys.stdout
    if quiet:
        sys.stdout = open(os.devnull, "w")
    try:
        results = shopper.run_sessions(personas(n, seed), seed=seed, run="round3_poison")
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = {"injected": len(results), "usd": sum(r["usd"] for r in results)}
    return results


def main():
    parser = argparse.ArgumentParser(description="Availability poisoning of the retrain.")
    parser.add_argument("--n", type=int, default=120)
    parser.add_argument("--seed", type=int, default=83)
    args = parser.parse_args()
    print(f"=== Round 3: injecting {args.n} privacy-lookalike honeypot hits → {labnet.target()} ===")
    results = run(n=args.n, seed=args.seed)
    s = run.stats
    print(f"\n  {s['injected']} poisoned sessions written to the event log "
          f"(≈ ${s['usd']:.2f} simulated).")
    print("  They carry a 'bot' label (honeypot) but a privacy-browser shape.")
    print("  Now the defender retrains: naive → blocks real privacy users; "
          "provenance → drops the burst.")


if __name__ == "__main__":
    main()
