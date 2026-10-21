"""
Round 3 attack: poison the retrain

The defender retrains on traffic the defender does not control. That is the opening. This is NOT the
account-takeover label poisoning of W2 Ch6 (where a stuffed credential turns a bot into a "loyal customer").
Here the attacker never signs in. Instead they weaponise the one bot-label source the defender trusts: the
honeypot.

The attack is an AVAILABILITY poison. The crew sends a burst of sessions that (a) deliberately hit the
honeypot, so the weak rule labels them "bot", and (b) are built to look exactly like a legitimate cohort:
here the privacy-browser users (Firefox resistFingerprinting: UTC, generic GPU, per-session canvas,
residential exit, human-like behaviour). The next retrain learns "privacy-browser-shaped sessions are bots"
and starts refusing the real privacy users. The attacker has turned the defender's own retraining loop into a
denial of service against a group of real customers. It buys nothing at the checkout; the damage is done to
the model.

Why it is nasty: the poisoned rows are not mislabeled. They really did hit the honeypot, so a naive "drop
the wrong labels" check finds nothing. It takes provenance (defenses/provenance.py) to see that a sudden
burst of honeypot hits that look like a protected cohort is an attack, not a signal.

  - naive retrain (the stub provenance.py)  -> real privacy-browser customers refused well above budget
  - provenance-sanitized retrain            -> the burst is removed; they are back under budget

Run (store up; this injects traffic, then the defender retrains):
    python tools/simulate.py --wave round3_poison
    python attacks/round3_poison.py              # the same burst, sent live (it is not captured)
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard)
import shopper  # noqa: E402
from shopper import UA, Persona, accept_language, desktop_behavior, fingerprint, human_think  # noqa: E402

HISTORY_N, HISTORY_SEED = 120, 83


def privacy_lookalike(rng, n):
    """A Firefox resistFingerprinting shape, the same one tools/personas_ch8.py gives real privacy_browser
    users, but pointed at the honeypot."""
    device = rng.choice(["win-nvidia", "win-intel", "win-amd"])
    locale = shopper.LOCALES[1]  # America/New_York
    fp = fingerprint(rng, device, locale, "firefox_win", canvas=f"{rng.getrandbits(64):016x}")
    fp.update(tz="UTC", langs=["en-US", "en"], gpu="Mozilla", hw=4, screen=rng.choice(["1400x800", "1600x900", "1200x700"]))
    return Persona(actor=f"bot:poison:{n:03d}", persona="poison", browser=("poison",),
                   ip=rng.choice(labclient.world_pool("resi_us")), ua=UA["firefox_win"],
                   accept_language=accept_language(["en-US", "en"]), fp=fp, behavior=desktop_behavior(rng),
                   think=human_think(6.0), browse=rng.randint(1, 4), honeypot=1.0, usd_per_gb=4.0)


def personas(n=120, seed=0):
    rng = random.Random(seed + 3000)
    return [privacy_lookalike(rng, i) for i in range(n)]


def run(n=HISTORY_N, seed=HISTORY_SEED):
    return shopper.run_sessions(personas(n, seed), seed=seed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Availability poisoning of the retrain.")
    parser.add_argument("--n", type=int, default=HISTORY_N)
    parser.add_argument("--seed", type=int, default=HISTORY_SEED)
    args = parser.parse_args()
    print(f"=== Round 3: {args.n} privacy-lookalike honeypot hits -> {labclient.BASE_URL} ===")
    results = run(args.n, args.seed)
    print(f"\n  {len(results)} poisoned sessions written to the event log (~${sum(r['usd'] for r in results):.2f} simulated).")
    print("  They carry a 'bot' label (honeypot) but a privacy-browser shape.")
    print("  Now the defender retrains: naive -> refuses real privacy users; provenance -> drops the burst.")
    print(json.dumps(shopper.summarize_attack(results)))
